# relay_vless.py
# بخش VLESS Relay — جدا شده از main.py (منطق اصلی دست‌نخورده)
# تغییر: ثبت IP واقعی کلاینت (با احتساب هدر x-forwarded-for پشت پراکسی) در connections
# تغییر جدید: هدایت ترافیک خروجی از طریق پروکسی مسکونی دویچه تلکام آلمان (Socks5)

import asyncio
import secrets
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    connections,
    error_logs,
    hourly_traffic,
    is_ip_allowed,
    is_link_allowed,
    log_activity,
    logger,
    now_ir,
    save_state,
    stats,
)
from speed_limit import throttle

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay — بهینه‌شده برای حداکثر throughput
# ══════════════════════════════════════════════════════════════════════════════

RELAY_BUF = 256 * 1024   # 256 KB buffer

# مشخصات پروکسی مسکونی دویچه تلکام شما
PROXY_HOST = "://ipoasis.com"
PROXY_PORT = 8668
PROXY_USER = "user-K7UO7Ach_6607-region-de-city-TROISDORF-sess-838010-sessTime-118"
PROXY_PASS = "wB20uBAH"

def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "نامشخص"

async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]

async def check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[now_ir().strftime("%H:00")] += n
    return True

async def open_socks5_connection(target_host: str, target_port: int) -> tuple:
    """باز کردن اتصال به مقصد نهایی از طریق پروکسی ساکس ۵ با احراز هویت"""
    reader, writer = await asyncio.open_connection(PROXY_HOST, PROXY_PORT)
    
    # مرحله 1: ارسال متدهای احراز هویت (تأیید متد یوزرنیم/پسورد)
    writer.write(b"\x05\x02\x00\x02")
    await writer.drain()
    
    version, method = await reader.readexactly(2)
    if version != 5:
        raise ValueError("نسخه پروتکل ساکس نامعتبر است")
        
    if method == 2:
        # مرحله 2: انجام احراز هویت با نام کاربری و رمز عبور
        user_bytes = PROXY_USER.encode('utf-8')
        pass_bytes = PROXY_PASS.encode('utf-8')
        auth_req = b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes
        writer.write(auth_req)
        await writer.drain()
        
        auth_ver, auth_status = await reader.readexactly(2)
        if auth_status != 0:
            raise ValueError("نام کاربری یا رمز عبور پروکسی اشتباه است")
    elif method != 0:
        raise ValueError("پروکسی متد احراز هویت پشتیبانی شده را قبول نکرد")

    # مرحله 3: ارسال درخواست کانکت به مقصد اصلی
    req = b"\x05\x01\x00"
    try:
        # بررسی اینکه مقصد آی‌پی است یا دامنه
        import ipaddress
        ip_obj = ipaddress.ip_address(target_host)
        if ip_obj.version == 4:
            req += b"\x01" + ip_obj.packed
        else:
            req += b"\x04" + ip_obj.packed
    except ValueError:
        # اگر دامنه بود
        host_bytes = target_host.encode('utf-8')
        req += b"\x03" + bytes([len(host_bytes)]) + host_bytes
        
    req += target_port.to_bytes(2, 'big')
    writer.write(req)
    await writer.drain()
    
    # خواندن پاسخ سرور پروکسی
    resp = await reader.readexactly(4)
    if resp[1] != 0:
        raise ValueError(f"اتصال پروکسی ناموفق بود با کد خطا: {resp[1]}")
        
    if resp[3] == 1:
        await reader.readexactly(4)
    elif resp[3] == 4:
        await reader.readexactly(16)
    elif resp[3] == 3:
        dlen = await reader.readexactly(1)
        await reader.readexactly(dlen[0])
        
    await reader.readexactly(2) # خواندن پورت باز شده در پاسخ
    return reader, writer

async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data))
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data))
            connections[conn_id]["bytes"] += len(data)
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await ws.send_bytes(payload)
    except Exception:
        pass

async def websocket_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… (not allowed)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)

    if not is_ip_allowed(link, uuid, ip):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… ip={ip} (ip limit reached)")
        log_activity("connection", f"اتصال {ip} به کانفیگ «{link.get('label','?')}» رد شد (محدودیت تعداد آی‌پی)", "warn")
        await ws.close(code=1008, reason="ip limit reached")
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"✅ WS [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    log_activity("connection", f"اتصال جدید از {ip} (کانفیگ {link.get('label','?')})", "info")
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        command, address, port, payload = await parse_vless_header(first_chunk)

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"➡️  [{conn_id}] → {address}:{port} (Via Telekom Proxy)")

        # تغییر کلیدی: اتصال از طریق تابع جدید پروکسی ساکس ۵
        reader, writer = await asyncio.wait_for(
            open_socks5_connection(address, port),
            timeout=12.0
        )
        sock = writer.transport.get_extra_info('socket')
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if payload:
            writer.write(payload)
            await writer.drain()

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout via proxy", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 WS closed [{conn_id}] total={len(connections)}")
