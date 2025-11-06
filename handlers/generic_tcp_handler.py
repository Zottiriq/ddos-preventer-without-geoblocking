# handlers/generic_tcp_handler.py
import asyncio
import logging
import socket
import struct

from core.mitigation_manager import MitigationManager

logger = logging.getLogger("ddos-preventer")

async def get_original_destination(writer):
    sock = writer.get_extra_info('socket')
    try:
        # SOL_IP = 0, SO_ORIGINAL_DST = 80
        addr = sock.getsockopt(socket.IPPROTO_IP, 80, 16)
        _, port, ip1, ip2, ip3, ip4 = struct.unpack("!HHBBBB", addr[:8])
        ip = f"{ip1}.{ip2}.{ip3}.{ip4}"
        return ip, port
    except Exception as e:
        logger.error("Orijinal hedef alınamadı: %s. 'sudo' ile çalıştırdığınızdan emin olun.", e)
        return None, None

async def bridge_streams(reader1, writer1, reader2, writer2):
    try:
        while not reader1.at_eof() and not reader2.at_eof():
            data = await asyncio.wait_for(reader1.read(4096), timeout=300)
            if not data: break
            writer2.write(data)
            await writer2.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        for w in [writer1, writer2]:
            if not w.is_closing():
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass

async def handle_generic_tcp(client_reader, client_writer):
    client_ip, _ = client_writer.get_extra_info('peername', ('unknown', 0))
    mitigator = MitigationManager()

    original_dest_ip, original_dest_port = await get_original_destination(client_writer)
    if not original_dest_port:
        logger.warning("Orijinal hedef port alınamadığı için bağlantı kapatılıyor: %s", client_ip)
        client_writer.close(); await client_writer.wait_closed()
        return

    allowed, reason = await mitigator.check_and_mitigate(client_ip, original_dest_port)
    if not allowed:
        logger.warning(f"[TCP-GENERIC] Bağlantı reddedildi: {client_ip} -> port {original_dest_port} ({reason})")
        client_writer.close(); await client_writer.wait_closed()
        return

    logger.info(f"[TCP-GENERIC] {client_ip} -> {original_dest_ip}:{original_dest_port} bağlantısı alındı.")

    try:
        if not await mitigator.increment_connection(client_ip, original_dest_port):
             logger.warning(f"[TCP-GENERIC] Bağlantı reddedildi (limit aşıldı): {client_ip} -> port {original_dest_port}")
             client_writer.close(); await client_writer.wait_closed()
             return

        dest_reader, dest_writer = await asyncio.open_connection(original_dest_ip, original_dest_port)

        await asyncio.gather(
            bridge_streams(client_reader, client_writer, dest_reader, dest_writer),
            bridge_streams(dest_reader, dest_writer, client_reader, client_writer)
        )
    except Exception as e:
        logger.error(f"Hedefe bağlanılamadı ({original_dest_ip}:{original_dest_port}): {e}")
        client_writer.close(); await client_writer.wait_closed()
    finally:
        await mitigator.decrement_connection(client_ip, original_dest_port)
        logger.info(f"[TCP-GENERIC] {client_ip} -> {original_dest_ip}:{original_dest_port} bağlantısı kapatıldı.")