# handlers/http_handler.py
import logging
from aiohttp import web, ClientSession

from core.mitigation_manager import MitigationManager
from .generic_tcp_handler import get_original_destination

logger = logging.getLogger("ddos-preventer")

class HTTPDDoSMitigator:
    """HTTP trafiği için DDoS koruması ve proxy mantığını yönetir."""

    def __init__(self):
        self.mitigator = MitigationManager()

    def _client_ip_from_request(self, req):
        xff = req.headers.get("X-Forwarded-For")
        if xff: return xff.split(",")[0].strip()
        peer = req.transport.get_extra_info("peername")
        return (peer[0] if peer else req.remote) or "unknown"

    async def proxy_handler(self, req):
        ip = self._client_ip_from_request(req)

        original_dest_ip, original_dest_port = await get_original_destination(req.transport)
        if not original_dest_port:
            logger.error("HTTP handler orijinal hedefi alamadı, bağlantı kapatılıyor.")
            return web.Response(status=502, text="Bad Gateway: Cannot determine original destination.")

        allowed, reason = await self.mitigator.check_and_mitigate(ip, original_dest_port)
        if not allowed:
            logger.warning(f"[HTTP] Bağlantı reddedildi: {ip} -> port {original_dest_port} ({reason})")
            return web.Response(status=429, text=f"Too Many Requests: {reason}")

        upstream_url = f"{req.scheme}://{original_dest_ip}:{original_dest_port}"

        if not await self.mitigator.increment_connection(ip, original_dest_port):
            logger.warning(f"[HTTP] Bağlantı reddedildi (limit aşıldı): {ip} -> port {original_dest_port}")
            return web.Response(status=429, text="Connection limit exceeded")

        try:
            data = await req.read()
            headers = {k:v for k,v in req.headers.items() if k.lower() != "host"}
            headers["Host"] = req.host
            headers["X-Forwarded-For"] = ip

            target_url = upstream_url + req.rel_url.path_qs
            logger.info(f"[HTTP] {ip} -> {target_url}")

            async with req.app["session"].request(
                req.method, target_url,
                headers=headers, data=data, allow_redirects=False, ssl=False
            ) as resp:
                body = await resp.read()
                h = {k:v for k,v in resp.headers.items() if k.lower() not in
                     ("content-length","connection","transfer-encoding","keep-alive")}
                return web.Response(status=resp.status, body=body, headers=h)
        except Exception as e:
            logger.exception("Proxy hatası %s: %s", ip, e)
            return web.Response(status=502, text="Bad gateway")
        finally:
            await self.mitigator.decrement_connection(ip, original_dest_port)