# handlers/http_handler.py
import logging
from aiohttp import web, ClientSession

from core.mitigation_manager import MitigationManager
from .generic_tcp_handler import get_original_destination

# "ddos-preventer" adında, main.py'de yapılandırılmış olan logger'ı çağırır.
# Bu sayede loglar aynı yere ve aynı formatta yazılır.
logger = logging.getLogger("ddos-preventer")

class HTTPDDoSMitigator:
    """HTTP trafiği için DDoS koruması ve proxy mantığını yönetir."""

    # Sınıfın yapıcı metodu (constructor). Sınıftan bir nesne oluşturulduğunda ilk olarak bu metod çalışır.
    def __init__(self):
        # MitigationManager'dan bir nesne oluşturur ve bunu sınıfın bir özelliği olarak saklar.
        # Bu, IP adreslerini kontrol etme, engelleme ve sayım işlemlerini yönetmek için kullanılır.
        self.mitigator = MitigationManager()

    # aiohttp'nin 'request' nesnesinden istemcinin gerçek IP adresini çıkaran özel bir metod.
    # _ ile başlaması, bu metodun sınıf içinde kullanılmak üzere tasarlandığını belirtir (private method).
    def _client_ip_from_request(self, req):
        # Öncelikle 'X-Forwarded-For' başlığını kontrol eder. Bu başlık, proxy'ler tarafından eklenir
        # ve isteğin orijinal IP adresini içerir.
        xff = req.headers.get("X-Forwarded-For")
        # Eğer 'X-Forwarded-For' başlığı varsa:
        if xff: 
            # Başlık birden fazla IP içerebilir (örn: "client, proxy1, proxy2"),
            # bu yüzden virgülle ayırıp ilk IP'yi (gerçek istemci IP'si) alırız.
            return xff.split(",")[0].strip()
        # Eğer XFF başlığı yoksa, bağlantının doğrudan bilgilerine bakarız.
        # 'peername', bağlantıyı kuran karşı tarafın (istemcinin) adres bilgisini içerir.
        peer = req.transport.get_extra_info("peername")
        # Eğer 'peername' bilgisi mevcutsa onun IP adresini (ilk elemanını), değilse 'req.remote'u kullanır.
        # Hiçbiri yoksa "unknown" döner.
        return (peer[0] if peer else req.remote) or "unknown"

    # Gelen tüm HTTP isteklerini karşılayan ve işleyen ana metod (handler).
    async def proxy_handler(self, req):
        # Yukarıdaki metodu kullanarak istek yapan istemcinin IP adresini alır.
        ip = self._client_ip_from_request(req)

        # 'iptables' yönlendirmesi olmadan önce isteğin gitmesi gereken asıl IP ve portu alır.
        # Bu, bağlantının soket bilgilerinden (socket options) okunur.
        original_dest_ip, original_dest_port = await get_original_destination(req.transport)
        # Eğer orijinal hedef portu alınamazsa, bu bir hata durumudur.
        if not original_dest_port:
            # Hata loglanır ve istemciye "Bad Gateway" hatası döndürülür.
            logger.error("HTTP handler orijinal hedefi alamadı, bağlantı kapatılıyor.")
            return web.Response(status=502, text="Bad Gateway: Cannot determine original destination.")

        # MitigationManager'a bu IP'nin bu porta erişiminin uygun olup olmadığını sorar.
        # Bu metod, IP'nin kara listede olup olmadığını ve saniye başına istek limitini aşıp aşmadığını kontrol eder.
        allowed, reason = await self.mitigator.check_and_mitigate(ip, original_dest_port)
        # Eğer erişime izin verilmiyorsa:
        if not allowed:
            # Neden reddedildiğine dair bir uyarı logu yazılır.
            logger.warning(f"[HTTP] Bağlantı reddedildi: {ip} -> port {original_dest_port} ({reason})")
            # İstemciye "429 Too Many Requests" (Çok Fazla İstek) yanıtı döndürülür.
            return web.Response(status=429, text=f"Too Many Requests: {reason}")

        # İsteği yönlendireceğimiz asıl sunucunun URL'sini oluşturur.
        upstream_url = f"{req.scheme}://{original_dest_ip}:{original_dest_port}"

        # Bu IP'nin ve portun anlık aktif bağlantı sayısını bir artırır.
        # Eğer bu artırma işlemi, tanımlanan maksimum anlık bağlantı limitini aşıyorsa 'False' döner.
        if not await self.mitigator.increment_connection(ip, original_dest_port):
            # Bağlantı limitinin aşıldığına dair bir uyarı logu yazılır.
            logger.warning(f"[HTTP] Bağlantı reddedildi (limit aşıldı): {ip} -> port {original_dest_port}")
            # İstemciye "Connection limit exceeded" mesajıyla birlikte 429 hatası döndürülür.
            return web.Response(status=429, text="Connection limit exceeded")

        # Proxy işlemini bir try...finally bloğuna alırız.
        # 'finally' bloğu, işlem başarılı olsa da hata olsa da her zaman çalışır.
        # Bu, bağlantı sayacını düşürmek için kritik öneme sahiptir.
        try:
            # Gelen isteğin gövdesini (body) okur (örn: POST verisi).
            data = await req.read()
            # Orijinal isteğin başlıklarını (headers) kopyalar. 'Host' başlığı proxy tarafından değiştirileceği için hariç tutulur.
            headers = {k:v for k,v in req.headers.items() if k.lower() != "host"}
            # Hedef sunucunun doğru sanal sunucuyu (virtual host) bulabilmesi için 'Host' başlığını ayarlar.
            headers["Host"] = req.host
            # İsteğin arkasındaki orijinal istemci IP'sini belirtmek için 'X-Forwarded-For' başlığını ekler/günceller.
            headers["X-Forwarded-For"] = ip

            # Asıl sunucuya gönderilecek tam URL'yi oluşturur (path ve query string dahil).
            target_url = upstream_url + req.rel_url.path_qs
            # Hangi isteğin nereye yönlendirildiğini loglar.
            logger.info(f"[HTTP] {ip} -> {target_url}")

            # 'aiohttp' session'ını kullanarak asıl sunucuya isteği gönderir.
            # req.method: GET, POST, vb.
            # allow_redirects=False: Yönlendirmeleri otomatik takip etme, istemciye bırak.
            # ssl=False: SSL doğrulamasını proxy katmanında yapma, çünkü hedef genellikle localhost'taki bir servistir.
            async with req.app["session"].request(
                req.method, target_url,
                headers=headers, data=data, allow_redirects=False, ssl=False
            ) as resp:
                # Asıl sunucudan gelen yanıtın gövdesini (body) okur.
                body = await resp.read()
                # Bağlantıyı kontrol eden bazı başlıkları (hop-by-hop headers) hariç tutarak yanıt başlıklarını filtreler.
                h = {k:v for k,v in resp.headers.items() if k.lower() not in
                     ("content-length","connection","transfer-encoding","keep-alive")}
                # Orijinal istemciye, asıl sunucudan gelen yanıtın aynısını (status, body, headers) döndürür.
                return web.Response(status=resp.status, body=body, headers=h)
        # Proxy işlemi sırasında herhangi bir hata oluşursa (örn: hedef sunucuya ulaşılamazsa):
        except Exception as e:
            # Hatanın detaylarını loglar.
            logger.exception("Proxy hatası %s: %s", ip, e)
            # İstemciye "502 Bad Gateway" hatası döndürür.
            return web.Response(status=502, text="Bad gateway")
        # try bloğundaki işlemler bitince veya bir hata oluşunca bu blok çalışır.
        finally:
            # İstemcinin bağlantısı sonlandığı için, bu IP ve port için aktif bağlantı sayısını bir azaltır.
            # Bu, sayaçların şişmesini önler ve limitlerin doğru çalışmasını sağlar.
            await self.mitigator.decrement_connection(ip, original_dest_port)
