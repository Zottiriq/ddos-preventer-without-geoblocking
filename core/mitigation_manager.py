# core/mitigation_manager.py
import asyncio
import time
import logging
from collections import deque
from pathlib import Path

import config
from . import ipset_manager

# main.py'de yapılandırılmış olan ana logger'ı çağırır.
logger = logging.getLogger("ddos-preventer")

# Beyaz liste (whitelist) dosyasının konumu. Bu dosyadaki IP'lere asla kısıtlama uygulanmaz.
WHITELIST_FILE = "/etc/ddos_preventer/whitelist.txt"

class TokenBucket:
    """Her bir IP-Port çifti için hız limitini (rate limit) 'Token Bucket' algoritması ile uygular."""
    # Sınıfın yapıcı metodu.
    def __init__(self, rate, capacity):
        self.rate = float(rate)          # Kovaya saniyede eklenen token (izin) sayısı.
        self.capacity = float(capacity)  # Kovanın maksimum token kapasitesi (burst limiti).
        self.tokens = float(capacity)    # Kovanın başlangıçtaki token sayısı (tam dolu).
        self.last = time.time()          # Son token ekleme/kontrol zamanı.

    # Kovadan belirli miktarda token tüketmeyi dener.
    def consume(self, amount=1.0):
        now = time.time()
        # Son kontrolden bu yana geçen sürede ne kadar token biriktiğini hesapla ve kovaya ekle.
        # Ancak kovanın toplam kapasitesini aşmamasını sağla.
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        # Son kontrol zamanını şimdi olarak güncelle.
        self.last = now
        # Eğer istenen miktarda token varsa:
        if self.tokens >= amount:
            # Token'ı tüket.
            self.tokens -= amount
            # İşlemin başarılı olduğunu bildir (True).
            return True
        # Yeterli token yoksa, işlemin başarısız olduğunu bildir (False).
        return False

class MitigationManager:
    """Tüm gelen bağlantılar için merkezi DDoS azaltma yöneticisi. Bu bir Singleton sınıfıdır."""
    _instance = None # Sınıfın tek bir örneğini (instance) tutmak için statik değişken.

    # Bu özel metod, sınıf çağrıldığında (`MitigationManager()`) çalışır ve her zaman aynı nesneyi döndürür.
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(MitigationManager, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    # Nesnenin yapıcı metodu.
    def __init__(self):
        # Bu 'if' bloğu, __init__ metodunun sadece ilk nesne oluşturulduğunda bir kez çalışmasını sağlar.
        if hasattr(self, '_initialized'):
            return
        self._initialized = True

        logger.info("MitigationManager başlatılıyor (ipset & Port-based modu)...")
        # Config'den varsayılan engelleme süresini (saniye) alır.
        self.block_sec = int(config.DEFAULT_BLOCK_SEC)

        # Her (IP, Port) çifti için TokenBucket nesnelerini saklar.
        self.buckets = {}
        # Her (IP, Port) çifti için asyncio.Lock nesnelerini saklar (race condition önlemek için).
        self.locks = {}
        # Her (IP, Port) çifti için anlık bağlantı sayısını tutar.
        self.conns = {}
        # Her IP için son bağlantı zamanlarını tutan bir 'deque' (hızlı bir liste) saklar.
        self.recent = {}

        # Beyaz listedeki IP adreslerini tutan bir set (hızlı arama için).
        self.whitelist = set()
        # Beyaz listeyi dosyadan okuyup belleğe yükler.
        self._load_whitelist()

        # Performansı izlemek için metrikleri tutar.
        self.metrics = {"total": 0, "allowed": 0, "blocked": 0, "blacklisted": 0}

    # Anlık zamanı döndüren bir yardımcı metod.
    def _now(self):
        return time.time()

    # Belirli bir (IP, Port) anahtarı için bir kilit (lock) nesnesi döndürür. Eğer yoksa oluşturur.
    def _get_lock(self, ip, port):
        key = (ip, port)
        if key not in self.locks:
            self.locks[key] = asyncio.Lock()
        return self.locks[key]

    # Belirli bir IP için son zaman damgalarını tutan 'deque' nesnesini döndürür. Eğer yoksa oluşturur.
    def _get_recent(self, ip):
        if ip not in self.recent:
            self.recent[ip] = deque(maxlen=1000) # Son 1000 zaman damgasını tutar.
        return self.recent[ip]

    def _load_whitelist(self):
        """Whitelist dosyasını okur ve belleğe yükler."""
        try:
            path = Path(WHITELIST_FILE)
            # Eğer dosya mevcut değilse, bilgi ver ve devam et.
            if not path.exists():
                logger.info(f"Whitelist dosyası bulunamadı: {path}")
                return
            # Dosyayı okuma modunda aç.
            with open(path, "r") as f:
                # Dosyadaki her satırı oku.
                for line in f:
                    ip = line.strip() # Satır başı ve sonundaki boşlukları temizle.
                    # Eğer satır boş değilse ve yorum satırı (#) ile başlamıyorsa:
                    if ip and not ip.startswith("#"):
                        # IP'yi beyaz listeye ekle.
                        self.whitelist.add(ip)
            logger.info(f"Whitelist yüklendi ({len(self.whitelist)} IP).")
        except Exception as e:
            logger.error(f"Whitelist okunamadı: {e}")

    # Bir IP'nin engellenmiş olup olmadığını kontrol eder.
    def is_blocked(self, ip):
        # IP beyaz listede ise asla engellenmiş sayılmaz.
        if ip in self.whitelist:
            return False
        # ipset_manager'a sorarak IP'nin kara listede olup olmadığını kontrol et.
        return ipset_manager.contains(ip)

    async def clear_expired_entries(self):
        """1 saatten eski token ve bağlantı kayıtlarını temizleyerek hafızayı boşaltır."""
        now = self._now()
        # 'buckets' sözlüğünde son erişim zamanı 1 saatten (3600 saniye) eski olan kayıtları bul.
        expired_keys = [k for k, bucket in self.buckets.items() if now - bucket.last > 3600]
        # Bu eski kayıtları tüm sözlüklerden sil.
        for k in expired_keys:
            self.buckets.pop(k, None)
            self.conns.pop(k, None)
            self.locks.pop(k, None)
            self.recent.pop(k[0], None) # 'recent' anahtarı sadece IP olduğu için k[0] kullanılır.

        # Eğer temizlenen kayıt varsa, logla.
        if expired_keys:
            logger.debug(f"{len(expired_keys)} adet eski IP/Port kaydı hafızadan temizlendi.")

    async def check_and_mitigate(self, ip, port):
        """IP ve port bazında hız limitini uygular ve gerekirse engelleme kararı alır."""
        # IP beyaz listedeyse, hemen izin ver.
        if ip in self.whitelist:
            return True, "Whitelisted IP"

        self.metrics["total"] += 1 # Toplam istek sayacını artır.
        # IP'nin ipset'te engelli olup olmadığını kontrol et.
        if self.is_blocked(ip):
            self.metrics["blocked"] += 1 # Engellenen istek sayacını artır.
            return False, "IP blacklisted (ipset)"

        # Bu port için özel ayarları (rate, burst) config'den al. Yoksa varsayılanları kullan.
        port_config = config.TARGET_PORTS.get(port, {})
        rate = port_config.get("rate", config.DEFAULT_RATE)
        burst = port_config.get("burst", config.DEFAULT_BURST)
        key = (ip, port) # Sözlükler için anahtar oluştur.

        # Race condition'ları önlemek için bu IP/Port çiftine özel kilidi kullan.
        async with self._get_lock(ip, port):
            # Bu anahtar için bir TokenBucket olup olmadığını kontrol et.
            tb = self.buckets.get(key)
            # Eğer yoksa, yeni bir tane oluştur ve sözlüğe ekle.
            if not tb:
                tb = TokenBucket(rate, burst)
                self.buckets[key] = tb

            # Bu IP için son bağlantı zamanlarını tutan listeyi al.
            r = self._get_recent(ip)
            # Şu anki zamanı listeye ekle.
            r.append(self._now())

            # TokenBucket'tan bir token tüketmeyi dene.
            if not tb.consume():
                # Eğer token yoksa (hız limiti aşıldıysa):
                # Son 10 saniyedeki istek sayısı 'burst' limitini aştı mı diye kontrol et.
                # Bu, kısa süreli yoğun saldırıları tespit eder.
                if len([t for t in r if self._now() - t < 10]) > burst:
                    # Eğer aştıysa, IP'yi ipset kullanarak kara listeye al.
                    ipset_manager.add(ip, self.block_sec)
                    self.metrics["blacklisted"] += 1 # Kara listeye alınan IP sayacını artır.
                self.metrics["blocked"] += 1 # Engellenen istek sayacını artır.
                return False, f"Rate limit exceeded for port {port}"

        # Tüm kontrollerden geçtiyse, izin verilen istek sayacını artır.
        self.metrics["allowed"] += 1
        return True, "Allowed"

    async def increment_connection(self, ip, port):
        """Bir IP'nin anlık bağlantı sayısını artırır ve limiti kontrol eder."""
        # Beyaz listedeki IP'ler için limit uygulanmaz.
        if ip in self.whitelist:
            return True

        # Bu port için anlık bağlantı limitini (conn_limit) config'den al.
        port_config = config.TARGET_PORTS.get(port, {})
        conn_limit = port_config.get("conn_limit", config.DEFAULT_CONN_LIMIT)
        key = (ip, port)

        # Kilit kullanarak sayaçları güvenli bir şekilde artır.
        async with self._get_lock(ip, port):
            # Mevcut bağlantı sayısını 1 artır. Eğer kayıt yoksa 0'dan başla.
            self.conns[key] = self.conns.get(key, 0) + 1
            # Eğer yeni bağlantı sayısı limiti aşıyorsa:
            if self.conns[key] > conn_limit:
                # IP'yi hemen ipset ile engelle.
                ipset_manager.add(ip, self.block_sec)
                self.metrics["blocked"] += 1 # Engellenen istek sayacını artır.
                return False # Başarısız olduğunu bildir.
        return True # Limit aşılmadıysa, başarılı olduğunu bildir.

    async def decrement_connection(self, ip, port):
        """Bir bağlantı kapandığında anlık bağlantı sayısını düşürür."""
        key = (ip, port)
        # Eğer bu IP/Port için bir kayıt (ve dolayısıyla kilit) yoksa, bir şey yapma.
        if key not in self.locks:
            return
        # Kilit kullanarak sayacı güvenli bir şekilde azalt.
        async with self._get_lock(ip, port):
            # Mevcut bağlantı sayısını 1 azalt. Sayının 0'ın altına düşmemesini sağla.
            self.conns[key] = max(0, self.conns.get(key, 1) - 1)

    async def run_background_tasks(self):
        """Hafıza temizliği ve programın çalıştığını gösteren 'heartbeat' gibi arka plan görevlerini yürütür."""
        # Programın hayatta olduğunu göstermek için dokunulacak dosyanın yolu.
        heartbeat_file = Path("/tmp/ddos_preventer.heartbeat")
        # Sonsuz döngü.
        while True:
            try:
                # Heartbeat dosyasının son değiştirilme tarihini günceller.
                heartbeat_file.touch()
                # Hafızadaki eski kayıtları temizler.
                await self.clear_expired_entries()
            except Exception as e:
                logger.exception("Arka plan temizlik görevinde hata: %s", e)
            # Bir sonraki döngüden önce 10 saniye bekle.
            await asyncio.sleep(10)
