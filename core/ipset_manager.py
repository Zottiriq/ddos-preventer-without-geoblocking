import subprocess
import logging
import config

# main.py'de yapılandırılmış olan ana logger'ı çağırır.
logger = logging.getLogger("ddos-preventer")

# Shell komutlarını çalıştırmak için merkezi bir yardımcı fonksiyon.
# _ ile başlaması, bu fonksiyonun sadece bu dosya içinde kullanılmasının amaçlandığını belirtir.
def _run_shell(cmd, check=True):
    """Shell komutlarını çalıştırır ve hataları yakalar."""
    # Olası hataları (komutun başarısız olması, zaman aşımı vb.) yakalamak için try...except bloğu.
    try:
        # 'subprocess.run' ile verilen komutu çalıştırır.
        result = subprocess.run(
            cmd,              # Çalıştırılacak komut ve argümanları (bir liste olarak).
            check=check,      # True ise ve komut hata koduyla dönerse, bir CalledProcessError istisnası fırlatır.
            text=True,        # stdout ve stderr'i metin olarak ele alır.
            timeout=5,        # Komutun tamamlanması için maksimum bekleme süresi (saniye).
            capture_output=True # stdout ve stderr'i yakalayıp sonuç nesnesine ekler.
        )
        # Komut başarılı olursa, sonuç nesnesini döndürür.
        return result
    # 'check=True' iken komut başarısız olursa bu blok çalışır.
    except subprocess.CalledProcessError as e:
        # Eğer hata mesajı "yok" veya "zaten var" gibi beklenen bir durum içeriyorsa,
        # bunu gerçek bir hata olarak görmeyip None döndürürüz. Bu, işlemleri daha akıcı hale getirir.
        if "does not exist" in e.stderr or "already exists" in e.stderr:
            return None
        # Sadece 'check=True' olarak ayarlandığında hata loglaması yapılır.
        # Bu, 'contains' gibi fonksiyonların beklenen başarısızlık durumlarını loglamasını engeller.
        if check:
            logger.error("Shell komut hatası '%s': %s", " ".join(cmd), e.stderr.strip())
        # Hata durumunda None döndürülür.
        return None
    # Komutu çalıştırırken başka bir hata oluşursa (örn: komut bulunamadı, zaman aşımı):
    except Exception as e:
        # Genel bir hata mesajı loglanır ve None döndürülür.
        logger.error("Shell komutu çalıştırılamadı '%s': %s", " ".join(cmd), e)
        return None

def setup():
    """Engellenen IP'leri tutmak için bir ipset listesi oluşturur."""
    # config dosyasından kullanılacak ipset listesinin adını alır.
    set_name = config.DEFAULT_IPSET_NAME
    # ipset listesinin oluşturulmaya başlandığını loglar.
    logger.info(f"'{set_name}' adında ipset listesi oluşturuluyor...")
    # 'ipset create' komutunu çalıştırarak listeyi oluşturur.
    # hash:ip: IP adreslerini verimli bir şekilde saklamak için kullanılan bir set türü.
    # timeout 0: Varsayılan olarak eklenen elemanların süresiz kalacağını belirtir (add komutuyla değiştirilebilir).
    if not _run_shell(["ipset", "create", set_name, "hash:ip", "timeout", "0"]):
        # Eğer komut başarısız olursa, bir hata loglanır ve False döndürülür.
        logger.error("ipset listesi oluşturulamadı. 'ipset' paketinin kurulu olduğundan emin olun.")
        return False
    # Başarılı olursa, bir bilgi mesajı loglanır ve True döndürülür.
    logger.info("ipset listesi hazır.")
    return True

def add(ip: str, timeout: int):
    """Bir IP adresini belirtilen süreyle (saniye) ipset listesine ekler."""
    # config dosyasından ipset listesinin adını alır.
    set_name = config.DEFAULT_IPSET_NAME
    # Hangi IP'nin ne kadar süreyle engellendiğini loglar.
    logger.warning(f"[IPSET] IP engelleniyor: {ip} ({timeout} saniye)")
    # 'ipset add' komutunu çalıştırır.
    # timeout str(timeout): Bu IP'nin listede ne kadar süre kalacağını belirtir.
    # -exist: Eğer IP zaten listede varsa, hata verme. Sadece timeout süresini günceller.
    _run_shell(["ipset", "add", set_name, ip, "timeout", str(timeout), "-exist"])

def contains(ip: str) -> bool:
    """Bir IP adresinin ipset listesinde olup olmadığını kontrol eder."""
    # config dosyasından ipset listesinin adını alır.
    set_name = config.DEFAULT_IPSET_NAME
    # --- DÜZELTME: 'check=False' kullanarak komutun başarısız olmasına izin veriyoruz. ---
    # Eğer 'check=True' olsaydı, IP listede olmadığında komut hata koduyla dönecek ve
    # _run_shell fonksiyonu bir istisna fırlatacaktı. 'check=False' bunu engeller.
    result = _run_shell(["ipset", "test", set_name, ip], check=False)
    
    # 'ipset test' komutu, IP listede varsa 0 (başarılı), yoksa 0'dan farklı bir kodla (başarısız) döner.
    # Bu yüzden, sonucun None olmadığını (komutun çalıştığını) ve dönüş kodunun 0 olduğunu kontrol ederiz.
    return result is not None and result.returncode == 0

def cleanup():
    """Oluşturulan ipset listesini siler."""
    # config dosyasından ipset listesinin adını alır.
    set_name = config.DEFAULT_IPSET_NAME
    # Temizleme işleminin başladığını loglar.
    logger.info(f"'{set_name}' ipset listesi temizleniyor...")
    # 'ipset destroy' komutu ile listeyi ve içindeki tüm IP'leri tamamen siler.
    _run_shell(["ipset", "destroy", set_name])
    # Temizlemenin bittiğini loglar.
    logger.info("ipset listesi temizlendi.")
