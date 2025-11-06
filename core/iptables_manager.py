# core/iptables_manager.py
import subprocess
import logging
import config

# main.py'de yapılandırılmış olan ana logger'ı çağırır.
logger = logging.getLogger("ddos-preventer")

# Shell komutlarını, özellikle iptables komutlarını çalıştırmak için bir yardımcı fonksiyon.
def _run_shell(cmd):
    """iptables komutlarını çalıştırır ve hataları yakalar."""
    # Olası hataları yakalamak için try...except bloğu kullanılır.
    try:
        # Verilen komutu çalıştırır. check=True, komut hata verirse istisna fırlatmasını sağlar.
        subprocess.run(cmd, check=True, text=True, timeout=5, capture_output=True)
        # Komut başarılı olursa True döndürür.
        return True
    # 'check=True' iken komut başarısız olursa bu blok çalışır.
    except subprocess.CalledProcessError as e:
        # Script tekrar çalıştırıldığında "zincir zaten var" veya silinmeye çalışıldığında "zincir yok"
        # gibi hatalar normaldir. Bunları bir hata olarak görmeyip görmezden geliyoruz ve True döndürüyoruz.
        if "does not exist" in e.stderr or "already exists" in e.stderr:
            return True # Bu hataları görmezden gel, sorun değil.
        # Gerçek bir hata varsa, bunu loglarız ve False döndürürüz.
        logger.error("iptables komut hatası '%s': %s", " ".join(cmd), e.stderr.strip())
        return False

def setup_transparent_proxy_rules():
    """Gelen trafiği analiz için yerel portlarımıza yönlendiren kuralları ayarlar."""
    logger.info("Transparent Proxy için iptables yönlendirme kuralları ayarlanıyor...")

    # 1. 'nat' tablosunda kendi özel zincirimizi (-N, New chain) oluşturuyoruz.
    # 'nat' tablosu, Ağ Adresi Çevirimi (Network Address Translation) için kullanılır ve port yönlendirmesi burada yapılır.
    _run_shell(["iptables", "-t", "nat", "-N", config.IPTABLES_CHAIN])

    # 2. Korunacak her bir port için (config.TARGET_PORTS içinde tanımlanan) bir yönlendirme kuralı oluştururuz.
    for port, settings in config.TARGET_PORTS.items():
        # Portun protokol tipini (http veya tcp) alırız.
        proto_type = settings.get('protocol', 'tcp')
        # Protokol tipine göre trafiği ya HTTP proxy portumuza ya da genel TCP proxy portumuza yönlendiririz.
        redirect_port = config.HTTP_PROXY_LISTEN_PORT if proto_type == 'http' else config.GENERIC_TCP_LISTEN_PORT

        # iptables kuralını oluştururuz.
        _run_shell([
            "iptables", "-t", "nat", "-A", config.IPTABLES_CHAIN, # Kuralı kendi zincirimize ekle (-A, Append).
            "-p", "tcp", "--dport", str(port), # Belirli bir hedef porta (-dport) giden TCP paketleri için.
            "-j", "REDIRECT", "--to-port", str(redirect_port) # Paketi, aynı makinedeki başka bir porta (-to-port) YÖNLENDİR (REDIRECT).
        ])

    # 3. Son olarak, sunucuya gelen tüm trafiğin ilk geçtiği yer olan PREROUTING zincirine,
    # bizim özel zincirimize atlamasını (-j) söyleyen bir kural ekleriz.
    # Bu sayede, korunacak portlara gelen tüm trafik önce bizim kurallarımız tarafından işlenir.
    _run_shell(["iptables", "-t", "nat", "-A", "PREROUTING", "-j", config.IPTABLES_CHAIN])
    logger.info("iptables yönlendirme kuralları aktif.")

def cleanup_transparent_proxy_rules():
    """Başlangıçta eklenen tüm yönlendirme kurallarını temizler."""
    logger.info("iptables yönlendirme kuralları temizleniyor...")
    # Temizleme işlemi, kurulumun tam tersi sırayla yapılır.
    
    # 1. PREROUTING zincirinden bizim zincirimize olan atlama kuralını siliyoruz (-D, Delete).
    _run_shell(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", config.IPTABLES_CHAIN])
    
    # 2. Kendi özel zincirimizin içindeki tüm kuralları temizliyoruz (-F, Flush).
    _run_shell(["iptables", "-t", "nat", "-F", config.IPTABLES_CHAIN])
    
    # 3. Artık boş olan kendi özel zincirimizi tamamen siliyoruz (-X, Delete chain).
    _run_shell(["iptables", "-t", "nat", "-X", config.IPTABLES_CHAIN])
    
    logger.info("iptables temizlendi.")
