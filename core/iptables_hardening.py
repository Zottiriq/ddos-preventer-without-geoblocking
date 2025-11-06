# core/iptables_hardening.py
import subprocess
import logging
import config
from . import ipset_manager

# main.py'de yapılandırılmış olan ana logger'ı çağırır.
logger = logging.getLogger("ddos-preventer")

# Kurallarımızı gruplamak için oluşturacağımız özel iptables zincirinin (chain) adı.
# Bu, kuralları düzenli tutar ve temizlemeyi kolaylaştırır.
IPTABLES_FILTER_CHAIN = "DDOS_FILTER"

# Shell komutlarını çalıştırmak için merkezi bir yardımcı fonksiyon.
def _run_shell(cmd):
    """iptables veya sysctl komutlarını çalıştırır ve hataları yakalar."""
    # Olası hataları yakalamak için try...except bloğu.
    try:
        # Verilen komutu çalıştırır. check=True, komut hata verirse istisna fırlatmasını sağlar.
        result = subprocess.run(cmd, check=True, text=True, timeout=5, capture_output=True)
        # Başarılı olursa, sonuç nesnesini döndürür.
        return result
    # Komut başarısız olduğunda (check=True iken) bu blok çalışır.
    except subprocess.CalledProcessError as e:
        # "Zaten var" veya "yok" gibi hatalar, script'i birden çok kez çalıştırınca normaldir.
        # Bu hataları görmezden gelerek script'in durmasını engelleriz.
        if "does not exist" in e.stderr or "already exists" in e.stderr:
            return None
        # Diğer hataları loglayarak sorunu bildiririz.
        logger.error("Shell komut hatası '%s': %s", " ".join(cmd), e.stderr.strip())
        return None
    # Komutu çalıştırırken başka bir hata oluşursa (örn: komut bulunamadı).
    except Exception as e:
        logger.error("Shell komutu çalıştırılamadı '%s': %s", " ".join(cmd), e)
        return None

# Bir çekirdek (kernel) parametresini hem geçici (anlık) hem de kalıcı olarak ayarlayan fonksiyon.
def _set_sysctl_param(param, value, comment="DDoS-Preventer"):
    """Bir sysctl parametresini ayarlar ve /etc/sysctl.conf'a kalıcı olarak ekler."""
    try:
        # Ayarın yapıldığını loglar.
        logger.info(f"Kernel parametresi ayarlanıyor: {param} = {value}")
        # 'sysctl -w' komutu, parametreyi hemen (ama geçici olarak) ayarlar. Reboot sonrası kaybolur.
        if not _run_shell(["sysctl", "-w", f"{param}={value}"]):
            logger.error(f"{param} geçici olarak ayarlanamadı.")
            return

        # Ayarı kalıcı hale getirmek için /etc/sysctl.conf dosyasına yazarız.
        conf_path = "/etc/sysctl.conf"
        setting_line = f"{param} = {value}\n"
        # Dosyayı hem okuma hem de yazma modunda açarız.
        with open(conf_path, 'r+') as f:
            content = f.read()
            # Eğer ayar dosyada zaten varsa, tekrar eklememek için kontrol ederiz.
            if setting_line.strip().split('=')[0].strip() in content:
                logger.info(f"{param} ayarı {conf_path} içinde zaten mevcut.")
            else:
                # Dosyanın sonuna gider ve yeni ayarı bir açıklama ile birlikte ekleriz.
                f.seek(0, 2)
                f.write(f"\n# {comment}\n{setting_line}")
                logger.info(f"{param} ayarı {conf_path} dosyasına kalıcı olarak eklendi.")
    # Dosya işlemleri veya başka bir nedenle hata oluşursa yakalarız.
    except Exception as e:
        logger.error(f"{param} ayarlanırken bir hata oluştu: {e}")

def enable_syn_cookies():
    """SYN Cookie korumasını etkinleştirir. Bu, SYN Flood saldırılarına karşı çok etkilidir."""
    logger.info("SYN Cookie koruması kontrol ediliyor...")
    # Mevcut ayarı kontrol ederiz.
    result = _run_shell(["sysctl", "net.ipv4.tcp_syncookies"])
    # Eğer sonuç '1' ise (aktif demek), bir şey yapmaya gerek yoktur.
    if result and ("= 1" in result.stdout):
        logger.info("SYN Cookie koruması zaten aktif.")
        return
    # Aktif değilse, _set_sysctl_param fonksiyonu ile hem geçici hem kalıcı olarak etkinleştiririz.
    _set_sysctl_param("net.ipv4.tcp_syncookies", "1", "Enabled by DDoS-Preventer for SYN Flood protection")

def adjust_conntrack_settings():
    """Connection tracking (conntrack) tablosu boyutunu ayarlar. Bu, çok sayıda bağlantıyı yönetmek için önemlidir."""
    logger.info("Connection tracking (conntrack) tablosu ayarları kontrol ediliyor...")
    param = "net.netfilter.nf_conntrack_max"
    target_value = config.KERNEL_CONNTRACK_MAX # Hedeflenen değer config dosyasından alınır.

    # Mevcut değeri okuruz.
    result = _run_shell(["sysctl", param])
    if result:
        try:
            # Gelen çıktıyı ("net.netfilter.nf_conntrack_max = 262144") parse edip sayısal değeri alırız.
            current_value = int(result.stdout.strip().split("=")[1].strip())
            # Eğer mevcut değer, hedeflediğimiz değerden zaten büyük veya eşitse, değişiklik yapmayız.
            if current_value >= target_value:
                logger.info(f"{param} zaten yeterli bir değerde ({current_value}). Değişiklik yapılmadı.")
                return
        except (ValueError, IndexError):
            # Değeri okuyamazsak bir uyarı veririz.
            logger.warning(f"Mevcut {param} değeri okunamadı.")

    # Gerekliyse, _set_sysctl_param ile yeni değeri ayarlarız.
    _set_sysctl_param(param, str(target_value), "Increased by DDoS-Preventer to handle more connections")


def setup_kernel_level_protection():
    """
    SYN Flood ve diğer temel ağ saldırılarına karşı iptables kurallarını ayarlar.
    """
    logger.info("Kernel seviyesi iptables koruma kuralları ayarlanıyor...")
    # 1. Kendi özel zincirimizi (-N, New chain) oluşturuyoruz.
    _run_shell(["iptables", "-N", IPTABLES_FILTER_CHAIN])
    # 2. Gelen tüm trafiği (-I INPUT 1, Insert into INPUT at position 1) ilk olarak bizim zincirimize yönlendiriyoruz.
    _run_shell(["iptables", "-I", "INPUT", "1", "-j", IPTABLES_FILTER_CHAIN])

    # --- YENİ ve GÜÇLENDİRİLMİŞ KURAL SETİ (Sıralama önemlidir) ---
    
    # Kural 1: ipset'teki IP'leri en başta engelle. Bu en hızlı ve verimli engelleme yöntemidir.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN,
                "-m", "set", "--match-set", config.DEFAULT_IPSET_NAME, "src", # Kaynak IP'si ipset listesinde olanları...
                "-j", "DROP"]) # ...sessizce düşür (DROP).

    # Kural 2: Kurulmuş ve ilgili bağlantılara hemen izin ver. Bu, meşru trafiğin sürekli kontrol edilmesini önleyerek performansı artırır.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, 
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", # Bağlantı durumu "kurulmuş" veya "ilgili" ise...
                "-j", "ACCEPT"]) # ...paketi kabul et.

    # Kural 3: Geçersiz (INVALID) paketleri düşür. Bu, bozuk veya beklenmedik paketlere karşı bir güvenlik önlemidir.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, 
                "-m", "conntrack", "--ctstate", "INVALID", # Bağlantı durumu "geçersiz" ise...
                "-j", "DROP"]) # ...paketi düşür.

    # Kural 4: Genel UDP hız limitini uygula (config'de aktifse). UDP flood saldırılarını sınırlar.
    if config.ENABLE_UDP_PROTECTION:
        logger.info(f"Genel UDP hız limiti etkinleştiriliyor ({config.UDP_LIMIT_RATE})...")
        # Belirtilen hız limitine uyan UDP paketlerini kabul et.
        _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "udp", 
                    "-m", "limit", "--limit", config.UDP_LIMIT_RATE, "--limit-burst", str(config.UDP_LIMIT_BURST),
                    "-j", "ACCEPT"])
        # Limiti aşan geri kalan tüm UDP paketlerini düşür.
        _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "udp", "-j", "DROP"])

    # Kural 5: SYN Flood'a karşı AKILLI KORUMA (hashlimit ile).
    # Bu kural, her bir kaynak IP adresinin saniyede belirli bir sayıda yeni bağlantı isteği (SYN paketi) göndermesini sağlar.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "tcp", "--syn", # Sadece yeni TCP bağlantı istekleri için...
                "-m", "hashlimit", # ...hashlimit modülünü kullan.
                "--hashlimit-upto", "25/s", # Saniyede 25 pakete kadar izin ver.
                "--hashlimit-burst", "50", # Başlangıçta 50 paketlik bir "kredi" tanı.
                "--hashlimit-mode", "srcip", # Bu limiti HER BİR KAYNAK IP'Sİ için ayrı ayrı uygula.
                "--hashlimit-name", "conn_rate", # Bu limit tablosuna bir isim ver.
                "-j", "ACCEPT"]) # Limite uyanları kabul et.
                
    # Kural 6: Geri kalan her şeyi düşür.
    # Bu, yukarıdaki ACCEPT kurallarından birine uymayan her paketi (örn: hız limitini aşan SYN'ler) engeller.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-j", "DROP"])

    logger.info("Gelişmiş Kernel seviyesi iptables koruması aktif.")


def cleanup_kernel_level_protection():
    """Eklenen tüm kernel seviyesi iptables koruma kurallarını temizler."""
    logger.info("Kernel seviyesi iptables koruma kuralları temizleniyor...")
    # 1. Kendi zincirimize olan yönlendirmeyi (-D, Delete) INPUT zincirinden kaldırıyoruz.
    _run_shell(["iptables", "-D", "INPUT", "-j", IPTABLES_FILTER_CHAIN])
    # 2. Kendi zincirimizin içindeki tüm kuralları (-F, Flush) siliyoruz.
    _run_shell(["iptables", "-F", IPTABLES_FILTER_CHAIN])
    # 3. Boş olan kendi zincirimizi (-X, Delete chain) tamamen siliyoruz.
    _run_shell(["iptables", "-X", IPTABLES_FILTER_CHAIN])
    logger.info("Kernel seviyesi iptables koruması temizlendi.")
