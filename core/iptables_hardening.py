# core/iptables_hardening.py
import subprocess
import logging
import config
from . import ipset_manager

logger = logging.getLogger("ddos-preventer")

IPTABLES_FILTER_CHAIN = "DDOS_FILTER"

def _run_shell(cmd):
    """iptables veya sysctl komutlarını çalıştırır ve hataları yakalar."""
    try:
        result = subprocess.run(cmd, check=True, text=True, timeout=5, capture_output=True)
        return result
    except subprocess.CalledProcessError as e:
        if "does not exist" in e.stderr or "already exists" in e.stderr:
            return None
        logger.error("Shell komut hatası '%s': %s", " ".join(cmd), e.stderr.strip())
        return None
    except Exception as e:
        logger.error("Shell komutu çalıştırılamadı '%s': %s", " ".join(cmd), e)
        return None

def _set_sysctl_param(param, value, comment="DDoS-Preventer"):
    """Bir sysctl parametresini ayarlar ve /etc/sysctl.conf'a kalıcı olarak ekler."""
    try:
        logger.info(f"Kernel parametresi ayarlanıyor: {param} = {value}")
        if not _run_shell(["sysctl", "-w", f"{param}={value}"]):
            logger.error(f"{param} geçici olarak ayarlanamadı.")
            return

        conf_path = "/etc/sysctl.conf"
        setting_line = f"{param} = {value}\n"
        with open(conf_path, 'r+') as f:
            content = f.read()
            if setting_line.strip().split('=')[0].strip() in content:
                logger.info(f"{param} ayarı {conf_path} içinde zaten mevcut.")
            else:
                f.seek(0, 2)
                f.write(f"\n# {comment}\n{setting_line}")
                logger.info(f"{param} ayarı {conf_path} dosyasına kalıcı olarak eklendi.")
    except Exception as e:
        logger.error(f"{param} ayarlanırken bir hata oluştu: {e}")

def enable_syn_cookies():
    """SYN Cookie korumasını etkinleştirir."""
    logger.info("SYN Cookie koruması kontrol ediliyor...")
    result = _run_shell(["sysctl", "net.ipv4.tcp_syncookies"])
    if result and ("= 1" in result.stdout):
        logger.info("SYN Cookie koruması zaten aktif.")
        return
    _set_sysctl_param("net.ipv4.tcp_syncookies", "1", "Enabled by DDoS-Preventer for SYN Flood protection")

def adjust_conntrack_settings():
    """Connection tracking (conntrack) tablosu boyutunu ayarlar."""
    logger.info("Connection tracking (conntrack) tablosu ayarları kontrol ediliyor...")
    param = "net.netfilter.nf_conntrack_max"
    target_value = config.KERNEL_CONNTRACK_MAX

    result = _run_shell(["sysctl", param])
    if result:
        try:
            current_value = int(result.stdout.strip().split("=")[1].strip())
            if current_value >= target_value:
                logger.info(f"{param} zaten yeterli bir değerde ({current_value}). Değişiklik yapılmadı.")
                return
        except (ValueError, IndexError):
            logger.warning(f"Mevcut {param} değeri okunamadı.")

    _set_sysctl_param(param, str(target_value), "Increased by DDoS-Preventer to handle more connections")


def setup_kernel_level_protection():
    """
    SYN Flood ve diğer temel ağ saldırılarına karşı iptables kurallarını ayarlar.
    """
    logger.info("Kernel seviyesi iptables koruma kuralları ayarlanıyor...")
    _run_shell(["iptables", "-N", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-I", "INPUT", "1", "-j", IPTABLES_FILTER_CHAIN])

    # --- YENİ ve GÜÇLENDİRİLMİŞ KURAL SETİ ---
    
    # 1. ipset listesindeki IP'leri en başta engelle
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN,
                "-m", "set", "--match-set", config.DEFAULT_IPSET_NAME, "src",
                "-j", "DROP"])

    # 2. Kurulmuş ve ilgili bağlantılardan gelen paketlere her zaman izin ver. Bu, performansı artırır.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, 
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", 
                "-j", "ACCEPT"])

    # 3. Geçersiz paketleri düşür
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, 
                "-m", "conntrack", "--ctstate", "INVALID", 
                "-j", "DROP"])

    # 4. Genel UDP hız limitini uygula
    if config.ENABLE_UDP_PROTECTION:
        logger.info(f"Genel UDP hız limiti etkinleştiriliyor ({config.UDP_LIMIT_RATE})...")
        _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "udp", 
                    "-m", "limit", "--limit", config.UDP_LIMIT_RATE, "--limit-burst", str(config.UDP_LIMIT_BURST),
                    "-j", "ACCEPT"])
        _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "udp", "-j", "DROP"])

    # 5. SYN Flood'a karşı AKILLI KORUMA (hashlimit ile)
    # Bu, tek bir IP'nin saniyede 4'ten fazla yeni bağlantı kurmasını engeller.
    # Bu kural, SYN Cookie'nin çalışmasına izin verir.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "tcp", "--syn",
                "-m", "hashlimit",
                "--hashlimit-upto", "25/s",
                "--hashlimit-burst", "50",
                "--hashlimit-mode", "srcip",
                "--hashlimit-name", "conn_rate",
                "-j", "ACCEPT"])
                
    # 6. Geri kalan her şeyi (hız limitini aşan SYN'ler, istenmeyen diğer paketler) düşür.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-j", "DROP"])

    logger.info("Gelişmiş Kernel seviyesi iptables koruması aktif.")


def cleanup_kernel_level_protection():
    """Eklenen tüm kernel seviyesi iptables koruma kurallarını temizler."""
    logger.info("Kernel seviyesi iptables koruma kuralları temizleniyor...")
    _run_shell(["iptables", "-D", "INPUT", "-j", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-F", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-X", IPTABLES_FILTER_CHAIN])
    logger.info("Kernel seviyesi iptables koruması temizlendi.")
