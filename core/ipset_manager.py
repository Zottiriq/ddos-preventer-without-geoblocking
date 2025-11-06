import subprocess
import logging
import config

logger = logging.getLogger("ddos-preventer")

def _run_shell(cmd, check=True):
    """Shell komutlarını çalıştırır ve hataları yakalar."""
    try:
        result = subprocess.run(
            cmd,
            check=check,
            text=True,
            timeout=5,
            capture_output=True
        )
        return result
    except subprocess.CalledProcessError as e:
        if "does not exist" in e.stderr or "already exists" in e.stderr:
            return None
        # Sadece 'check=True' ise hata logla
        if check:
            logger.error("Shell komut hatası '%s': %s", " ".join(cmd), e.stderr.strip())
        return None
    except Exception as e:
        logger.error("Shell komutu çalıştırılamadı '%s': %s", " ".join(cmd), e)
        return None

def setup():
    """Engellenen IP'leri tutmak için bir ipset listesi oluşturur."""
    set_name = config.DEFAULT_IPSET_NAME
    logger.info(f"'{set_name}' adında ipset listesi oluşturuluyor...")
    if not _run_shell(["ipset", "create", set_name, "hash:ip", "timeout", "0"]):
        logger.error("ipset listesi oluşturulamadı. 'ipset' paketinin kurulu olduğundan emin olun.")
        return False
    logger.info("ipset listesi hazır.")
    return True

def add(ip: str, timeout: int):
    """Bir IP adresini belirtilen süreyle (saniye) ipset listesine ekler."""
    set_name = config.DEFAULT_IPSET_NAME
    logger.warning(f"[IPSET] IP engelleniyor: {ip} ({timeout} saniye)")
    _run_shell(["ipset", "add", set_name, ip, "timeout", str(timeout), "-exist"])

def contains(ip: str) -> bool:
    """Bir IP adresinin ipset listesinde olup olmadığını kontrol eder."""
    set_name = config.DEFAULT_IPSET_NAME
    # <--- DÜZELTME: 'check=False' kullanarak komutun başarısız olmasına izin veriyoruz. --->
    # Bu, "not in set" durumunun bir Python hatası fırlatmasını engeller.
    result = _run_shell(["ipset", "test", set_name, ip], check=False)
    
    # 'test' komutu başarılı olursa (return code 0), IP listededir.
    return result is not None and result.returncode == 0

def cleanup():
    """Oluşturulan ipset listesini siler."""
    set_name = config.DEFAULT_IPSET_NAME
    logger.info(f"'{set_name}' ipset listesi temizleniyor...")
    _run_shell(["ipset", "destroy", set_name])
    logger.info("ipset listesi temizlendi.")