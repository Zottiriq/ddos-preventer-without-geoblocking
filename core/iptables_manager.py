# core/iptables_manager.py
import subprocess
import logging
import config

logger = logging.getLogger("ddos-preventer")

def _run_shell(cmd):
    """iptables komutlarını çalıştırır ve hataları yakalar."""
    try:
        subprocess.run(cmd, check=True, text=True, timeout=5, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        if "does not exist" in e.stderr or "already exists" in e.stderr:
            return True # Bu hataları yoksay
        logger.error("iptables komut hatası '%s': %s", " ".join(cmd), e.stderr.strip())
        return False

def setup_transparent_proxy_rules():
    """Gelen trafiği analiz için yerel portlarımıza yönlendiren kuralları ayarlar."""
    logger.info("Transparent Proxy için iptables yönlendirme kuralları ayarlanıyor...")

    _run_shell(["iptables", "-t", "nat", "-N", config.IPTABLES_CHAIN])

    for port, settings in config.TARGET_PORTS.items():
        proto_type = settings.get('protocol', 'tcp')
        redirect_port = config.HTTP_PROXY_LISTEN_PORT if proto_type == 'http' else config.GENERIC_TCP_LISTEN_PORT

        _run_shell([
            "iptables", "-t", "nat", "-A", config.IPTABLES_CHAIN,
            "-p", "tcp", "--dport", str(port),
            "-j", "REDIRECT", "--to-port", str(redirect_port)
        ])

    _run_shell(["iptables", "-t", "nat", "-A", "PREROUTING", "-j", config.IPTABLES_CHAIN])
    logger.info("iptables yönlendirme kuralları aktif.")

def cleanup_transparent_proxy_rules():
    """Başlangıçta eklenen tüm yönlendirme kurallarını temizler."""
    logger.info("iptables yönlendirme kuralları temizleniyor...")
    _run_shell(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", config.IPTABLES_CHAIN])
    _run_shell(["iptables", "-t", "nat", "-F", config.IPTABLES_CHAIN])
    _run_shell(["iptables", "-t", "nat", "-X", config.IPTABLES_CHAIN])
    logger.info("iptables temizlendi.")