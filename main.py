# main.py
import asyncio
import logging
import os
import shutil
import signal
import subprocess
import re

from aiohttp import web, ClientSession

import config
from core import iptables_manager
from core import iptables_hardening
from core import ipset_manager
from core.mitigation_manager import MitigationManager
from handlers.http_handler import HTTPDDoSMitigator
from handlers.generic_tcp_handler import handle_generic_tcp

logger = logging.getLogger("ddos-preventer")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
sh = logging.StreamHandler(); sh.setFormatter(fmt); logger.addHandler(sh)
try:
    fh = logging.FileHandler(config.DEFAULT_LOG_FILE); fh.setFormatter(fmt); logger.addHandler(fh)
except Exception:
    logger.warning("Log dosyasına yazılamıyor: %s", config.DEFAULT_LOG_FILE)

def discover_listening_ports():
    """
    'ss' komutunu kullanarak sunucunun dış dünyaya açık portlarını tarar
    ve bu portları koruma altına almak için config.TARGET_PORTS'a dinamik olarak ekler.
    """
    logger.info("Sunucudaki açık TCP portları taranıyor...")
    try:
        result = subprocess.run(["ss", "-lnt"], check=True, capture_output=True, text=True)
        port_pattern = re.compile(r"(?:0\.0\.0\.0|\[::\]):(\d+)")

        for line in result.stdout.splitlines():
            match = port_pattern.search(line)
            if match:
                port = int(match.group(1))
                if (port not in config.TARGET_PORTS and
                        port != config.HTTP_PROXY_LISTEN_PORT and
                        port != config.GENERIC_TCP_LISTEN_PORT):

                    proto_type = 'http' if port in config.WELL_KNOWN_HTTP_PORTS else 'tcp'
                    logger.info(f"Yeni herkese açık port keşfedildi: {port}. '{proto_type}' koruması altına alınıyor (varsayılan limitlerle).")
                    
                    config.TARGET_PORTS[port] = {'protocol': proto_type}

    except FileNotFoundError:
        logger.error("'ss' komutu bulunamadı. Otomatik port tarama devre dışı. Sadece config'deki portlar korunacak.")
    except Exception as e:
        logger.error(f"Portlar taranırken bir hata oluştu: {e}")

async def main():
    background_task = None
    http_runner = None
    generic_tcp_server = None
    
    # Kapanma sinyalini yakalamak için bir Event oluştur
    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    
    # Sinyal geldiğinde sadece Event'i set et, başka bir şey yapma
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    try:
        mitigator = MitigationManager()
        background_task = asyncio.create_task(mitigator.run_background_tasks())

        http_mitigator = HTTPDDoSMitigator()
        http_app = web.Application()
        http_app["session"] = ClientSession()
        http_app.router.add_route("*", "/{tail:.*}", http_mitigator.proxy_handler)
        http_app.on_cleanup.append(lambda app: app["session"].close())

        http_runner = web.AppRunner(http_app)
        await http_runner.setup()
        http_site = web.TCPSite(http_runner, '0.0.0.0', config.HTTP_PROXY_LISTEN_PORT)
        await http_site.start()
        logger.info(f"HTTP Proxy dinlemede: 0.0.0.0:{config.HTTP_PROXY_LISTEN_PORT}")

        generic_tcp_server = await asyncio.start_server(
            handle_generic_tcp, '0.0.0.0', config.GENERIC_TCP_LISTEN_PORT
        )
        logger.info(f"Genel TCP Proxy dinlemede: 0.0.0.0:{config.GENERIC_TCP_LISTEN_PORT}")

        logger.info("Uygulama çalışıyor. Durdurmak için Ctrl+C'ye basın.")
        
        # Program burada sinyal gelene kadar bekler
        await stop_event.wait()

        # <--- YENİ MANTIK: Sinyal geldikten sonra, finally bloğundan ÖNCE sunucuları kapat --->
        logger.info("Durdurma sinyali alındı, Python sunucuları kapatılıyor...")
        background_task.cancel()
        if http_runner:
            await http_runner.cleanup()
        if generic_tcp_server:
            generic_tcp_server.close()
            await generic_tcp_server.wait_closed()
        logger.info("Python sunucuları durduruldu.")

    finally:
        # <--- YENİ MANTIK: Bu blok, sunucular tamamen kapandıktan SONRA çalışır --->
        logger.info("Program sonlanıyor, sistem temizleniyor...")
        iptables_manager.cleanup_transparent_proxy_rules()
        iptables_hardening.cleanup_kernel_level_protection()
        ipset_manager.cleanup()
        logger.info("Sistem temizlendi. Çıkılıyor.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.error("HATA: Bu betik root yetkisiyle çalıştırılmalıdır ('sudo python3 main.py').")
        exit(1)
    
    required_commands = ["iptables", "ss", "ipset", "sysctl"]
    if any(not shutil.which(cmd) for cmd in required_commands):
        logger.error(f"HATA: Gerekli komutlardan biri bulunamadı. Lütfen 'iptables', 'iproute2', 'ipset' paketlerinin kurulu olduğundan emin olun.")
        exit(1)

    try:
        # iptables kurallarını ve ipset'i en başta kur
        iptables_hardening.enable_syn_cookies()
        iptables_hardening.adjust_conntrack_settings()
        if not ipset_manager.setup():
            exit(1)
        discover_listening_ports()
        logger.info(f"Korunacak son port listesi ve ayarları: {config.TARGET_PORTS}")
        iptables_hardening.setup_kernel_level_protection()
        iptables_manager.setup_transparent_proxy_rules()
        
        # Ana programı çalıştır
        asyncio.run(main())
        
    except (Exception, KeyboardInterrupt) as e:
        if isinstance(e, KeyboardInterrupt):
             logger.info("Kullanıcı tarafından program sonlandırıldı.")
        else:
             logger.critical("Ana programda beklenmedik bir hata oluştu: %s", e, exc_info=True)