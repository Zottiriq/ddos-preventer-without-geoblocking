# main.py
import asyncio
import logging
import os
import shutil
import signal
# <--- DEĞİŞİKLİK: Yeni importlar eklendi --->
import argparse
import subprocess
import re
# <--- DEĞİŞİKLİK SONU --->

from aiohttp import web, ClientSession

import config
from core import iptables_manager
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

# <--- YENİ FONKSİYON BAŞLANGICI --->
def discover_listening_ports():
    """
    'ss' komutunu kullanarak sunucunun dış dünyaya (0.0.0.0 ve [::])
    açık olan portlarını tarar ve config.TARGET_PORTS'a dinamik olarak ekler.
    """
    logger.info("Sunucudaki açık TCP portları taranıyor...")
    try:
        # -l: dinleyen, -n: numerik, -t: tcp
        result = subprocess.run(["ss", "-lnt"], check=True, capture_output=True, text=True)

        # Hem IPv4 (0.0.0.0:80) hem de IPv6 ([::]:443) adreslerini yakalayan regex
        port_pattern = re.compile(r"(?:0\.0\.0\.0|\[::\]):(\d+)")

        for line in result.stdout.splitlines():
            match = port_pattern.search(line)
            if match:
                port = int(match.group(1))

                # Kendi proxy portlarımızı veya zaten eklenmiş bir portu tekrar eklemeyi önle
                if (port not in config.TARGET_PORTS and
                        port != config.HTTP_PROXY_LISTEN_PORT and
                        port != config.GENERIC_TCP_LISTEN_PORT):

                    # Portun HTTP mi yoksa genel TCP mi olduğuna karar ver
                    proto_type = 'http' if port in config.WELL_KNOWN_HTTP_PORTS else 'tcp'
                    logger.info(f"Yeni herkese açık port keşfedildi: {port}. '{proto_type}' koruması altına alınıyor.")
                    config.TARGET_PORTS[port] = proto_type

    except FileNotFoundError:
        logger.error("'ss' komutu bulunamadı. Otomatik port tarama devre dışı. Sadece config'deki portlar korunacak.")
    except Exception as e:
        logger.error(f"Portlar taranırken bir hata oluştu: {e}")
# <--- YENİ FONKSİYON SONU --->


async def main():
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
    logger.info(f"HTTP Proxy dinlemede: 0.0.0.0:{config.HTTP_PROXY_LISTEN_PORT} -> Dinamik Hedefleme Aktif")

    generic_tcp_server = await asyncio.start_server(
        handle_generic_tcp, '0.0.0.0', config.GENERIC_TCP_LISTEN_PORT
    )
    logger.info(f"Genel TCP Proxy dinlemede: 0.0.0.0:{config.GENERIC_TCP_LISTEN_PORT}")

    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, stop_event.set)
    loop.add_signal_handler(signal.SIGTERM, stop_event.set)
    await stop_event.wait()

    logger.info("Sunucular durduruluyor...")
    background_task.cancel()
    await http_runner.cleanup()
    generic_tcp_server.close()
    await generic_tcp_server.wait_closed()

if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.error("HATA: Bu betik root yetkisiyle çalıştırılmalıdır ('sudo python3 main.py').")
        exit(1)
    if not shutil.which("iptables") or not shutil.which("ss"):
        logger.error("HATA: 'iptables' veya 'ss' komutları bulunamadı. Lütfen 'iproute2' ve 'iptables' paketlerini kurun.")
        exit(1)

    try:
        # <--- DEĞİŞİKLİK: Otomatik tarama fonksiyonu program başlangıcında çağrılıyor --->
        discover_listening_ports()
        logger.info(f"Korunacak son port listesi: {config.TARGET_PORTS}")

        iptables_manager.setup_transparent_proxy_rules()
        asyncio.run(main())
    except Exception as e:
        logger.critical("Ana programda beklenmedik bir hata oluştu: %s", e)
    finally:
        logger.info("Program durduruluyor, sistem temizleniyor...")
        iptables_manager.cleanup_transparent_proxy_rules()