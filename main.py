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

# "ddos-preventer" adında bir logger (kayıt tutucu) nesnesi oluşturuluyor.
logger = logging.getLogger("ddos-preventer")
# Logger'ın seviyesi INFO olarak ayarlanıyor, yani INFO ve daha üst seviye (WARNING, ERROR, CRITICAL) mesajlar işlenecek.
logger.setLevel(logging.INFO)
# Log mesajlarının formatı belirleniyor: "zaman damgası - log seviyesi - mesaj".
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
# Bir StreamHandler oluşturuluyor. Bu, logları konsola (terminale) yazdıracak.
sh = logging.StreamHandler(); sh.setFormatter(fmt); logger.addHandler(sh)
# Bir FileHandler oluşturuluyor. Bu, logları config dosyasında belirtilen dosyaya yazacak.
try:
    fh = logging.FileHandler(config.DEFAULT_LOG_FILE); fh.setFormatter(fmt); logger.addHandler(fh)
# Eğer log dosyasına yazma izni gibi bir sorun olursa, bir istisna yakalanır.
except Exception:
    # Kullanıcıya log dosyasına yazılamadığına dair bir uyarı mesajı gösterilir.
    logger.warning("Log dosyasına yazılamıyor: %s", config.DEFAULT_LOG_FILE)

def discover_listening_ports():
    """
    'ss' komutunu kullanarak sunucunun dış dünyaya açık portlarını tarar
    ve bu portları koruma altına almak için config.TARGET_PORTS'a dinamik olarak ekler.
    """
    # Otomatik port taramasının başladığına dair bilgi mesajı loglanır.
    logger.info("Sunucudaki açık TCP portları taranıyor...")
    # Olası hataları yakalamak için bir try-except bloğu başlatılır.
    try:
        # 'ss -lnt' komutu çalıştırılır. Bu komut, sadece dinlemede olan (listening) TCP portlarını listeler.
        # check=True: komut hata verirse bir istisna fırlatır.
        # capture_output=True: komutun çıktısını yakalar.
        # text=True: çıktıyı metin olarak alır.
        result = subprocess.run(["ss", "-lnt"], check=True, capture_output=True, text=True)
        # 'ss' komutunun çıktısında "0.0.0.0:PORT" veya "[::]:PORT" gibi ifadeleri bulmak için bir regex deseni derlenir.
        # Bu, sunucunun tüm ağ arayüzlerinde dinlediği portları bulur (yani dış dünyaya açık portları).
        port_pattern = re.compile(r"(?:0\.0\.0\.0|\[::\]):(\d+)")

        # 'ss' komutunun çıktısı satır satır işlenir.
        for line in result.stdout.splitlines():
            # Her satırda regex deseni aranır.
            match = port_pattern.search(line)
            # Eğer bir eşleşme bulunursa (yani bir port numarası bulunursa):
            if match:
                # Eşleşen port numarası bir tamsayıya (integer) dönüştürülür.
                port = int(match.group(1))
                # Bulunan portun, zaten config'de manuel olarak eklenmemiş veya proxy'lerimizin kendi dinleme portları OLMADIĞI kontrol edilir.
                if (port not in config.TARGET_PORTS and
                        port != config.HTTP_PROXY_LISTEN_PORT and
                        port != config.GENERIC_TCP_LISTEN_PORT):

                    # Portun bilinen bir HTTP portu olup olmadığına göre protokol tipi belirlenir ('http' veya 'tcp').
                    proto_type = 'http' if port in config.WELL_KNOWN_HTTP_PORTS else 'tcp'
                    # Yeni bir portun keşfedildiği ve koruma altına alındığı loglanır.
                    logger.info(f"Yeni herkese açık port keşfedildi: {port}. '{proto_type}' koruması altına alınıyor (varsayılan limitlerle).")
                    
                    # Keşfedilen port, korunacak portlar listesine (sözlüğüne) protokol tipiyle birlikte eklenir.
                    config.TARGET_PORTS[port] = {'protocol': proto_type}

    # Eğer 'ss' komutu sistemde bulunamazsa (FileNotFoundError), bu blok çalışır.
    except FileNotFoundError:
        logger.error("'ss' komutu bulunamadı. Otomatik port tarama devre dışı. Sadece config'deki portlar korunacak.")
    # Port tarama sırasında başka herhangi bir hata oluşursa, bu blok çalışır.
    except Exception as e:
        logger.error(f"Portlar taranırken bir hata oluştu: {e}")

# 'async def' ile asenkron bir ana fonksiyon tanımlanır. Programın ana mantığı burada çalışır.
async def main():
    # Arka plan görevi için değişken None olarak başlatılır.
    background_task = None
    # HTTP sunucusu için değişken None olarak başlatılır.
    http_runner = None
    # Genel TCP sunucusu için değişken None olarak başlatılır.
    generic_tcp_server = None
    
    # Programın düzgün bir şekilde kapatılması için bir 'Event' nesnesi oluşturulur. Sinyal geldiğinde bu event tetiklenecek.
    stop_event = asyncio.Event()
    # Mevcut asenkron olay döngüsü (event loop) alınır.
    loop = asyncio.get_event_loop()
    
    # SIGINT (Ctrl+C) ve SIGTERM (kapatma komutu) sinyalleri için bir döngü kurulur.
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Bu sinyallerden herhangi biri geldiğinde, 'stop_event'in 'set' metodunu çalıştıracak bir sinyal işleyici eklenir.
        # Bu, 'await stop_event.wait()' satırının beklemesini sonlandırır.
        loop.add_signal_handler(sig, stop_event.set)

    # try...finally bloğu, program sonlandığında veya bir hata oluştuğunda bile 'finally' kısmının çalışmasını garanti eder.
    try:
        # Saldırı azaltma yöneticisi (MitigationManager) sınıfından bir nesne oluşturulur.
        mitigator = MitigationManager()
        # Saldırıları kontrol eden ve IP'leri engelleyen arka plan görevleri başlatılır.
        background_task = asyncio.create_task(mitigator.run_background_tasks())

        # HTTP DDoS azaltıcı (HTTPDDoSMitigator) sınıfından bir nesne oluşturulur.
        http_mitigator = HTTPDDoSMitigator()
        # aiohttp kütüphanesi ile bir web uygulaması nesnesi oluşturulur.
        http_app = web.Application()
        # Uygulama içinde kullanılacak bir ClientSession oluşturulur (dış servislere istek atmak için).
        http_app["session"] = ClientSession()
        # Gelen tüm istekleri ("*") ve tüm yolları ("/{tail:.*}") 'proxy_handler' metoduna yönlendiren bir kural eklenir.
        http_app.router.add_route("*", "/{tail:.*}", http_mitigator.proxy_handler)
        # Uygulama temizlenirken (kapanırken) ClientSession'ın da kapatılmasını sağlar.
        http_app.on_cleanup.append(lambda app: app["session"].close())

        # Web uygulamasını çalıştırmak için bir AppRunner oluşturulur.
        http_runner = web.AppRunner(http_app)
        # Runner kurulur.
        await http_runner.setup()
        # Runner'ı belirtilen IP ('0.0.0.0' - tüm arayüzler) ve portta dinleyecek bir TCPSite oluşturulur.
        http_site = web.TCPSite(http_runner, '0.0.0.0', config.HTTP_PROXY_LISTEN_PORT)
        # HTTP proxy sunucusu başlatılır.
        await http_site.start()
        # HTTP proxy'nin dinlemede olduğu loglanır.
        logger.info(f"HTTP Proxy dinlemede: 0.0.0.0:{config.HTTP_PROXY_LISTEN_PORT}")

        # Genel TCP proxy sunucusu asyncio.start_server ile başlatılır.
        # Gelen her bağlantı 'handle_generic_tcp' fonksiyonuna yönlendirilir.
        generic_tcp_server = await asyncio.start_server(
            handle_generic_tcp, '0.0.0.0', config.GENERIC_TCP_LISTEN_PORT
        )
        # Genel TCP proxy'nin dinlemede olduğu loglanır.
        logger.info(f"Genel TCP Proxy dinlemede: 0.0.0.0:{config.GENERIC_TCP_LISTEN_PORT}")

        # Uygulamanın başarıyla başladığı ve çalıştığı bilgisi loglanır.
        logger.info("Uygulama çalışıyor. Durdurmak için Ctrl+C'ye basın.")
        
        # Bu satır, 'stop_event.set()' çağrılana kadar (yani bir kapatma sinyali gelene kadar) programın çalışmasını bekletir.
        await stop_event.wait()

        # --- KAPATMA MANTIĞI BAŞLANGICI ---
        # Kapatma sinyali alındığında bu mesaj loglanır.
        logger.info("Durdurma sinyali alındı, Python sunucuları kapatılıyor...")
        # Arka planda çalışan saldırı azaltma görevleri iptal edilir.
        background_task.cancel()
        # Eğer HTTP sunucusu çalışıyorsa, temizlenir ve kapatılır.
        if http_runner:
            await http_runner.cleanup()
        # Eğer genel TCP sunucusu çalışıyorsa, kapatılır.
        if generic_tcp_server:
            generic_tcp_server.close()
            # Sunucunun tamamen kapanması beklenir.
            await generic_tcp_server.wait_closed()
        # Tüm Python tabanlı sunucuların durdurulduğu loglanır.
        logger.info("Python sunucuları durduruldu.")

    # Bu blok, try bloğu bittikten sonra (hata olsa da olmasa da) her zaman çalışır.
    finally:
        # --- TEMİZLİK MANTIĞI BAŞLANGICI ---
        # Programın sonlandığı ve sistem temizliğinin başladığı loglanır.
        logger.info("Program sonlanıyor, sistem temizleniyor...")
        # iptables'a eklenen şeffaf proxy (transparent proxy) yönlendirme kuralları silinir.
        iptables_manager.cleanup_transparent_proxy_rules()
        # iptables ve sysctl ile yapılan çekirdek seviyesi (kernel-level) koruma ayarları geri alınır.
        iptables_hardening.cleanup_kernel_level_protection()
        # ipset ile oluşturulan tüm listeler (yasaklı IP listesi gibi) silinir.
        ipset_manager.cleanup()
        # Temizliğin bittiği ve programın çıkmak üzere olduğu loglanır.
        logger.info("Sistem temizlendi. Çıkılıyor.")

# Bu script'in doğrudan çalıştırılıp çalıştırılmadığını kontrol eder (başka bir script tarafından import edilmediğini anlar).
if __name__ == "__main__":
    # Programı çalıştıran kullanıcının yetkisinin root (yetkili kullanıcı) olup olmadığını kontrol eder.
    if os.geteuid() != 0:
        # Eğer kullanıcı root değilse, bir hata mesajı loglar ve programı sonlandırır.
        logger.error("HATA: Bu betik root yetkisiyle çalıştırılmalıdır ('sudo python3 main.py').")
        exit(1)
    
    # Programın çalışması için gerekli olan komutların listesi oluşturulur.
    required_commands = ["iptables", "ss", "ipset", "sysctl"]
    # Listelenen komutlardan herhangi birinin sistemde kurulu olup olmadığı kontrol edilir.
    if any(not shutil.which(cmd) for cmd in required_commands):
        # Eğer komutlardan biri bile eksikse, bir hata mesajı loglar ve programı sonlandırır.
        logger.error(f"HATA: Gerekli komutlardan biri bulunamadı. Lütfen 'iptables', 'iproute2', 'ipset' paketlerinin kurulu olduğundan emin olun.")
        exit(1)

    # Ana program bloğunu bir try-except içine alır, böylece başlangıçta oluşabilecek hatalar yakalanabilir.
    try:
        # --- BAŞLANGIÇ KURULUM ADIMLARI ---
        # SYN Flood saldırılarına karşı koruma sağlayan SYN cookie'leri etkinleştirilir.
        iptables_hardening.enable_syn_cookies()
        # Bağlantı izleme (conntrack) tablosu ayarları, yüksek trafik için optimize edilir.
        iptables_hardening.adjust_conntrack_settings()
        # ipset listeleri (örn: 'blacklist') kurulur. Eğer kurulum başarısız olursa program sonlandırılır.
        if not ipset_manager.setup():
            exit(1)
        # Sunucuda dinlemede olan portlar otomatik olarak keşfedilir.
        discover_listening_ports()
        # Keşfedilen ve config dosyasında belirtilen tüm portların son hali loglanır.
        logger.info(f"Korunacak son port listesi ve ayarları: {config.TARGET_PORTS}")
        # Çekirdek seviyesinde genel DDoS koruma kuralları (iptables, sysctl) uygulanır.
        iptables_hardening.setup_kernel_level_protection()
        # Korunacak portlara gelen trafiği yerel proxy sunucularına yönlendiren iptables kuralları ayarlanır.
        iptables_manager.setup_transparent_proxy_rules()
        
        # Tüm kurulumlar tamamlandıktan sonra, asenkron ana fonksiyon çalıştırılır.
        asyncio.run(main())
        
    # Kullanıcı Ctrl+C'ye bastığında (KeyboardInterrupt) veya başka bir beklenmedik hata (Exception) oluştuğunda bu blok çalışır.
    except (Exception, KeyboardInterrupt) as e:
        # Eğer hata KeyboardInterrupt ise (kullanıcı isteğiyle sonlandırma):
        if isinstance(e, KeyboardInterrupt):
             # Kullanıcının programı sonlandırdığına dair bir bilgi mesajı loglanır.
             logger.info("Kullanıcı tarafından program sonlandırıldı.")
        # Eğer başka bir hata ise:
        else:
             # Beklenmedik kritik bir hata oluştuğu, hatanın detayıyla birlikte loglanır.
             logger.critical("Ana programda beklenmedik bir hata oluştu: %s", e, exc_info=True)
