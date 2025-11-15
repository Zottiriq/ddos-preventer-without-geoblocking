# config.py

# --- KERNEL & IPTABLES AYARLARI ---
# ipset, iptables'dan çok daha verimli bir IP engelleme listesi yönetimi sağlar.
# Bu isimdeki bir ipset listesi oluşturulacak ve kullanılacaktır.
DEFAULT_IPSET_NAME = "ddos_blocklist"
IPTABLES_CHAIN = "DDOS_GATEWAY"

# Çekirdek (Kernel) seviyesi SYN Flood koruması için limitler.
# Yüksek trafikli siteler için bu değerleri artırmanız gerekebilir.
IPTABLES_SYN_LIMIT_RATE = "10/s"
IPTABLES_SYN_LIMIT_BURST = 20

# <--- YENİ: UDP Flood Koruması Ayarları --->
# Basit UDP flood saldırılarına karşı genel bir hız limiti uygular.
# Oyun sunucusu, DNS gibi UDP servisleriniz varsa bu ayarları dikkatli yapın.
ENABLE_UDP_PROTECTION = True
UDP_LIMIT_RATE = "100/s"
UDP_LIMIT_BURST = 200

# <--- YENİ: conntrack Tablosu Optimizasyonu --->
# Sunucunun kaldırabileceği anlık bağlantı sayısını artırır.
# Değer, sistem RAM'ine göre ayarlanmalıdır. 1GB RAM için 65536 iyi bir başlangıçtır.
KERNEL_CONNTRACK_MAX = 131072


# --- UYGULAMA KATMANI LİMİTLERİ ---
# Her bir IP adresi için varsayılan limitler.
# Bu limitler, TARGET_PORTS'ta özel bir ayar belirtilmemiş portlar için kullanılır.
DEFAULT_RATE = 20         # Saniyede izin verilen istek sayısı
DEFAULT_BURST = 50        # Anlık olarak izin verilen maksimum istek sayısı
DEFAULT_CONN_LIMIT = 100  # Tek bir IP'den izin verilen anlık toplam bağlantı sayısı
DEFAULT_BLOCK_SEC = 30   # Bir IP'nin engelli kalacağı süre (saniye)


# --- KORUNACAK PORTLAR VE ÖZEL LİMİTLER ---
# Otomatik port keşfi, bu listede olmayan diğer açık portları 'varsayılan' ayarlarla ekleyecektir.
# Bir porta özel limitler atamak için buraya ekleyebilirsiniz.
# Eğer bir limit belirtilmezse (örn: 'rate' anahtarı yoksa), yukarıdaki DEFAULT değeri kullanılır.
TARGET_PORTS = {
    22: {
        'protocol': 'tcp',
        'rate': 5,
        'burst': 10,
        'conn_limit': 10
    },
    80: {
        'protocol': 'http',
        'rate': 15,
        'burst': 25
    },
    # <--- DÜZELTME: 443 (HTTPS) trafiği şifreli olduğu için TCP katmanında ele alınmalıdır. --->
    443: {
        'protocol': 'tcp',
        'rate': 100,
        'burst': 200
    }
}

# Otomatik keşfin bu portları 'http' olarak sınıflandırmasını sağlar.
# <--- DÜZELTME: 443 buradan kaldırıldı. --->
WELL_KNOWN_HTTP_PORTS = {80, 5000, 8000, 8080}

# Proxy sunucularımızın dinleyeceği iç portlar.
# Bu portların TARGET_PORTS listesinde OLMADIĞINDAN emin olun!
HTTP_PROXY_LISTEN_PORT = 8081
GENERIC_TCP_LISTEN_PORT = 9000


# --- SİSTEM VE SERVİS AYARLARI ---
DEFAULT_LOG_FILE = "/home/log/ddos-preventer.log"
