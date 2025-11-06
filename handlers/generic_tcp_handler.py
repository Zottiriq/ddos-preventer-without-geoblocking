# handlers/generic_tcp_handler.py
import asyncio
import logging
import socket
import struct

from core.mitigation_manager import MitigationManager

# main.py'de yapılandırılmış olan ana logger'ı çağırır.
logger = logging.getLogger("ddos-preventer")

# Gelen bir bağlantının, iptables tarafından yönlendirilmeden ÖNCE gitmesi gereken asıl hedefi bulan fonksiyon.
async def get_original_destination(writer):
    # Yazıcı (writer) nesnesinden temel soket (socket) nesnesini alır.
    sock = writer.get_extra_info('socket')
    # Olası hataları yakalamak için bir try-except bloğu kullanılır.
    try:
        # Bu, Linux'a özgü bir soket seçeneğidir (socket option).
        # iptables'ın REDIRECT hedefi tarafından yönlendirilen bir bağlantının orijinal hedefini sorgular.
        # socket.IPPROTO_IP: IP seviyesinde bir seçenek olduğunu belirtir.
        # 80: SO_ORIGINAL_DST seçeneğinin sayısal değeridir. Bu, 'iptables' tarafından saklanan orijinal hedef bilgisini ister.
        # 16: Dönecek verinin boyutu (byte olarak).
        addr = sock.getsockopt(socket.IPPROTO_IP, 80, 16)
        # 'getsockopt'tan dönen 16 byte'lık ham veriyi 'struct.unpack' ile parçalara ayırırız.
        # "!HHBBBB": Verinin nasıl okunacağını belirten format string'i.
        # !: Network byte order (big-endian)
        # H: 2 byte'lık unsigned short (port için)
        # B: 1 byte'lık unsigned char (IP adresinin her bir okteti için)
        # addr[:8]: Gelen verinin sadece ilk 8 byte'ını kullanırız, çünkü IP ve port bilgisi oradadır.
        _, port, ip1, ip2, ip3, ip4 = struct.unpack("!HHBBBB", addr[:8])
        # Parçalara ayrılmış IP oktetlerini birleştirerek okunabilir bir IP adresi string'i oluştururuz.
        ip = f"{ip1}.{ip2}.{ip3}.{ip4}"
        # Orijinal IP ve portu geri döndürürüz.
        return ip, port
    # Eğer bu işlem başarısız olursa (örn: root yetkisi yoksa veya bu bir yönlendirilmiş bağlantı değilse):
    except Exception as e:
        # Bir hata logu yazdırılır. Genellikle bu hata, script'in 'sudo' ile çalıştırılmamasından kaynaklanır.
        logger.error("Orijinal hedef alınamadı: %s. 'sudo' ile çalıştırdığınızdan emin olun.", e)
        # Hata durumunda None, None döndürülür.
        return None, None

# İki yönlü veri akışını (stream) birbirine bağlayan (köprüleyen) yardımcı bir fonksiyon.
# reader1'den okunan veriyi writer2'ye yazar ve tam tersi de başka bir çağrıda yapılır.
async def bridge_streams(reader1, writer1, reader2, writer2):
    # Olası bağlantı hatalarını (zaman aşımı, bağlantı sıfırlanması vb.) yakalamak için try bloğu.
    try:
        # Her iki okuyucu da dosya sonuna (end-of-file) ulaşmadığı sürece döngü devam eder.
        # Bu, bağlantılardan biri kapandığında döngünün sonlanmasını sağlar.
        while not reader1.at_eof() and not reader2.at_eof():
            # reader1'den en fazla 4096 byte veri okumaya çalışır. 300 saniye (5 dakika) zaman aşımı vardır.
            # Bu, bir taraftan veri gelmediğinde programın sonsuza kadar takılı kalmasını önler.
            data = await asyncio.wait_for(reader1.read(4096), timeout=300)
            # Eğer 'read' işlemi boş veri döndürürse, bu bağlantının kapandığı anlamına gelir. Döngüden çıkılır.
            if not data: break
            # Okunan veriyi diğer tarafın yazıcısına (writer2) yazar.
            writer2.write(data)
            # Yazma tamponunun (buffer) boşaltılmasını ve verinin gerçekten gönderilmesini bekler.
            await writer2.drain()
    # Zaman aşımı, bağlantı sıfırlanması gibi beklenen ve normal kabul edilen hatalar yakalanır.
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        # Bu hatalar sadece bağlantının normal bir şekilde sonlandığını gösterir, bu yüzden bir şey yapmaya gerek yoktur.
        pass
    # Hata olsa da olmasa da, bağlantı kapandığında bu blok her zaman çalışır.
    finally:
        # Her iki yazıcıyı da (writer1 ve writer2) güvenli bir şekilde kapatmak için döngüye alınır.
        for w in [writer1, writer2]:
            # Eğer yazıcı zaten kapanmıyorsa:
            if not w.is_closing():
                try:
                    # Yazıcıyı kapat.
                    w.close()
                    # Kapanma işleminin tamamlanmasını bekle.
                    await w.wait_closed()
                # Kapatma sırasında nadiren oluşabilecek hataları görmezden gel.
                except Exception:
                    pass

# Genel (HTTP olmayan) TCP bağlantılarını işleyen ana fonksiyon. Her yeni bağlantı için bu fonksiyon çağrılır.
async def handle_generic_tcp(client_reader, client_writer):
    # Bağlantıyı kuran istemcinin IP adresini ve portunu alır. Port burada kullanılmaz.
    client_ip, _ = client_writer.get_extra_info('peername', ('unknown', 0))
    # DDoS azaltma mantığını yöneten MitigationManager'dan bir nesne oluşturur.
    mitigator = MitigationManager()

    # Bu bağlantının asıl hedef IP ve portunu öğrenmek için yukarıdaki fonksiyonu çağırır.
    original_dest_ip, original_dest_port = await get_original_destination(client_writer)
    # Eğer orijinal hedef bilgisi alınamazsa, proxy işlemi yapılamaz.
    if not original_dest_port:
        # Bir uyarı loglanır ve istemci bağlantısı hemen kapatılır.
        logger.warning("Orijinal hedef port alınamadığı için bağlantı kapatılıyor: %s", client_ip)
        client_writer.close(); await client_writer.wait_closed()
        return

    # MitigationManager'a bu IP'nin bu porta erişiminin uygun olup olmadığını sorar (karaliste, saniye/istek limiti kontrolü).
    allowed, reason = await mitigator.check_and_mitigate(client_ip, original_dest_port)
    # Eğer erişime izin verilmiyorsa:
    if not allowed:
        # Bağlantının neden reddedildiğini loglar ve bağlantıyı kapatır.
        logger.warning(f"[TCP-GENERIC] Bağlantı reddedildi: {client_ip} -> port {original_dest_port} ({reason})")
        client_writer.close(); await client_writer.wait_closed()
        return

    # Eğer kontrollerden geçtiyse, yeni bir bağlantının kabul edildiğini loglar.
    logger.info(f"[TCP-GENERIC] {client_ip} -> {original_dest_ip}:{original_dest_port} bağlantısı alındı.")

    # Orijinal hedefe bağlanma ve veri aktarımı işlemleri için bir try...finally bloğu.
    try:
        # İzin verilen bağlantının anlık bağlantı sayacını artırır. Eğer limit aşıldıysa 'False' döner.
        if not await mitigator.increment_connection(client_ip, original_dest_port):
             # Limit aşıldıysa, bağlantının reddedildiğini loglar ve bağlantıyı kapatır.
             logger.warning(f"[TCP-GENERIC] Bağlantı reddedildi (limit aşıldı): {client_ip} -> port {original_dest_port}")
             client_writer.close(); await client_writer.wait_closed()
             return

        # Orijinal hedefe (asıl sunucuya) yeni bir TCP bağlantısı açar.
        dest_reader, dest_writer = await asyncio.open_connection(original_dest_ip, original_dest_port)

        # 'asyncio.gather' ile iki 'bridge_streams' görevini aynı anda çalıştırır.
        # Bu, iki yönlü (istemci -> sunucu ve sunucu -> istemci) veri akışını sağlar.
        await asyncio.gather(
            bridge_streams(client_reader, client_writer, dest_reader, dest_writer),
            bridge_streams(dest_reader, dest_writer, client_reader, client_writer)
        )
    # Orijinal hedefe bağlanırken bir hata oluşursa (örn: sunucu kapalıysa):
    except Exception as e:
        # Hata loglanır ve istemci bağlantısı kapatılır.
        logger.error(f"Hedefe bağlanılamadı ({original_dest_ip}:{original_dest_port}): {e}")
        client_writer.close(); await client_writer.wait_closed()
    # Bağlantı sonlandığında (hata olsa da olmasa da) bu blok her zaman çalışır.
    finally:
        # Bağlantı kapandığı için, bu IP ve port için aktif bağlantı sayısını bir azaltır.
        await mitigator.decrement_connection(client_ip, original_dest_port)
        # Bağlantının tamamen kapatıldığını loglar.
        logger.info(f"[TCP-GENERIC] {client_ip} -> {original_dest_ip}:{original_dest_port} bağlantısı kapatıldı.")
