Sistem Özeti

Kernel: Temel saldırıları anında engeller

iptables NAT: Tüm HTTP/TCP trafiğini Python’a yönlendirir

Python Proxy: Rate-limit, connection-limit, blacklist uygular

Sonuç: Temiz trafik gerçek hedefe iletilir, kötü trafik kernel’de kesilir

--------------------------------------------------------------------------
1) Trafik Nasıl İşlenir?

Bir kullanıcı siteye veya sunucuya bağlanmak istediğinde paket şöyle bir yol izler:

1. Paket sunucuya gelir

  - Önce fiziksel olarak ağ kartına düşer.

2. Kernel paketi inceler

  Linux kernel, gelen her paketi otomatik olarak iptables kurallarından geçirir.

  Kernel burada şunlara bakar:

  - Bu IP kara listede mi?
  - Paket bozuk mu?
  - SYN flood var mı?
  - UDP flood var mı?

  Eğer paket zararlıysa:

  - → kernel seviyesinde DROP edilir
  - → Python’a ve Nginx’e hiç ulaşmaz

3. NAT PREROUTING: Paket Python’a yönlendirilir

  Eğer paket 80, 443, 22 gibi bir porta gidiyorsa, iptables şunu yapar:

  - “Gerçek hedefe gitmeden önce Python güvenlik katmanına uğrayacaksın.”

  Yani trafik zorla Python’a yönlendirilir.
  Bu işlem tamamen kernel içinde yapılır.

4. Python Proxy isteği alır

  Python gelen paketi işler ve paketin aslında hangi porta gitmek istediğini tespit eder.

  Örnek:

  - Paket Python’a 8081’den gelmiştir ama Python bilir ki:
   - “Bu istek aslında port 80 (Nginx)’e gitmek istiyordu.”

5. Python güvenlik kontrolü yapar

  Python tarafındaki MitigationManager şunları denetler:

  - IP başına hız limiti (rate limit)
  - IP başına eşzamanlı bağlantı limiti
  - whitelist kontrolü
  - ipset blacklist kontrolü

  Eğer kurallar aşılırsa:

  - → IP ipset kara listesine alınır
  - → Kernel bu IP’den gelen paketleri engeller

6. Temiz istek gerçek hedefine gönderilir

  Eğer IP saldırgan değilse:

  - HTTP istekleri Nginx’e gönderilir (80/443)
  - TCP istekleri gerçek servisine iletilir (22/3306/25565…)

  Python burada sadece bir “köprü” görevi görür:
    - İsteği alır
    - Kontrol eder
    - Temizse gerçek hedefe iletir
