                                            ANDROID'i DAHA GÜVENLİ KULLANABİLMEK
                                 
                                               
Günümüzde evlerimizde bulunan kisisel masaüstü bilgisayarlardan ve diz üstü bilgisayarlardan farkli olarak akilli telefonlarin,tabletlerin güvenli kullanimi daha zordur.Dünya üzerinde Android,IOS ve Windows isletim sistemleri ile olusturulmus tasinabilir cihazlarin sayisi oldukça fazladir. Bu pazarda Android isletim sistemi ve android ile olusturulmus cihazlarin
sayisi digerlerine göre oldukça yüksektir.Fiyatlarinin düsük olmasi sebebi ile tercih edilen Android tabanli cihazlarin güvenlik açigi oldukça yüksektir.  

Android kullaniminda saldirganlarin basvuracagi yöntemler kisisel bilgilerin yani sira, tasinabilir cihazlari fazlasi ile kullanan kurumlari da zor durumda birakmaktadir.Bu kilavuzda kisisel cihazlarin güvenlik sikilastirma adimlari ile Android isletim sisteminin yetki seviyesi güvenligi,network güvenliği ayrintili olarak islenecek olmasina ragmen, kurumsal mobil cihaz güvenligine de
deginecegiz.

Android isletim sistemine sahip cihaz ve uygulamalarin maruz kaldigi en büyük saldiri çesidi 'Rooting' saldirilaridir. IOS da özel olarak ismi 'jailbreaking' olarak geçmektedir.Bu saldiri sonrasinda cihazin dosya sistemi yönetimi ele geçirilmekte ve mikrofon açma,kamera çalistirma ile ortam kaydi alma,dosya kriptolama,e-mail eklerinin okunmasi gibi saldirilar kullanici
ve kurumlara ciddi zararlar vermektedir. Bu sebep ile bu kilavuzda ilerleyen adimlarda Android'de GÜVENLIK sikilastirma adimlari ile Rooting saldirilarinin önlenmesi daha detayli islenecektir.

**A)** **KURUMSAL MOBİL GÜVENLİK**:

**a) Mobil Cihaz Yönetim Sistemleri ( MDM ):**

    Son kullaniciya verilen mobil cihazin fiziksel ve politika olarak yönetimi,kurumsal anlamda Android güvenliginin ilk adimi olmaktadir.
    Bu açidan bakildiginda uç cihazda saglanmasi gereken güvenlik adimlari asagidaki gibidir:
    1) Son kullanicinin mikrofon,kamera açma vb.yetkilerinin özel durumlar hariç alinmasi,
    2) Cihazin sürekli olarak MDM çözümü tarafindan takibinin saglanmasi ( GPS ile ) ve çalinti durumunda uzaktan hard-reset vb. yöntemler ile bilgi güvenliginin saglanmasi,
    3) Son kullanicinin mobil cihazindaki kisisel uygulamalar ile ( Facebook vb. ) kurumsal kaynaklarin izole edilmesi için Güvenli Bölge ( Secure Workspace ) olusturulmasi,
    4) Son kullanicinin kriptolu güvenli bölgeye geçisi esnasinda Single-Sign-On, One-Time-Password, Touch-ID gibi dogrulama mekanizmalarinin olusturulmasi,
    5) Son kullanicinin Güvenli Bölge içerisinde ekran görüntüsü alma,e-mail eklerini kopyalama gibi islemleri yapmasinin engellenmesi,

Bu temel adimlarin saglanabilmesi için Airwatch,Mobile Iron gibi Gartner'da üst seviyelerde yer alan MDM çözümleri kullanilmaktadir.
Herhangi bir ihlal durumunda sistem yöneticisini uyarma mekanizmalari da oldukça avantaj saglamaktadir.

   **b) Gelismis Siber Saldirilari Önleme ( Sandboxing,Dynamic Rating/Analysis ) Çözümleri:**

MDM ile saglanan temel özellikler bilinmeyen zararli yazilimlara,Güvenli Bölge kirma saldirilarina karsi yeterince etkili degildir.
Bu sebep ile MDM çözümleri dinamik olarak zararli yazilim analizi yapan third-party çözümler ile entegre edilmelidir.
Fireye,Checkpoint vb.üreticilerin çözümleri bu konularda yetkindir.
       
   **c) Android Tabanli Cihazlarin Güvenlik Odakli Seçimi:**
   
Yukarida bahsi geçen çözümler, kurumlarin kendi bünyelerinde alabilecekleri önlemlerdir.
Bir kurumun agina sizilmasi için kullanilabilecek en zayif noktalardan biri Mobil Cihazlardir.
Android tabanli cihazlara yapilan saldirilar arttikça çesitli cihaz üreticileri ( Samsung vb. ) güvenlik konusuna daha çok önem vermeye başladılar.
Bu da beraberinde yeni isletim sistemi versiyonlari ve çözümleri getirdi.
Android for Work, Samsung KNOX, Android Lollipop bunlardan bazilaridir.
Kurumlarin bu cihazlari ve onlari destekleyen MDM çözümlerini kullanmalari güvenlik açisindan fayda saglayacaktir.

Son olarak Web Application Firewall, F5-BIG-IP APM gibi çözümler ile MDM'in entegrasyonu kurumun dis dünyaya bakan uygulamalarinin güvenligi için katki saglayacaktir.

  **B) KISISEL ANDROID CIHAZLARININ GÜVENLİĞİ:**
  
Kisisel amaç ile kullandigimiz Android tabanli cihazlarin güvenliginin saglanabilmesi amaci ile çesitli kontrol listeleri bulunmaktadir.
Kilavuzun bu bölümündeki amaç basit ama etkili adimlarin kontrol listesi olarak sunulmasidir. Asagidaki kontrol listesi Android 4.0 ve sonrasi için geçerlidir.
Android isletim sisteminin güvenligi detayli olarak anlatilacaktir.

    1) Android Isletim Sistemi'nin düzenli olarak güncellenmesi,
    2) Cihazin root yetki seviyesinde kullanilmamasi,: Root yetki seviyesinde kullanmak beraberinde ciddi güvenlik zaafiyetleri olusturabilir.Örnegin bir uygulama kendi sandbox alanını aşarak zararlı program şeklinde çalışabilir.
    3) Third-party uygulama kaynaklarindan uygulama yüklememek: Google Play diger uygulama depolarina göre daha temkinli davranmaktadir.
    4) Cihaz kriptolanmasini aktif etmek: Buradaki amaç passcode / password ile hassas bilgiye erisimin kisitlanmasidir.
    5) Developer Opsiyonunu inaktif hale getirmek: Android developerlar USB girisleri ile isletim sistemi üzerinde ve storage alaninda islem yapabilirler.Disaridan birinin bu islemi yapabilmesi için bu önlem alinmalidir.
    6) Cihazin kullanim süresi doldugunda,geri dönüsüm vb. asamalarda içindeki bilgilerin temizlenmesi,
    7) Cihaz uyku moduna geçtiginde aktif hale gelecek bir PIN ekrani / PIN kodu yaratilmasi,
    8) Alfanumerik sifrelerin kullanilmasi,
    9) Auto-Lock süresinin belirlenmesi: Bu opsiyon ile cihazin belirli bir süre inaktif kalmasi halinde kapanmasi saglanir.
    10) Sifre girisleri esnasinda karakterlerin kisa süreli olsa da gizlenmesinin saglanmasi,
    11) Sifrenin belirli sayida yanlis girilmesi sonucu bilgilerin silinmesi: Bu özellik Android'in entegre olabilecegi third-party bir çözüm ile saglanir.
    12) Ziyaret edilen web siteleri ile ilgili güvenlik uyarilarinin aktif edilmesi: Bu özellik ile SSL sertifika tarih asimi,geçersiz sertifika gibi uyarilar alinmaktadir.
    13) Auto-Fill özelliginin inaktif hale getirilmesi: Üst üste ziyaret edilen web siteleri otomatik doldurma özelligini aktif hale getirerek, kredi karti numarasi,sifre gibi hassas bilgilerin çalınmasına sebep olabilir.
    14) Sifrelerin otomatik hatirlanma özelliginin kullanilmamasi
    15) Browser plug-in'lerin inaktif hale getirilmesi: Zararli Yazilimlarin sisteme zarari için ciddi bir açiktir.Sadece güvenilir siteler için aktif edilmelidir.
    16) Girilen Web Sitelerinin takibinin engellenmesi,
    17) Bluetooth'un yalnizca ihtiyaç halinde kullanilmasi,
    18) Lokasyon servislerinin kapatilmasi,
    19) Otomatik kablosuz baglantinin engellenmesi için 'forget SSID' seçeneginin kullanilmasi,
    20) Google Play'de yer alan TextSecure uygulamasi ile SMS'lerin sifrelenmesi,

Android mobil cihazimizin güvenliginin saglanmasi için yapilabilecek islemlerden bazilaridir.

  **ANDROİD NETWORK ve KERNEL GÜVENLİĞİ**
  
  **a) DroidWall ( Uygulama Firewall'u )**
  
Droidwall Android cihazlarda kullanilabilecek olan 'Uygulama Tabanli Firewall' olarak islev yapabilen bir uygulamadir.
Linux Security Modules'e benzer olarak iptables kullanmaktadir.
Bu uygulamanin düzgün bir sekilde konfigüre edilmesi Android Güvenligi açisindan önemlidir.Fakat cihazda root gereksinimi vardir.
Asagida çesitli saldirilari önlemek için örnek konfigürasyonlar bulunmaktadir.

--Kernel Parametreleri,Degiskenler ve Modlar:

    ### KERNEL PARAMETERS ###
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
    echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
    echo 0 > /proc/sys/net/ipv4/ip_forward
    ### VARIABLES & MODULES ###
    # Variables
    #IPTABLES=/system/bin/iptables
    #IP6TABLES=/system/bin/ip6tables
    #MODPROBE=/system/xbin/modprobe
    INT_NET=192.168.0.0/16
    INT_INTF=eth0
    VPN_INTF=tap0

    # Modules
    #$MODPROBE ip_conntrack
    #$MODPROBE iptable_nat  
    
--IPTABLES KURALLARI:

**1) Flush kurallari:**

  $IPTABLES -F INPUT
  
  $IPTABLES -F FORWARD
  
  $IPTABLES -F droidwall-drop
    
**2) Loglama ve Paket Düsürme için:**

   $IPTABLES --new droidwall-drop
   
   $IPTABLES -A droidwall-drop -j LOG --log-prefix "[DROIDWALL] " --log-uid
   
   $IPTABLES -A droidwall-drop -j DROP
    
  **3) Spoofing:**
  
  $IPTABLES -A INPUT --source "127.0.0.0/8" ! -i lo -j droidwall-drop
  
  $IPTABLES -A INPUT --destination "127.0.0.0/8" ! -i lo -j droidwall-drop
  
  $IPTABLES -A INPUT --source "192.168.0.0/16" ! -i $INT_INTF -j droidwall-drop
  
  $IPTABLES -A INPUT --destination "192.168.0.0/16" ! -i $INT_INTF -j droidwall-drop
  
  $IPTABLES -A INPUT --source "10.0.0.0/8" -j droidwall-drop
  
  $IPTABLES -A INPUT --destination "10.0.0.0/8" -j droidwall-drop
  
  $IPTABLES -A INPUT --source "169.254.0.0/16" -j droidwall-drop
  
  $IPTABLES -A INPUT --destination "169.254.0.0/16" -j droidwall-drop
  
  $IPTABLES -A INPUT --source "172.16.0.0/20" -j droidwall-drop
  
  $IPTABLES -A INPUT --destination "172.16.0.0/20" -j droidwall-drop
  
  $IPTABLES -A INPUT --source "224.0.0.0/4" -j DROP
  
  $IPTABLES -A INPUT --destination "224.0.0.0/4" -j DROP
  
  $IPTABLES -A INPUT --source "240.0.0.0/5" -j droidwall-drop
  
  $IPTABLES -A INPUT --destination "240.0.0.0/5" -j droidwall-drop
  
  $IPTABLES -A INPUT --source "0.0.0.0/8" -j DROP
  
  $IPTABLES -A INPUT --destination "0.0.0.0/8" -j DROP
  
  $IPTABLES -A INPUT --source "255.255.255.255" -i $VPN_INTF -j DROP
  
  $IPTABLES -A INPUT --destination "255.255.255.255" -i $VPN_INTF -j DROP

  **4) Lokal bir cihazin trafiginin kabulu için:**
  
  $IPTABLES -A INPUT -i lo -j ACCEPT
  $IPTABLES -A OUTPUT -o lo -j ACCEPT
  
**5) ICMP trafigini düsürmek için:**

  $IPTABLES -A INPUT -f -j DROP
  
  $IPTABLES -A FORWARD -f -j DROP
  
  $IPTABLES -A "droidwall" -f -j DROP

**6) Fragmante edilmis ve düsürülmemis paketleri engellemek için:**

  $IPTABLES -A INPUT -f -j DROP
  
  $IPTABLES -A FORWARD -f -j DROP
  
  $IPTABLES -A "droidwall" -f -j DROP
  
  **7) Disariya gönderilen bir TCP paketinin mutlaka SYN bit'inin 1 olarak isaretlenmesinin saglanmasi için:**
  
  $IPTABLES -A "droidwall" -p tcp ! --syn -m state --state NEW -j DROP

  **8) TCP Durumlari'nin gözlemlenmesi ve Geç/Düsür kurallarinin yazilmasi için:**
  
   $IPTABLES -A INPUT -m state --state INVALID -j DROP

   $IPTABLES -A FORWARD -m state --state INVALID -j DROP

   $IPTABLES -A "droidwall" -m state --state INVALID -j DROP

  $IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  **9) OpenVPN saldirilarinin engellenmesi için:**
  
  $IPTABLES -A "droidwall" -o $VPN_INTF -j "droidwall-wifi"

  **10) Geçersiz SYN bitine sahip ( yanlis isaretlenmis ) paketlerin düsürülmesi için:**
  
  $IPTABLES -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP

  $IPTABLES -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

  $IPTABLES -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

  $IPTABLES -A FORWARD -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP

  $IPTABLES -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

  $IPTABLES -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

  $IPTABLES -A "droidwall" -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP

  $IPTABLES -A "droidwall" -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

  $IPTABLES -A "droidwall" -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

 **b) Android Cihazlar için Network Seviyesinde IDS/IPS Kurulumu:**
 
  Android cihazlarin üzerindeki trafigin analizi çesitli saldirilarin ( Cross-Site-Scripting,USSD,SQL Injection vb. ) engellenmesi için önemli bir adimdir.
Geçmiste Android cihaz ile üzerine snort kurulan bilgisayar arasinda VPN kurularak Android cihaz trafigi analiz edilirdi.
Fakat 2013 BlackHat sunumlarinda da belirtildigi gibi OSfooler yaklasimi ile bilgisayarlarin isletim sistemlerinin zaafiyetleri tespit edilip, Snort çalisan bilgisayar ele geçirilebilirdi.

  Ayrica Kernel ve User düzlemlerinde var olan paket isleme mekanizmalari problem yaratabilirdi.Örnegin, siraya alinma islemi birçok paketin düsmesine sebep olabilirdi.

Bu problemlerin çözülmesi için paketlerin Android'e gelmeden gerçek zamanli olarak analiz edilmesi gerekmektedir.
Iste bu durumda gerçek zamanli olarak protokol analizi yapabilen,içerik arama ve eslestirme fonksiyonlarina sahip bir IDS/IPS sistemi oldukça faydalidir.

Android cihazlarda bulunan sensörler araciligi ile:

      1)Trafik analiz edilir,
      2) Kullaniciyi tehditler hakkinda uyarmak için uyarilar gönderilir,
      3) Spesifik paketlerin düsürülmesi, iptables'a yeni kurallarin yüklenmesi ve çesitli scriptlerin kullanimi saglanir,
      4) Güncel imzalar ile senkronizasyon saglanir,

Android için network seviyesinde bir IDS/IPS sistemi kuruldugunda, Android sensörler loglarini içerideki bir Linux Sunucu'ya gönderirler.
Bu sunucu,

      1) Imzalarin Android cihazlara gönderilmesi,
      2) Olay loglarinin kayit altina alinmasi,
      3) Gerçek zamanli istatistiksel verinin çikartilmasini saglar.

Kurulan bu IDS/IPS sistemi sayesinde nmap gibi çesitli tarama araçlarindan gelen paketler düsürülerek; açik portlar araciligi ile cihazin ele geçirilmesi engellenebilir.

Android cihazlar oldukça yaygin kullanilmaktadir ve USSD kod ile ( genelde servis saglayicilarin kendi uygulamalarina erisim kullandirdigi bir yöntemdir ) cihaz içerisine zararlilarin sizmasi,
SMS'ler ile trojanlarin nüfuz etmesi mümkündür.Bu tür önemli saldirilarin engellenmesi için önemlidir.

  **c) Android Sertifika Kara Listesi:**
  
Ideal sartlarda,saglikli çalisan bir PKI ( Public Key Infrastructure ) sistemi sertifika dogrulama,dagitimi ve güncellenmesi konularini dikkate alir.
Bu sekilde ele geçirilmis olan sertifikalara karsi önlem alinmis olur.
Bir sertifikanin ele geçirilmesi sonucu yapilabilecek 2 muhtemel hamle: a) Istemcilerin güvenilir sertifika alanindan ilgili sertifikayi uzaklastirmak b) Etkilenen sertifikayi Vekil Sunucu vb.cihazlardan uzaklastirmaktir.

Fakat günümüzde bir istemcinin düzenli olarak güvenilir sertifika güncellemesi yapmasi her zaman mümkün olmamaktadir.Her daim network baglantisinin bulunup, düzenli olarak baska cihazlara erisim
yapmasi ve dogru kaynaklardan bilgi almasi gerekmektedir. Ayrica Windows vb. isletim sistemlerinin güncellemeleri de vakit alirsa problem daha da büyümektedir.

Android cihazlarda ise web tarayicinin güvenecegi sertifikalar listesi Bounce Castle anahtar depolama dosyasidir. Bu dosyayi cihazda root yetkisine sahip olmadan düzenlemek imkansizdir.
Ele geçirilmis olan sertifikalarin güvenilir listeden uzaklastirilmasi ise Isletim Sistemi Güncellemesi gerektirmektedir. Bu ise kullaniciya bagli bir durumdur.
Buna ek olarak,kullanici az satan bir cihaza sahip ise üreticinin isletim sistemi güncellemesi de çok nadirdir.
Bu durumlar kullaniciyi ele geçirilmis sertifikalara güvenmeye iter.

Bu durumu engellemek için Android 4.1 ile birlikte, kullanimi kullaniciya da bagli olan,online güncellemeler ve sertifika kara liste olusturma güvenlik sikilastirma adimlari gelmistir.
2 kara liste sistemi bulunmaktadir:

     a) Public Key Hash Listesi ( Ele geçirilmis olan sertifikalarin uzaklastirilmasi için )
     b) Seri Numarasi Kara Listesi ( Ele geçirilmis olan EE sertifikalarin uzaklastirilmasi için )

Bu ayrintinin etkili bir sikilastirma adimi olarak kullanilmasi için, nasil çalistigina dair biraz daha detay vermeliyiz:

Android isletim sistemi ayarlarini sistem veritabaninda tutmak için Content Provider kullanir.2 yeni güvenlik ayari asagidaki URL'lerde toplanmistir.

     1) content://settings/secure/pubkey_blacklist
     2) content://settings/secure/serial_blacklist


Ilk URL ele geçirilmis sertifikalarin hash (bütünlük) degerlerini, ikinci URL ise EE sertifika seri numaralarini depolar.
Ayni zamanda sistem bu 2 URL için kendini 'ContentObserver' olarak kaydeden 'CertiBlacklister' olusturur.Ne zaman bir degisiklik olsa 'CertiBlacklister' uyarilip,degisiklik diske yazilir.
Kaydeddilen dosyalar ve formatlari su sekildedir:

     1) certificate blacklist: /data/misc/keychain/pubkey_blacklist.txt
     2) serial number blacklist: /data/misc/keychain/serial_blacklist.txt
     
Sertifika dogrulama sistemi bütün Android sistemi boyunca kullanilir.Dolayisiyla kara liste olusturma HTTP client class, Web View ve Android Browser kullanan uygulamalari etkiler.
Bu listeleri modifiye etmek sistem izni gerektirmektedir ve yalnizca çekirdek sistem uygulamalari yapabilir.
Sertifika yönetimini düzgün yapmak isteyenler Google Servis Bilesenlerini kullanabilirler. Google Client Messaging push-style uyarilar ile güncel bir kara liste olusumu saglayabilmektedir.

Gerçek bir Android cihaz üzerinde bu sikilastirma adimi 'Certificate Blacklisting' uygulamasi ile basarilabilir.
Bu uygulama ile,

      1) Güvenilir Sertifika Depolama alanina sertifika eklenebilir,
      2) Sertifika zinciri dogrulanabilir,
      3) Sertifika kara listeye eklenebilir,
      4) Ele geçirilmis sertifika uzaklastirilabilir,
      
Bu sekilde PKI kaynakli saldirilara ve zaafiyetlere karsi etkin bir önlem alinmis olunur.

 **d) Android Sertifika Pinning:**

Android uygulamalarin disaridaki sunuculara güvenilir baglanti yapmasi önemlidir.
En basit örnek, Android web tarayicilarinin güvenilir SSL baglanti yapmalari gerekmektedir.
Bu noktada problem, web tarayici vb. uygulamalarin ele geçirilmemis PKI Sertifikalari'na güvenmesini nasil saglayacagimizdir. Comodo vb. public sertifikalarin ele geçirildigi bilinmektedir.

Özellikle mobil bankacilik uygulamalari açisindan kritik öneme sahip olan bu güvenli network baglantisi problemi 'Android pinning' ile çözülebilmektedir.
'Android pinning' ile bir banka uygulama sertifikasinin isletim sistemi güncellemesi vb. kosullara bagli olmadan güvenilir olmasi saglanir.
Android cihazin içerisine hard-coded olarak ilgili sertifika gömülür.
Bu sikilastirma adiminin uygulanmasi Android Gelistiriciler içindir fakat önemli bir Güvenli Ag Baglantisi adimidir.
Bir örnegi su sekildedir:

PinningTrustManager ile basit bir **HttpsURLConnection** kurmak için;

     // Define an array of pins.  One of these must be present
     // in the certificate chain you receive.  A pin is a hex-encoded
     // hash of a X.509 certificate's SubjectPublicKeyInfo. A pin can
     // be generated using the provided pin.py script:
     // python ./tools/pin.py certificate_file.pem
     String[] pins                 = new String[] {"f30012bbc18c231ac1a44b788e410ce754182513"};
     URL url                       = new URL("https://www.google.com");
     HttpsURLConnection connection = PinningHelper.getPinnedHttpsURLConnection(context, pins, url);'''

 Cihazda default olarak güvenilir kilinmis sertifika/alan'lari görmek için:
 
 '''cat /data/misc/keychain/pins | cut -d"=" -f1 
*.youtube.com 
*.profiles.google.com'''

  komutu kullanilabilir.
  
 **ANDROID UYGULAMA GÜVENLİĞİ**
 
 Bu adimda Android Isletim Sistemi üzerinde kullanici uygulama bilgilerinin güvenligi için yapilacak kontroller ve atilacak adimlar anlatilmaktadir.
 
 **Güvenlik ve Gizlilik Açisindan Degerli Adimlar:**
 
Android isletim sistemi varsayilan olarak tarif edilen belirli güvenlik mekanizmalari ile cihazlarin içerisine gömülmektedir.
Bu sekilde uygulamalara karsi yapilan saldirilarin sikligi ve etkisi azaltilmaktadir.
Bu güvenlik mekanizmalari su sekildedir:

    a) Android Uygulama Sandbox ( Izole Alani ): 
    b) Kriptografi,izinler,prosesler arasi güvenli iletisimi saglayacak (secure IPC) özellikler ile gelen Android Güvenlik Çatisi ( Framework )
    c) Hafiza yönetim hatalarini düzeltmek için var olan ASLR,OpenBSD dlmalloc,NX,Propolice gibi programlar
    d) Cihazin çalinmasi halinde bilgi kaybini engelleyecek olan sifrelenmis dosya sistemi
    e) Sistem özellikleri ve kullanici bilgisine erisimi denetleyen izin sistemi
    f) Uygulama özelinde erisim izinleri
    
Bunlara ek olarak asagida yer alan adimlarin izlenmesi güvenli bir Android isletim sistemi olusturulmasina olanak saglayacaktir:

**1) Bilgiyi Saklama ( Storing Data )**

Bir Android uygulamasi için en önemli güvenlik konusu diger uygulamalar tarafindan ulasilabilir olup / olmadigidir.
Android'de uygulama bilgisinin güvenli bir sekilde saklanmasinin 3 yolu vardir:

**a) Internal Storage ( Cihaz içi Depolama ):**

Varsayilan olarak internal storage'da yaratilan dosyalar sadece bizim uygulamamiza açiktir ve bu özellik birçok uygulamanin güvenligi için yeterlidir.
Fakat **IPC** ( prossesler arasi iletisim ) dosyalari için MODE_WORLD_WRITEABLE kullanmamak faydalidir çünkü bu modlar spesifik uygulamalara bilgi akisini denetleme ve bilgi formatini düzenleme
konusunda yetersizdir.Eger farkli uygulamalarin farkli prosesleri ile bilgi paylasimina ihtiyaç var ise Content Provider kullanilabilir.Bu alan duruma göre izinler yaratabilmektedir.
Hassas bilginin korunmasi için dosyalarin bir anahtar ile sifrelenmesi yöntemi de kullanilabilir.Anahtar **Keystore**'da saklanir ve bir sifre ile korunur.

**b) External Storage ( Cihaz disi Depolama ):**

Harddiskler gibi dis bir depolama alaninda yaratilan dosyalar okunabilir ve degistirilebilir.
Hassas bilgilerin USB,SD Card gibi depolama alaninda saklanmamasi tavsiye edilir.
Eger güvenilir olmayan bir kaynaktan bilgi akisi gerçeklesecek ise **Input Validation** isleminin gerçeklestirilmesi gerekmektedir.
Ayni zamanda executables almak durumunda kalacak ise kriptolama isleminin yapilmis olmasi gerekmektedir.

 **c) Content Provider Kullanimi:**

Content Provider uygulamalar arasi denetimli erisilebilirlik saglamak için yapilandirilmis bir depolama alanidir.
Eger diger uygulamalarin Content Provider'a erisimin istemiyorsak uygulama manifest'inde android:exported=false olarak isaretlenir, aksi durumda true olarak isaretlenir.
Content Provider olustururken uygulamalar için okuma ve yazma seviyesinde yetkiler, veya daha kati yetkiler tanimlanabilir.
Eger sadece kendi uygulamalarimiz için Content Provider olusturuyorsak **'android:protectionLevel''in 'signature'** olarak isaretlenmesi faydalidir. Bu attribute kullanici dogrulamasi gerektirmez
ve kullanici kolayligi saglar.
Ayni zamanda Content Provider'a ulasirken **query()**,**update()** ve **delete()** gibi sorgulama metodlari SQL Injection'in önlenmesi için etkilidir.

**2) Erisim Izinleri ve Sinirlamalar:**

Android uygulamalari sandbox yöntemi ile birbirinden izole eder fakat uygulamalarin aralarinda bilgi paylasimi veya bir kaynaga erisim ihtiyaci ( örnegin kamera ) bulunabilir.
Bu gibi durumlarda Basic Sandboxing yeterli degildiri ve izinler tanimlanmalidir.

**a) Izin Isteme:**

Android uygulamalarina mümkün olan en az izin verilmelidir.Uygulamalarin hassas bilgilere erisememesi izinlerin kötü amaçli kullanimini azaltir, kullanici kolayligi saglar ve saldirganlar için
mevcut olan zaafiyetleri azaltir.

Uygulamalarin cihaz bilgisine erisimi için tekil bir kimlik tanimlamak yerine, GUID kullanmak daha mantiklidir. Benzer bir önlem de disaridaki bir depolama alani yerine iç bir depolama alani
kullanmaktir.

Uygulamalarin bilgilere erisim için kullandiklari izin isteme yöntemine ek olarak, IPC'yi ( Prosesler arasi iletisim ) korumak için **<permissions>** kullanilabilir.
Uygulamalar arasi iletisim için izin sistemi kullanimina ek olarak, erisim kontrolleri de kullanilmalidir. Örnegin, signature-level protection IPC güvenligi için etkilidir.

**b) Izin Yaratma:**

Eger bir uygulama için yeni bir izin yaratilmasi gerekiyorsa, signature-protection-level kullanilabilir.
Imza izinleri kullaniciya transparanttir ve ayni developer tarafindan imzalanmis uygulamalarin, erisim kontrolü yapilarak iletisimine ve aralarindaki bilgi kullanimina izin verir.

**3) Network ( Ag ) Kullanimi:**

Ag içerisinde kisisel bilgilerin iletimi kullanici açisindan da risk teskil etmektedir.
Uygulamalar da kullanicinin hassas bilgilerinin korunmasi için gerekli güvenlik önlemlerini almalidir.

**a) IP Network Kullanimi:**

Android ag kullanimi diger Linux ortamlarindan farkli degildir.Temel mantik hassas bilgilerin güvenlik açisindan uygun protokoller ile tasinmasidir. Örnegin **HttpsURLConnection** güvenli web trafigi
içindir. HTTPS over HTTP tercih edilmelidir (karsi taraftaki sunucu da desteklemeli) çünkü Andoid tabanli cihazlar kolaylikla güvenli olmayan aglara ( Wifi ) baglanabilmektedir.

Android'de dogrulama ve kriptolamanin basari ile saglanabilecegi ''SSLSocket'' class'i kullanilabilir.

Bazi uygumalarin localhost network portlarini kullandigi tespit edilmistir ve bu güvenlik zaafiyetidir.Çünkü bu port ve localhost IP'ler IPC esnasinda diger uygulamalar tarafindan da erisilebilir durumdadir.
Bunun yerine dogrulamanin bir **''Service''** ile mümkün oldugu Android IPC mekanizmalari kullanilmalidir.

Bir diger önemli nokta da Android cihaz/uygulamanin indirilen HTTP trafigine güvenmemesidir. Bu da **input validation** ( bilgi giris denetemi ) ve **WebView** ile saglanir.

**b) Telefon Network'ü Kullanimi:**

SMS kullanicilar arasi bire-bir iletisimi saglamak için kullanilan ve güvensiz bir iletisim yöntemidir.
SMS'in kisitlamalari sebebi ile Google Cloud Messaging ( GCM ) ve IP Network kullanimi, sunucudan telefon uygulamalarina veri akisi esnasinda tercih edilmelidir.

SMS'in güvenli ve kriptolu olmamasi çesitli spoofing ve man-in-the-middle ( aradaki adam ) saldirilarina firsat verebilmekte ve uygulamalara zararli yazilimlar bulasabilmektedir.
Android cihazlarda, içeride SMS'ler broadcast olarak yayinlanmakta ve **''READ_SMS''** izni ile diger uygulamalar SMS'leri yakalayip,okuyabilmektedir.
 
**4) Giren Bilginin Dogrulanmasi ( Performing Input Validation ):**

Input ( gelen bilgi ) dogrulamasinin yetersizligi uygulamalarin karsi karsiya kaldigi en önemli güvenlik problemlerinden biridir.
Android uygulamalarin input validation ( bilgi dogrulama ) yetersizligi sebebi ile karsi karsiya kalacagi problemleri minimize etmek için platform düzeyinde önlemlere sahiptir.
Platform düzeyindeki önlemlere ragmen native code ( dogal kod ) kullaniliyorsa; dosyalardan okunan,network üzerinden alinan veya IPC sebebi ile elde edilen bilgilerin güvenlik problemlerine
sebebiyet verme durumu mevcuttur.En yaygin problemler buffer-overflows,use after free ve off-by-one errors'dir.
Android bu tür hatalarin kötü niyetli kullanimini önlemek için **ASLR ( Address Space Layout Randomization )** ve **DEP ( Data Execution Prevention )** gibi önlemlere sahiptir ve bunlar problemin
çözümünde yetersiz olmaktadir.Bu zaafiyetleri kapatmak için pointerlar iyi kullanilmali, bufferlar düzgün yönetilmelidir.
Javascript ve SQL gibi string tabanli diller de script injection ( script yerlestirme ) vb. problemler sebebi ile giren bilgi dogrulama sorunu ile karsi karsiya kalabilmektedir.
Yukaridaki önlemlere ek olarak SQL Database ve Content Provider kullanimnda, SQL Injection'i önlemek istiyorsak parameterized queries ( parametre sorgulamalari, **query(),delete()** vb. ) 
kullanmak bir çözümdür.
Son olarak iyi yapilandirilmis bir bilgi formati kullanilmasi,karakter karalistesinin olusturulup;degisikliginin önlenmesi de etkili bir güvenlik stratejisi olur.

**5) Kullanici Bilgisinin Güvenligi:**

Kullanici bilgi güvenligi için alinabilecek en önemli önlem, hassas ve kisisel bilgilere ulasimin kisitlanmasi amaci ile API(Application Programming Interface) kullanimini minimize etmektir.
Buna ek olarak, eger bilginin bütünlügünü korumamizi saglayacak bir hash mekanizmasi var ise, uygulamanin bu algoritmasini kullanmak etkili bir yöntemdir.Örnegin uygulamamiz bir e-mailin hash
( bütünlük ) degerini primary key ( birinci anahtar ) olarak tutup, okunmasini ve depolanmasini engelleyebilir.Bu önlem hem datanin okunmasini, hem de uygulamanin hacklenmesini önleyebilir.
Kisisel hassas bilgilerin ( kullanici adi/sifre,kimlik numarasi vb. ) third-party uygulamalar tarafindan istenmesi halinde bilgilerin verilmemesi basit ama etkili bir güvenlik önlemidir.
Eger kullanicidan bu bilgiler isteniyorsa, bilgilerin bir sunucuya aktarilip aktarilmadigi denetlenmeli, bir kod çalistiriliyorsa client üzerinde çalistirilip/çalistirilmadigina bakilmaldir.
Eger bir GUID isteniyorsa telefon numarasi gibi kisisel bilgiler ile iliskilendirilmeyen sekilde yaratilmasi faydali olacaktir.
Son olarak, cihaz loglamasi düzgün bir sekilde yapilmalidir. Telefon logu geçici ve cihazin yeniden baslatilmasi sonucu silinebilir olsa da; yanlis bir kullanici bilgisi loglamasi baska 
uygulamalar tarafindan kullanilabilir.

**6) WebView Kullanimi:**

WebView'in HTML ve Javascript içeren web kaynaklarini önemli ölçüde tükettigi için düzgün olmayan kullanimi Cross-Site-Scripting gibi çesitli web ataklarina sebebiyet verebilir.
Android WebView'in yetkilerini ve kullanim alanini kisitlayarak bazi atak çesitlerini önlese de kisisel olarak alinabilecek bazi önlemler de mevcuttur.

Eger uygulama **WebView** ile hassas bilgilere erisim sagliyorsa **clearCache()** metodu ile lokal olarak depolanmis dosyalar silinebilir.Sunucu tarafli no-cache gibi basliklar uygulamanin özel bir
içerigi saklamamasini saglayabilir.

Android 4.4 ( API Level 19 ) öncesi versiyonlar bazi güvenlik problemlerine sebep olan webkit versiyonlari kullanmaktadirlar. Uygulamalar bu cihazlar içerisinde kosuyorsa,yalnizca güvenilir
içerigi gösterdiginden emin olunmalidir.Ayrica çesitli SSL zaafiyetlerinin kullanilmasini engellemek için güncellenebilir güvenlik **''provider''**objesi de kullanilabilir.

**7) Kullanici Dogrulama Bilgileri'nin Korunmasi:**

Kullanici dogrulamasi yapilirken saglanan bilgilerin uygulamalar tarafindan sik sik sorulmasini engellemek muhtemel oltalama saldirilarinin önüne geçmektir.
Bu amaçla bir dogrulama token'i kullanilip,belirli periyotlar ile yenilenmesi saglanir.

Uygulamalarin dogrulama için kullanici adi/sifreyi bir kez almasi, depolamamasi ve bunun yerine kisa süreli, servise özel dogrulama belirteçi ( token ) kullanilmasi güvenlik açisindan etkilidir.
Birçok uygulama tarafindan ulasilabilir olan servislerin **''AccountManager''** ile erisimi saglanmalidir. Bu erisim bulut tabanli olursa cihaz üzerinde sifre depolanmasi engellenmis olur.

Kimlik dogrulama bilgilerinin dogru uygulamaya gitmesinin garanti edilmesi de önemli bir güvenlik adimidir.
Eger bilgiler sadece bizim yarattigimiz uygulamalar tarafindan kullanilacak ise **''checkSignature()''** ile dogrulama yapmak etkilidir.
Eger bir uygulama dogrulama bilgilerini kullanacak ise depolama için **''Keystore''** kullanimi güvenlik açisindan etkilidir.

**8) Kriptografi Kullanimi:**

Bilgi izolasyonuna ek olarak, dosya sistemi kriptolamasi, güvenilir iletisim kanallari gibi kriptografik islemlere dayali önlemler de Android'in sagladigi güvenlik çözümleri arasindadir.
Öncelikle Android'in sundugu olanaklar çerçevesinde, bir dosyayi güvenli bir sekilde bir yerden baska bir yere tasimak için basit bir HTTPS URI, ya da güvenli bir tünel için **''HttpsURLConnection''** veya 
**''SSLSocket''** kullanilabilir.

**''SecureRandom''** ( rastgele numara üretimi ) ve **''KeyGenerator''** ( kriptografik islemlerin baslamasi için anahtar üretimi ) kullanilmalidir. Random olarak üretilmeyen anahtarlar nedeni ile
off-line saldirilara maruz kalinma olasiligi yüksektir.

Eger bir anahtar düzenli olarak kullanilacak ise depolanmasi amaci ile **''Keystore''** kullanilmalidir.

**9) Dinamik Olarak Kod Yükleme:**

Uygulamanin APK'yi hariç,disaridan bir kod yükleme çok nadir kosullarda yapilmasi gereken bir eylemdir.
**Code Injection** ve **Code Tampering** saldirilari ile uygulamanin ele geçirilmesi muhtemeldir.
Ayni zamanda versiyon yönetimi ve uygulamanin çalisilabilirligi açisindan da son derece tehlikeli bir durumdur.
Buradaki en büyük güvenlik riski kodun güvenilir olmayan bir kaynaktan gelmesidir.Örnegin kriptolu olmayan bir protokol ile network üzerinden veya dis bir depolama alanindan.
Dinamik olarak kod yükleme yapilmadan uygulamanin gelistirilmesi daha güvenlidir.

**10) Virtual Machine ( Dalvik Sanal Makina ) Güvenligi:**

Dalvik Android'in Sanal Makina sistemidir.
Bazi sanal makinalar, JVM veya .net , isletim sistemi ile kod arasinda bir güvenlik bariyeri olarak islem görürler.
Android'de ise Dalvik bu sekilde bir güvenlik bariyeri olarak islem yapmaz.
Mobil cihazlardaki depo alan kisitina bagli olarak, kod gelistiriciler moduler uygulamalar gelistirmeyi ve dinamik class yüklemesini tercih ederler.
Bu sartlar altinda, dinamik classlarin nereden alindigi ve nerede depolandigi önem arz etmektedir. Aksi takdirde zararli bir aktiviteye neden olunabilir.
