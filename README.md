# 📄 BİLGİSAYAR AĞ GÜVENLİĞİ: BASİT IDS PROJESİ RAPORU

**Öğrenci Adı:** Memet Orakci
**Öğrenci No:** 224300700224 
**Ders:** Bilgisayar Ağ Güvenliği  
**Proje:** Python ve Scapy Tabanlı Anomali Tespit Sistemi (IDS)

---

## 1. PROJENİN AMACI
Bu projenin temel amacı, yerel bir bilgisayarın ağ bağdaştırıcısına gelen ağ paketlerini canlı olarak dinleyip analiz eden ve belirlenen kurallar çerçevesinde anomali (DoS ve Port Tarama) tespiti yapabilen kural tabanlı bir yazılım (IDS) geliştirmektir.

## 2. KULLANILAN TEKNOLOJİLER VE LİTERATÜR
* **Python 3:** Projenin temel programlama dili.
* **Scapy Kütüphanesi:** Ağ üzerinde akan L2/L3 paketlerini koklamak (sniffing), çözümlemek ve yönlendirmek için kullanıldı.
* **Tkinter:** Sistemin canlı izlenebilmesi amacıyla kullanıcı dostu bir Grafiksel Kullanıcı Arayüzü (GUI) oluşturmak için tercih edildi.
* **Threading (Çok İş Parçacıklı Çalışma):** Ağ paketlerini dinleme fonksiyonunun sistemi ve arayüzü kilitlememesi adına, analiz süreci arka plana (Thread) alınarak asenkron hale getirilmiştir.

## 3. TESPİT MEKANİZMASI VE KURALLAR
Projede ağ güvenliğinin en yaygın sorunları baz alınarak iki ana saldırı imzası (signature) tanımlanmıştır:

### A. Yoğun Trafik / DoS (Denial of Service) Tespiti
* **Kural:** Tek bir IP adresi `5 saniye` içerisinde hedefe `20'den fazla` paket gönderirse, sistem bu durumu olağandışı bir hizmeti aksatma (DoS) girişimi olarak algılar.
* **False Positive (Yanlış Pozitif) Analizi:** Sistem test edilirken YouTube vb. çoklu CDN mimarisi kullanan sistemlere girildiğinde IDS uyarı vermiştir. Gerçek dünyada bu tür platformlar tek seferde çok hızlı paket gönderdiği için basit kural tabanlı IDS'lerde "Yanlış Alarm" (False Positive) oluşturması beklenen ve sistemin iyi çalıştığını (paket kaçırmadığını) gösteren teknik bir durumdur. Kurumsal Güvenlik Duvarları kalibrasyon için Güvenli Liste (Whitelist) metotlarını kullanmaktadır.

### B. Port Tarama (Port Scanning) Tespiti
* **Kural:** Tek bir IP adresi, sistemin `5 veya daha fazla farklı portuna` temas kurmaya çalışırsa "Port Tarama / Keşif" şüphesiyle sisteme kırmızı alarm verilir. Siber saldırganların Nmap tarzı araçlarla zafiyet arama eylemlerini tespit etmeye yarar.

## 4. GÜVENLİ TEST ORTAMI VE SİMÜLASYON (DEMO) VERİLERİ
Okul veya kurumsal bir ağ üzerinde, diğer cihazları etkileyecek gerçek bir Yıkıcı DoS Saldırısı veya Port Tarama eylemi gerçekleştirmek tehlikeli/yasak olacağından, projeye izole bir **"Simülasyon Modülü"** entegre edilmiştir. 

**Simülasyondaki Verilerin İşlevi:**
Sistem arka planda rastgele sayılarla taklit bir ağ ortamı yaratır:
- `192.168.1.10`, `10.0.0.5` gibi **Normal IP'ler**: Ağdaki standart cihazları temsil ederler, HTTP (Port 80) vb. sıradan istekler atarlar ve sistem bu trafiğe alarm vermez.
- `192.168.1.99` IP'li **DoS Saldırganı Taklidi**: Sisteme kasıtlı olarak tek bir saniyede 25 sahte paket salgılar. Bu sayede yazılım limitimiz olan _"5 saniyede 20 paketi aşanları uyar"_ kuralının tespit mekanizmasının (DoS analizinin) doğru çalıştığı fiziki bir saldırı yaratılmadan kanıtlanır.
- `10.0.0.66` IP'li **Siber Tarayıcı (Scanner) Taklidi**: Yine tehlike arz etmeden (21, 22, 23.. vb.) sahte portlara peş peşe istek iletir. Sonucunda IDS'in "farklı portları sayan algoritmasının" da başarıyla tetiklendiği gözlemlenir.

Bu demo verilerinin temel amacı; fiziksel ağ cihazlarını riske atmadan kural analiz motorunun tam tutarlılıkla (sandbox mantığında) çalıştığını akademik olarak ve güvenle sunabilmektir.

## 5. SONUÇ
Geliştirilen bu yazılım, ağ paketlerini başarıyla analiz edebilmiş ve eşik değerleri doğrulutusunda saldırıları -gerçek ve simülasyon ortamlarında- anında tespit edip kullanıcıyı arayüz üzerinden uyarmıştır. Yazılıma dahil edilen simülasyon modülü sayesinde projenin başarılı olduğu risk almadan kanıtlanmıştır.
