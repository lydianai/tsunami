# BEYAZ ŞAPKA KURALLARI - TSUNAMI Siber Gözetleme Merkezi

## 📜 Version 1.0
**Tarih**: 20 Şubat 2026
**Durum**: Yürürlükte
**Sahiplik**: TSUNAMI Güvenlik Konseyi

---

## 1. GENEL PRENSİPLER

### 1.1 Beyaz Şapka Felsefesi
TSUNAMI platformu **sadece etik, yasal ve yetkili** siber güvenlik faaliyetleri için tasarlanmıştır. Tüm operasyonlar aşağıdaki temel prensiplere uygun yürütülmelidir:

#### Temel İlkeler
1. **Yasallık (Legality)**: Tüm faaliyetler Türk yasalarına ve uluslararası anlaşmalara uygun olmalıdır
2. **Gerekli (Necessity)**: Gözetleme sadece gerekli olduğunda ve orantılı ölçüde uygulanmalıdır
3. **Şeffaflık (Transparency)**: İlgili taraflar gözetleme hakkında bilgilendirilmelidir (yasal istisnalar hariç)
4. **Gizlilik (Privacy)**: Kişisel veriler KVKK ve ilgili yasalara uygun korunmalıdır
5. **Sorumluluk (Accountability)**: Tüm operasyonlardan sorumlu personel belirlenmelidir
6. **Denetlenebilirlik (Auditability)**: Tüm faaliyetler tam kayıt altına alınmalıdır

### 1.2 Kapsam
Bu kurallar TSUNAMI platformunun tüm kullanım alanlarını kapsar:
- WiFi sinyal istihbaratı
- Bluetooth cihaz tespiti
- Baz istasyonu haritalama
- IoT cihaz keşfi
- Ağ zafiyet taraması
- Paket yakalama ve analiz
- Video gözetleme
- OSINT istihbarat toplama

### 1.3 Hedef Kitle
Bu kurallar aşağıdaki personel için geçerlidir:
- Sistem yöneticileri
- Güvenlik analistleri
- Operatörler
- Denetçiler
- Yetkili kullanıcılar

---

## 2. YETKİLENDİRME VE SORUMLULUK

### 2.1 Yetki Seviyeleri

#### Seviye 1: Viewer (Görüntüleyici)
**Tanım**: Sadece görüntüleme yetkisi, veri ihraç etmez
**Yetkiler**:
- Veri görüntüleme
- Rapor okuma
- Dashboard görüntüleme
- Filtreleme ve arama

**Kısıtlamalar**:
- ❌ Veri dışa aktarma
- ❌ Rapor oluşturma
- ❌ Sistem yapılandırması
- ❌ Kullanıcı yönetimi

#### Seviye 2: Analyst (Analist)
**Tanım**: Analiz ve raporlama yetkisi, sınırlı ihracat
**Yetkiler**:
- Tüm Viewer yetkileri
- Rapor oluşturma
- Sınırlı veri ihracatı (max 100 kayıt)
- Analiz araçları kullanımı
- Not ekleme

**Kısıtlamalar**:
- ❌ Geniş ölçekli veri ihracatı
- ❌ Sistem yapılandırması
- ❌ Kullanıcı yönetimi
- ❌ Hassas verilere erişim

#### Seviye 3: Operator (Operatör)
**Tanım**: Tam operasyon yetkisi, onay gerektirir
**Yetkiler**:
- Tüm Analyst yetkileri
- Sınırsız veri ihracatı (onaylı)
- Aktif tarama operasyonları
- Sistem yapılandırma değişiklikleri (onaylı)
- Acil durum müdahalesi

**Kısıtlamalar**:
- ⚠️ Onay gerekli: Hassas operasyonlar
- ⚠️ Onay gerekli: Kritik sistem değişiklikleri
- ❌ Kullanıcı yönetimi
- ❌ Denetim logları silme

#### Seviye 4: Admin (Yönetici)
**Tanım**: Tüm yetkiler
**Yetkiler**:
- Tüm operasyonel yetkiler
- Kullanıcı yönetimi
- Rol atama
- Sistem yapılandırması
- Politika değişiklikleri

**Sorumluluklar**:
- Tüm faaliyetlerden sorumlu
- Denetim loglarını incelemek
- Yasal uyumu sağlamak
- Olayları raporlamak

#### Seviye 5: Auditor (Denetçi)
**Tanım**: Tam denetim erişimi
**Yetkiler**:
- Tüm loglara erişim
- Tüm raporları görüntüleme
- Kullanıcı aktivitesi izleme
- Uyumluluk raporlama
- İhlal tespiti

**Sorumluluklar**:
- Bağımsız denetim
- Uyumluluk değerlendirmesi
- İhlal raporlama
- Öneri geliştirme

### 2.2 Yetkilendirme Süreci

#### Adım 1: Başvuru
1. Aday kullanıcı **Yetkilendirme Formu** doldurur
2. Form şu bilgileri içerir:
   - Ad, soyad, TC kimlik no
   - Görev unvanı ve departman
   - İstenen yetki seviyesi
   - Gerekçe ve kullanım amacı
   - Süre (maksimum 1 yıl)

#### Adım 2: İnceleme
1. Yönetici başvuruyu inceler
2. Adayın güvenlik geçmişi kontrol edilir
3. Gerekçe uygunluğu değerlendirilir
4. En az 2 yönetici onayı gerekir

#### Adım 3: Onay
1. Onay verilen kullanıcıya e-posta gönderilir
2. Kullanıcı kabul beyanını imzalar
3. Eğitim tamamlanır (zorunlu)
4. Test sınavı geçilir (min %80)

#### Adım 4: Aktif Etme
1. Sistem yöneticisi hesabı oluşturur
2. İlk şifre güvenli şekilde iletilir
3. İlk girişte şifre değiştirme zorunludur
4. Aktivasyon loglanır

### 2.3 Sorumluluk Dağılımı

#### Kullanıcı Sorumlulukları
- Şifre güvenliğinden sorumlu
- Hesap paylaşımı yasaktır
- Yetkilerini aşmamak
- İhlal bildirmek
- Eğitimlere katılmak
- Kurallara uymak

#### Yönetici Sorumlulukları
- Kullanıcı yetkilendirme
- Düzenli denetim
- İhlal araştırması
- Raporlama
- Eğitim sağlama

#### Denetçi Sorumlulukları
- Bağımsız denetim
- Uyumluluk kontrolü
- İhlal tespiti
- Rapor hazırlama
- İyileştirme önerileri

---

## 3. VERİ KORUMA KURALLARI

### 3.1 KVKK Uyumu (6698 Sayılı Kanun)

#### Veri İşleme Şartları (Madde 5)
TSUNAMI'da veri işleme aşağıdaki şartlara dayanır:

1. **Açık Rıza**: Veri sahibi açık rıza vermişse
2. **Kanuni Yükümlülük**: Kanunlarda açıkça öngörülmüşse
3. **Sözleşme**: Sözleşmenin kurulması veya ifası gerekliyse
4. **Hukuki Yükümlülük**: Veri işlemenin hukuki yükümlülüğü yerine getirmek için gerekliyse
5. **Haklar**: Temel hak ve özgürlükleri korumak için gerekliyse
6. **Meşru Menfaat**: Veri sorumlusunun meşru menfaati için gerekliyse

#### Özellikle Zararlı Veriler (Madde 6)
Aşağıdaki veriler için **open rıza şarttır**:
- Irk, etnik köken, siyasi görüş
- Felsefi inanç, din, mezhep
- Kılık ve kıyafet
- Dernek, sendika üyeliği
- Sağlık verileri
- Cinsel hayat
- Ceza mahkumiyeti ve güvenlik tedbirleri

### 3.2 Veri Saklama Süreleri

#### Genel Kural
| Veri Türü | Saklama Süresi | Rationale |
|-----------|----------------|-----------|
| **Kritik güvenlik olayları** | 5 yıl | Yasal dava süresi |
| **Normal güvenlik olayları** | 2 yıl | Tipik denetim dönemi |
| **Erişim logları** | 1 yıl | GDPR/KVKK gereği |
| **Oturum verileri** | 90 gün | Operasyonel ihtiyaç |
| **Geçici analiz verileri** | 30 gün | Performans yönetimi |
| **Video kayıtları** | 90 gün | Standart güvenlik |
| **Paket capture** | 7 gün | Depolama sınırları |
| **Raw sinyal verileri** | 24 saat | Anlık işleme |

#### Özel Durumlar
- **Adli kovuşturma**: İlgili veri kovuşturma sonuna kadar saklanır
- **Veri ihlali**: İhlal tespitinden itibaren 5 yıl
- **Denetim**: Denetim tamamlanana kadar (min 1 yıl)

### 3.3 Veri İmha Prosedürü

#### İmha Nedenleri
1. Saklama süresi dolması
2. Rıza geri çekilmesi
3. İlgili kişinin talebi (Madde 11)
4. Amaç ortadan kalkması
5. Yasal zorunluluk

#### İmha Yöntemleri
1. **Silme**: Veriye erişimi tamamen engelleme
2. **Yok etme**: Veriyi geri döndürülemez şekilde kaldırma
3. **Anonimleştirme**: Veriyle ilişkilendirmeyi imkansız hale getirme

#### İmha Süreci
```
1. İmha talebi → İnceleme → Onay → İmha → Loglama
   ↓
2. İmha logu: Kim, ne, ne zaman, neden sildi
   ↓
3. Denetçi onayı: İmha doğrulandı
   ↓
4. Raporlama: İmha istatistikleri
```

### 3.4 Veri Güvenliği Önlemleri

#### Teknik Önlemler
- ✅ Şifreleme (TLS 1.3, AES-256)
- ✅ Erişim kontrolü (RBAC)
- ✅ Loglama ve izleme
- ✅ Güvenli yedekleme
- ✅ Güvenlik güncellemeleri
- ✅ Saldırı tespiti (IDS/IPS)

#### İdari Önlemler
- ✅ Personel eğitimi
- ✅ Gizlilik sözleşmeleri
- ✅ Yetki sınırlandırması
- ✅ Düzenli denetim
- ✅ Acil durum planları
- ✅ İhlal bildirim prosedürleri

### 3.5 Veri İhracı Kuralları

#### Genel İhracat Kısıtlamaları
- ❌ Kişisel veriler yurt dışına çıkarılamaz (yeterli koruma yoksa)
- ❌ Hassas veriler yetkisiz ihraç edilemez
- ⚠️ Toplu veri ihracatı onay gerektirir

#### İhracat Onay Süreci
1. **Talep**: Kullanıcı ihracat talep eder
2. **İnceleme**: Yönetici talebi değerlendirir
3. **Risk Analizi**: Veri türüne göre risk seviyesi belirlenir
4. **Onay**: Risk seviyesine göre yetkili onaylar
5. **Loglama**: İhracat detaylı loglanır
6. **Takip**: İhraç edilen verinin kullanımı izlenir

#### Risk Seviyeleri
| Seviye | Veri Türü | Onay | Saklama |
|--------|-----------|------|---------|
| **Düşük** | Anonimleştirilmiş istatistik | Yönetici | 1 yıl |
| **Orta** | Kişisel veri (anonim) | 2 Yönetici | 2 yıl |
| **Yüksek** | Kişisel veri (tanımlanabilir) | Yönetici + Hukuk | 3 yıl |
| **Kritik** | Özellikle zararlı veri | Yönetici Kurulu | 5 yıl |

---

## 4. OPERASYON SINIRLARI

### 4.1 İzin Verilen Operasyonlar

#### ✅ Açıkça İzin Verilen
1. **Kendi ağınızdaki cihazları tarama**
2. **Yetkili olduğunuz sistemleri izleme**
3. **Yazılı izni olan taramalar**
4. **Eğitim amaçlı laboratuvar testleri**
5. **Acil durum müdahaleleri (dokümante edilmiş)**
6. **Hukuki prosedüre dayalı operasyonlar**
7. **Sözleşme kapsamındaki hizmetler**

#### ⚠️ Koşullu İzin
1. **Kamusal alan WiFi taraması** (sadece istatistik, veri saklama yok)
2. **Açık kaynak istihbarat (OSINT)** (yasal sınırlar içinde)
3. **Baz istasyonu haritalama** (OpenCellID gibi açık kaynaklar)
4. **IoT cihaz keşfi** (Shodan gibi meşmu kaynaklar)

### 4.2 Yasaklanan Operasyonlar

#### ❌ Kesinlikle Yasak
1. **Yetkisiz ağlara saldırmak**
2. **İzinsiz paket yakalama**
3. **Şifre kırma (brute force)**
4. **Man-in-the-middle saldırıları**
5. **Sosyal mühendislik**
6. **Veri ihlali veya hırsızlığı**
7. **Ransomware veya malware dağıtımı**
8. **DDoS saldırıları**
9. **Fiziksel cihaza müdahale**
10. **Yasa dışı izleme**

#### ⚠️ Özel İzin Gerektiren
1. **Yüksek riskli taramalar** (üretim sistemleri)
2. **Kritik altyapı testleri**
3. **Büyük ölçekli veri toplama**
4. **Uzun süreli izleme**
5. **Çoklu kaynak veri füzyonu**

### 4.3 Operasyon Öncesi Kontrol Listesi

#### ✓ İşlem Başlamadan Önce
- [ ] Yetki seviyesi kontrol edildi
- [ ] Operasyon kapsamı belirlendi
- [ ] Hedef sistem belirlendi
- [ ] Risk analizi yapıldı
- [ ] Yasal dayanak belirlendi
- [ ] Gerekli izinler alındı
- [ ] Paydaşlar bilgilendirildi
- [ ] Loglama aktif edildi
- [ ] Acil durum planı hazırlandı
- [ ] Operasyon planı onaylandı

#### ✓ Operasyon Sırasında
- [ ] Gerçek zamanlı izleme aktif
- [ ] Anomali tespiti açık
- [ ] Limitler takip ediliyor
- [ ] Loglar düzenli kontrol ediliyor
- [ ] Yasal sınırlar ihlal edilmiyor
- [ ] Veri güvenliği sağlanıyor

#### ✓ Operasyon Sonrası
- [ ] Tüm veriler güvende
- [ ] Loglar arşivlendi
- [ ] Rapor hazırlandı
- [ ] İlgili taraflar bilgilendirildi
- [ ] Gereksiz veriler imha edildi
- [ ] Denetim kayıtları tamamlandı
- [ ] Ders çıkarıldı ve belgelendi

### 4.4 Operasyon Limitleri

#### Zaman Sınırları
| Operasyon Türü | Maksimum Süre | Uzatma |
|----------------|---------------|---------|
| **Aktif tarama** | 4 saat | +2 saat (onaylı) |
| **Pasif izleme** | 24 saat | +24 saat (onaylı) |
| **Paket capture** | 1 saat | +30 dk (onaylı) |
| **Video kayıt** | 8 saat | +8 saat (onaylı) |
| **Uzun dönem izleme** | 30 gün | Yönetim kurulu kararı |

#### Kayıt Sınırları
| Veri Türü | Maksimum Kayıt | Temizleme |
|-----------|----------------|-----------|
| **Paket capture** | 10 GB/oturum | 7 gün |
| **Video kayıt** | 100 GB/gün | 90 gün |
| **Log verileri** | 1 GB/gün | 1 yıl |
| **Raw sinyal** | 5 GB/oturum | 24 saat |

### 4.5 Acil Durum Protokolleri

#### Acil Durum Türleri
1. **Kritik güvenlik ihlali**
2. **Aktif saldırı tespiti**
3. **Sistem çökmesi**
4. **Veri ihlali**
5. **Yasal talep/arama**

#### Acil Müdahale Yetkisi
- **Operatör+**: Anlık müdahale yetkisi
- **Müdahale sonrası**: 24 saat içinde raporlama
- **Onay eksikliği**: Acil durum gerekçesi

#### Bildirim Zamanları
| Durum | İç Bildirim | Dış Bildirim | Resmi Kurum |
|-------|-------------|--------------|-------------|
| **Veri ihlali** | 1 saat | 24 saat | 72 saat |
| **Kritik saldırı** | 15 dk | 1 saat | 24 saat |
| **Sistem çökmesi** | 30 dk | - | - |
| **Yasal talep** | Anlık | - | Anlık |

---

## 5. RAPORLAMA YÜKÜMLÜLÜKLERİ

### 5.1 Düzenli Raporlar

#### Haftalık Rapor (Her Pazartesi)
**Kime**: Yönetim Kurulu
**İçerik**:
- Aktif operasyonlar
- Tespit edilen tehditler
- Kullanıcı aktiviteleri
- Sistem durumu
- Olaylar ve iyileştirmeler

#### Aylık Rapor (Her ayın 1'i)
**Kime**: Yönetim Kurulu + Denetçi
**İçerik**:
- Tüm operasyon özeti
- İhlal raporları
- Uyumluluk durumu
- Eğitim durumları
- Risk analizi
- Öneriler

#### Üç Aylık Rapor (Her çeyrek)
**Kime**: Yönetim Kurulu + Denetçi + İlgili Birimler
**İçerik**:
- Çeyrek performans
- Karşılaştırmalı analiz
- Trend analizi
- Yatırım gereksinimleri
- Stratejik öneriler

### 5.2 Olay Bazlı Raporlar

#### Güvenlik Olayı Raporu
**Zaman**: Olay tespitinden 4 saat içinde
**İçerik**:
- Olay tanımı
- Zaman çizelgesi
- Etki analizi
- Müdahale detayları
- Sonuç ve dersler

#### Veri İhlali Raporu
**Zaman**: Tespitinden 1 saat içinde
**İçerik**:
- İhlal türü
- Etkilenen veriler
- Etkilenen kişiler
- Nedenleri
- Alınan önlemler
- Önleyici tedbirler

#### Operasyon Tamamlama Raporu
**Zaman**: Operasyon bitiminden 24 saat içinde
**İçerik**:
- Operasyon özeti
- Hedefler vs sonuçlar
- Tespit edilen bulgular
- Kullanılan araçlar
- Sorunlar ve çözümler
- Öneriler

### 5.3 Yasal Raporlama

#### KVKK Bildirimleri (Madde 12)
**Veri İhlali Bildirimi**:
- Kuruma: 72 saat içinde
- İlgili kişilere: Gecikmeksizin
- İçerik:
  - İhlal niteliği
  - Etkilenen veri kategorisi
  - Olası sonuçları
  - Alınan/alınacak önlemler

#### Siber Olay Bildirimi (7469 Sayılı Kanun)
**Bildirim Zamanı**: 24 saat içinde
**Bildirim Yeri**: Ulusal Siber Olaylara Müdahale Merkezi (USOM)
**İçerik**:
- Olay türü
- Etki derecesi
- Kaynak ve hedef
- Müdahale bilgileri

#### Adli Yardım Talepleri
**Süreç**:
1. Resmi yazı ulaşır
2. Hukuk birimi inceler
3. Yetkili magistra onayı
4. Bilgi verilir
5. Tüm işlem loglanır

### 5.4 Denetim Raporları

#### İç Denetim
**Sıklık**: Yılda en az 2 kez
**Yürütür**: Baş denetçi
**Kapsam**:
- Tüm operasyonlar
- Log kayıtları
- Yetki yönetimi
- Veri güvenliği
- Uyumluluk durumu

#### Dış Denetim
**Sıklık**: Yılda en az 1 kez
**Yürütür**: Bağımsız denetim firması
**Kapsam**:
- Sistem güvenliği
- Veri koruma
- Yasal uyum
- Performans
- Risk yönetimi

### 5.5 Rapor Formatı

#### Standart Başlık
```
TSUNAMI GÜVENLİK RAPORU
Rapor Tipi: [Haftalık/Aylık/Olay]
Tarih: [GG/AA/YYYY]
Raporlayan: [Ad Soyad - Unvan]
Onaylayan: [Ad Soyad - Unvan]
Referans: [TSUNAMI-2026-XXX]
Gizlilik: [Özel/Gizli/Çok Gizli]
```

#### Standart İçerik Yapısı
1. **Yönetici Özeti**
2. **Olay Detayları**
3. **Analiz ve Bulgular**
4. **Etki Değerlendirmesi**
5. **Öneriler**
6. **Ekler**

---

## 6. YASAL UYUM (KVKK, Siber Güvenlik Yasası)

### 6.1 KVKK Uyumu (6698 Sayılı Kanun)

#### Veri Sorumlusu Sorumlulukları

**1. Aydınlatma Yükümlülüğü (Madde 10)**
Veri sorumlusu, ilgili kişileri şu konularda bilgilendirmelidir:
- Veri sorumlusunun kimliği
- Verilerin işleme amacı
- İşlenen verilerin kategorisi
- Alıcılar veya alıcı kategorileri
- Verilerin aktarılacağı ülkeler
- Veri toplama yöntemi
- Kişisel verilerin işlenmesinin hukuki sebebi
- Madde 11'de sayılan haklar

**2. Veri Güvenliği (Madde 12)**
Veri sorlusu:
- Verilerin hukuka aykırı işlenmesini önlemek
- Verilere hukuka aykırı erişimi önlemek
- Verilerin muhafazasını sağlamak
zorundadır.

**Alınan Önlemler**:
- Teknik önlemler: Şifreleme, erişim kontrolü, güncel yazılım
- İdari önlemler: Eğitim, yetki sınırlandırma, denetim

**3. Veri İhlali Bildirimi (Madde 12 - 2018 Eki Eki)**
Veri ihlali tespitinde:
- Kuruma bildirim: 72 saat içinde
- İlgili kişiye bildirim: Gecikmeksizin
- İhlal şiddetine göre farklı prosedürler

**4. İlgili Kişinin Hakları (Madde 11)**
Her ilgili kişi:
1. Kendi verisinin işlenip işlenmediğini öğrenme
2. İşlenmişse bilgi talep etme
3. İşleme amacını ve bunların amacına uygun kullanılıp kullanılmadığını öğrenme
4. Yurt içinde veya yurt dışında aktarılmasını bilme
5. Eksik/yanlış verilerin düzeltilmesini isteme
6. KVKK md. 7'de şartlar sağlanırsa silme/yok etme isteme
7. Md. 7'de şartlar sağlanırsa aktarılmasını isteme
8. Itiraz hakkı
9. Kanuna aykırı işleme sebebiyle zarara uğraması durumunda tazminat talep etme

### 6.2 7469 Sayılı Siber Güvenlik Yasası (2025)

#### Kritik Altyapı
**Tanım**: Ulusal güvenlik, ekonomik güvenlik, kamu sağlığı ve güvenliği için kritik olan sistemler.

**TSUNAMI Kapsamı**:
- Enerji iletim sistemleri
- Ulaştırma altyapısı
- Bankacılık ve finans
- Sağlık hizmetleri
- Telekomünikasyon
- Kamu hizmetleri

**Yükümlülükler**:
- Risk analizi (yıllık)
- Güvenlik değerlendirmesi (yıllık)
- USOM'a bildirim (24 saat)
- Olay müdahale planı
- Personel güvenliği
- Teknik güvenlik standartları

#### Siber Olay Bildirimi
**Zaman**: 24 saat içinde
**Yer**: USOM (Ulusal Siber Olaylara Müdahale Merkezi)
**İçerik**:
- Olay tanımı
- Etki derecesi
- Kaynak bilgisi
- Müdahale detayları
- Sonuçlar

### 6.3 5271 Sayılı Ceza Muhakemesi Kanunu

#### Adli Bilişim İnceleme
**Madde 134 - Arama, Elkoyma ve İnceleme**:
- Cumhuriyet savcısının kararı
- Kararda: Yer, zaman, kapsam belirtilir
- Bilgisayarlar, programlar, kayıtlar incelenebilir
- Kopya alma yetkisi

**Madde 135 - Koruma**:
- İncelenen veriler korunur
- Gereksizse iade edilir
- Gerekiyorsa elkoyma

**Sınırlar**:
- Haberleşmenin gizliliği (Anayasa md. 22)
- Özel hayatın gizliliği (Anayasa md. 20)
- Hak ihlali olmamalı

### 6.4 5651 Sayılı İnternet Ortamında Yapılan Yayınların Düzenlenmesi Hakkında Kanun

**Kapsam**: İnternet üzerinden yayın içerikleri

**TSUNAMI İçin Relevans**:
- İçerik tespiti ve kaldırma
- Erişim engelleme kararı
- Yer sağlayıcı yükümlülükleri
- Log tutma zorunluluğu (2 yıl)

**Sınırlar**:
- Yasadışı içerik tespit etme yetkisi yok
- Erişim engeli sadece hakim kararıyla

### 6.5 Diğer İlgili Mevzuat

#### Türk Ceza Kanunu (5237 Sayılı)
**İlgili Maddeler**:
- md. 243: Bilişim sistemine girme
- md. 244: Sistemi engelleme, bozma
- md. 245: Veri yok etme, değiştirme
- md. 246: Kartlı bilgi sistemleri
- md. 247: Kötüye kullanma
- md. 248: Cihaz veya program kullanma

#### Telekomünikasyon Yasası (5809 Sayılı)
**İlgili Maddeler**:
- Gizlilik ilkesi (md. 6)
- Trafik verisi koruma
- Konum verisi koruma
- Yetkisiz dinleme yasak

#### Anayasa
**İlgili Haklar**:
- md. 20: Özel hayatın gizliliği
- md. 21: Konut dokunulmazlığı
- md. 22: Haberleşme gizliliği
- md. 17: Kişisel dokunulmazlık

---

## 7. SORUMLULUK VE CEZALANDIRMA

### 7.1 İhlal Türleri

#### Kategori 1: Hafif İhlaller
**Tanım**: Bilgisizlik veya dikkatsizlikten kaynaklanan, sistemik olmayan ihlaller

**Örnekler**:
- Şifre paylaşımı
- Log tutmayı atlamak
- Eğitimlere katılmamak
- Küçük kapsam aşımı
- Raporlama gecikmesi (<24 saat)

**Cezalar**:
1. İlk: Yazılı uyarı
2. İkinci: Yetki düşürme (1 ay)
3. Üçüncü: Geçici uzaklaştırma (1 hafta)

#### Kategori 2: Orta İhlaller
**Tanım**: Kasıt veya ağır ihmal sonucu, potansiyel risk oluşturan ihlaller

**Örnekler**:
- Yetki aşımı (bilgili)
- Veri güvenliği ihlali
- İzinsiz veri ihracı
- Raporlama yapmamak (>7 gün)
- Log silme/değiştirme
- Yasal sınırları aşmak

**Cezalar**:
1. İlk: Yetki düşürme (3 ay)
2. İkinci: Geçici uzaklaştırma (1 ay)
3. Üçüncü: Kalıcı yetki iptali

#### Kategori 3: Ağır İhlaller
**Tanım**: Kasıtlı ve sistemik, ciddi sonuçları olan ihlaller

**Örnekler**:
- Veri hırsızlığı
- Yetkisiz sistem değişikliği
- İzinsiz paket yakalama
- Kritik altyapıya saldırı
- Yasa dışı izleme
- Raporsuz operasyon
- Gizlilik ihlali (kişisel veri)

**Cezalar**:
1. İlk: Kalıcı yetki iptali
2. Hukuki süreç: Savcılığa bildirim
3. Medeni tazminat: TSUNAMI'ya zarar
4. Ceza davası: TCK kapsamı

### 7.2 Disiplin Süreci

#### Adım 1: İhlal Tespiti
- Denetçi veya yönetici tespit eder
- İhlal loglanır
- Kanıt toplama başlar

#### Adım 2: İnceleme
- İlgili kişi yazılı olarak bilgilendirilir
- Savunma verme süresi: 7 gün
- İnceleme komisyonu kurulu
- Gerekirse hukuk danışmanlığı

#### Adım 3: Karar
- Komisyon kararı: 5 gün içinde
- Karar ilgili kişiye yazılı iletilir
- Karar nedeni açıklanır
- İtiraz hakkı: 14 gün

#### Adım 4: Uygulama
- Karar derhal uygulanır
- Yetkiler askıya alınır/iptal edilir
- Gerekli hukuki işlemler başlatılır
- Loglanır ve raporlanır

### 7.3 İtiraf ve İndirim

#### Kabul ve İşbirliği
**İndirim Oranı**: %25-50
**Koşullar**:
- İhlali kabul etmek
- İşbirliği yapmak
- Pişmanlık göstermek
- Telafiye çalışmak

#### Erken Bildirim
**İndirim Oranı**: %50
**Koşullar**:
- İhlali kendisi bildirmek
- Ciddiyetini azaltmak
- Kanıt sunmak
- Düzeltici eylemde bulunmak

### 7.4 Hukuki Sorumluluk

#### Medeni Sorumluluk
**Tazminat**: TSUNAMI'ya verilen zarar
**Hesaplama**:
- Doğrudan maddi zarar
- Dolaylı maddi zarar
- İtibar kaybı
- Yasal masraflar

#### Ceza Hukuku Sorumluluğu
**Kovuşturma**: Savcılığa bildirim
**Olası Suçlar**:
- Bilişim sistemine girme (TCK md. 243)
- Sistemi engelleme/bozma (TCK md. 244)
- Veri yok etme/değiştirme (TCK md. 245)
- Kişisel verileri hukuka aykırı ele geçirme (TCK md. 135-138)
- Özel hayatın gizliliğini ihlal (TCK md. 132)

### 7.5 İstisnai Durumlar

#### Acil Durum Müdahalesi
**Sınırlar**:
- Hayati tehlike
- Ciddi maddi zarar
- Kamu güvenliği
**İçin**: Protokol dışı hareket edilebilir
**Sonrası**: 24 saat içinde rapor gerekli

#### İyi Niyet
**Kabul**: Hata yaptı, ama iyi niyetli
**İndirim**: Uyarma veya düşük seviye ceza
**Koşul**: Telafi ve eğitim şart

#### Zorunluluk Halleri
**Tanım**: Kendini veya başkasını korumak
**Sınırlar**: Orantılılık ilkesi
**Sonrası**: Raporlama zorunlu

---

## 8. İZİN SÜRECİ VE LOGGING

### 8.1 Operasyon İzin Süreci

#### Normal İzin (1-7 gün)
**Kapsam**: Düşük-orta riskli operasyonlar
**Süreç**:
1. Kullanıcı form doldurur
2. Yönetici inceler (48 saat)
3. Onay/red karar bildirimi
4. Onaylanırsa operasyon başlar

**Form İçeriği**:
- Operasyon tanımı
- Hedef sistem
- Kapsam ve sınır
- Risk analizi
- Yasal dayanak
- Başlama ve bitiş tarihi
- Sorumlu kişi

#### Acil İzin (<24 saat)
**Kapsam**: Acil durum müdahalesi
**Süreç**:
1. Olay bildirimi (anlık)
2. Yönetici onayı (1 saat)
3. Operasyon başlar
4. 24 saat içinde detaylı rapor

**Koşullar**:
- Aktif saldırı
- Sistem çökmesi
- Veri ihlali
- Hayati tehlike

#### Özel İzin (>7 gün)
**Kapsam**: Kritik altyapı, uzun dönem izleme
**Süreç**:
1. Detaylı proje planı
2. Yönetim kurulu kararı (7 gün)
3. Hukuk birimi onayı
4. USOM bildirimi (gerekirse)
5. Dış denetçi atama
6. Periyodik raporlama

### 8.2 Loglama Gereksinimleri

#### Zorunlu Log Kayıtları

**Kullanıcı Aktivitesi**:
- Giriş/çıkış zamanı
- IP adresi ve konum
- İşlemler (CRUD)
- Yetki değişiklikleri
- Veri erişimi
- Hata logları

**Operasyon Logları**:
- Operasyon başlama/bitiş
- Hedef sistem
- Kullanılan araçlar
- Elde edilen sonuçlar
- Anomaliler
- Performans metrikleri

**Sistem Logları**:
- Servis başlatma/durdurma
- Yapılandırma değişiklikleri
- Hata ve uyarılar
- Güncellemeler
- Yedekleme işlemleri

**Güvenlik Logları**:
- Yetkisiz erişim denemeleri
- Şifre hataları
- Anormal aktiviteler
- Saldırı tespitleri
- İhlal bildirimleri

#### Log Formatı
```json
{
  "timestamp": "2026-02-20T14:30:00Z",
  "level": "INFO|WARNING|ERROR|CRITICAL",
  "source": "module_name",
  "event_type": "operation_type",
  "user_id": "username",
  "session_id": "session_hash",
  "ip_address": "xxx.xxx.xxx.xxx",
  "details": {
    "key1": "value1",
    "key2": "value2"
  },
  "status": "success|failure",
  "duration_ms": 1234
}
```

#### Log Saklama
| Log Türü | Saklama Süresi | Arşivleme |
|----------|----------------|-----------|
| **Kullanıcı aktivitesi** | 1 yıl | 3 yıl |
| **Operasyon logları** | 2 yıl | 5 yıl |
| **Sistem logları** | 6 ay | 1 yıl |
| **Güvenlik logları** | 5 yıl | 10 yıl |
| **İhlal logları** | 10 yıl | Sürekli |

### 8.3 Log Güvenliği

#### Korumalı Özellikler
- ✅ Şifreli saklama (AES-256)
- ✅ İmza ile bütünlük (HMAC)
- ✅ Güvenli yedekleme
- ✅ Erişim kontrolü (Admin/Denetçi)
- ✅ Değiştirilemez (append-only)
- ✅ Dağıtık depolama

#### Log Erişim Yetkileri
| Rol | Görüntüleme | İndirme | Silme | Düzenleme |
|-----|-------------|---------|-------|-----------|
| **Viewer** | ❌ | ❌ | ❌ | ❌ |
| **Analyst** | Kendi | ❌ | ❌ | ❌ |
| **Operator** | Tümü | ❌ | ❌ | ❌ |
| **Admin** | Tümü | ✅ | ❌ | ❌ |
| **Auditor** | Tümü | ✅ | ❌ | ❌ |

**Not**: Silme işlemi sadece veri imha prosedürüne göre yapılır.

### 8.4 Log Analizi

#### Gerçek Zamanlı Analiz
**Olası İhlal Belirtileri**:
- Anormal erişim zamanı (gece yarısı)
- Anormal lokasyon (yurt dışı)
- Anormal veri hacmi (toplu ihracat)
- Anormal sıklık (saniyede çok işlem)
- Başarısız denemeler (brute force)

#### Periyodik Analiz
**Haftalık**:
- Kullanıcı aktivite özeti
- Operasyon istatistikleri
- Anomali tespiti
- Performans metrikleri

**Aylık**:
- Trend analizi
- İhlal raporları
- Uyumluluk kontrolü
- Risk değerlendirmesi

### 8.5 Log Dışa Aktarma

#### Dışa Aktarma İzninleri
| Amaç | Yetki | Log Türü | Limit |
|------|-------|----------|-------|
| **Denetim** | Auditor | Tüm loglar | Unlimited |
| **Raporlama** | Admin+ | Operasyon logları | 1 GB |
| **Hukuki** | Yönetim | İlgili loglar | Gerekli |
| **Yedekleme** | Admin | Tüm loglar | Full |

#### Dışa Aktarma Formatı
- JSON (tercih edilen)
- CSV (alternatif)
- Sıkıştırılmış (gzip)

#### Dışa Aktarma Güvenliği
- ✅ Şifreli transfer (SFTP/HTTPS)
- ✅ İmza doğrulama
- ✅ Alıcı yetki kontrolü
- ✅ Transfer loglama
- ✅ Geçici link kullanma (maksimum 24 saat)

---

## 9. YASAKLI FAALİYETLER

### 9.1 Kesinlikle Yasaklanan Faaliyetler

#### Saldırı Faaliyetleri
- ❌ **Yetkisiz sistemlere giriş**
- ❌ **Brute force saldırıları**
- ❌ **DDoS/flood saldırıları**
- ❌ **Man-in-the-middle (MITM) saldırıları**
- ❌ **SQL Injection, XSS, CSRF**
- ❌ **Malware/ransomware dağıtımı**
- ❌ **Zero-day exploit kullanımı**
- ❌ **Sosyal mühendeslik saldırıları**
- ❌ **Fiziksel cihaza müdahale**

#### Veri Suistimali
- ❌ **Kişisel veri hırsızlığı**
- ❌ **Ticari sır ifşası**
- ❌ **Veri kaldıraçlama (data hostage)**
- ❌ **Veri manipülasyonu**
- ❌ **Log silme/değiştirme**
- ❌ **İzinsiz veri satışı**

#### İzleme İhlalleri
- ❌ **Yasa dışı telefon dinleme**
- ❌ **Web kamerası izleme (izinsiz)**
- ❌ **GPS takibi (izinsiz)**
- ❌ **Keylogger kullanımı**
- ❌ **Ekran görüntüsü alma (izinsiz)**
- ❌ **Mikrofon kaydı (izinsiz)**

#### Sistem İhlalleri
- ❌ **Yetki yükseltme (privilege escalation)**
- ❌ **Güvenlik atlama (bypass)**
- ❌ **Rootkit/firmware modifikasyonu**
- ❌ **İmza sahteciliği**
- ❌ **Sertifika hırsızlığı**

### 9.2 Koşullu Yasak (Özel İzin Gerekli)

#### Kritik Altyapı Testleri
- ⚠️ **Elektrik santrali testi**
- ⚠️ **Havaalanı sistemi testi**
- ⚠️ **Bankacılık sistemi testi**
- ⚠️ **Sağlık sistemi testi**
- ⚠️ **Telekomünikasyon altyapısı testi**

**Gereklilik**:
- Resmi izin (yazılı)
- İşletmeci bilgilendirme
- İşbirliği protokolü
- Acil durum planı
- Denetçi atama

#### Hassas Veri İşleme
- ⚠️ **Sağlık verisi**
- ⚠️ **Mali veri**
- ⚠️ **Devlet sırrı**
- ⚠️ **Adli data**
- ⚠️ **Çocuk verisi**

**Gereklilik**:
- KVKK Madde 6 açık rıza
- Veri sahibi bilgilendirme
- Gizlilik sözleşmesi
- Veri minimize etme
- İmha garantisi

#### Yayın Yayma / Paylaşım
- ⚠️ **Araştırma makalesi**
- ⚠️ **Konferans sunumu**
- ⚠️ **Blog yazısı**
- ⚠️ **Sosyal medya paylaşımı**
- ⚠️ **Açık kaynak kod paylaşımı**

**Gereklilik**:
- Hassas veri yok
- Kurum onayı
- Telif hakkı kontrolü
- Sorumluluk reddi
- Güvenlik önlemi

### 9.3 Gri Alan (Dikkat Gerekli)

#### OSINT (Açık Kaynak İstihbarat)
✅ **İzinli**: Sadece açık kaynaklar
❌ **Yasak**: Gizli/özel kaynaklara erişim

**Açık Kaynaklar**:
- Shodan, Censys
- OpenCellID
- Public sosyal medya
- Hükümet verileri
- Akademik araştırma

#### Pasif İzleme
✅ **İzinli**: Sadece yakalanan paketler
❌ **Yasak**: Aktif sorgu veya müdahale

**Sınırlar**:
- Kendi ağınız
- Kamusal alan (sınırlı)
- Kısa süre (4 saat)
- Veri saklama yok

#### Hobi / Eğitim
✅ **İzinli**: Laboratuvar ortamı
❌ **Yasak**: Gerçek sistem

**Koşullar**:
- Izole ağ
- İzinli cihazlar
- Eğitim amaçlı
- Denetçi gözetimi

### 9.4 İhlal Bildirimi

#### Bildirim Zorunluluğu
**Kime**: Denetçi ve Yönetici
**Zaman**: İhlal tespitinden 1 saat içinde
**İçerik**:
- İhlal tanımı
- Nedeni
- Etkisi
- Alınan önlemler
- Sorumlu kişi

#### Bildirim Yöntemleri
1. **E-posta**: auditor@tsunami.local
2. **Portal**: TSUNAMI Ethics Hotline
3. **Anonim**: Web formu (gerekirse)
4. **Doğrudan**: Denetçiye veya Yönetime

#### Koruma
**Gizlilik**: Bildirimci gizli tutulur
**İntikam**: Yasaktır ve cezalandırılır
**Ödül**: İyi niyetli bildirim için teşekkür

---

## 10. ACİL DURUM PROTOKOLLERİ

### 10.1 Acil Durum Türleri

#### Tip 1: Kritik Sistem Çökmesi
**Tanım**: TSUNAMI veya bağlı sistemin tamamen durması

**Belirtiler**:
- Dashboard erişilemez
- Tüm API'ler yanıt vermiyor
- Veritabanı bağlantısı yok
- Kayıp paket %100

**Müdahale Süreci**:
1. **Anlık (0-5 dk)**:
   - Durum tespiti
   - Acil durum ekibi bilgilendirme
   - Yedek sistem kontrolü

2. **Kısa vadeli (5-30 dk)**:
   - Log analizi
   - Sistem restart (gerekirse)
   - Kritik servisleri yükleme

3. **Orta vadeli (30 dk - 2 saat)**:
   - Sorun tespiti
   - Geçici çözüm
   - Hizmeti kısmi geri yükleme

4. **Uzun vadeli (2+ saat)**:
   - Kalıcı çözüm
   - Tam hizmet geri yükleme
   - Rapor hazırlama

#### Tip 2: Veri İhlali
**Tanım**: Yetkisiz veri erişimi, hırsızlığı veya ifşası

**Belirtiler**:
- Anormal veri ihracı
- Şüpheli erişim logları
- Raporlama eksikliği
- Dış kaynak sızıntı haberi

**Müdahale Süreci**:
1. **Anlık (0-15 dk)**:
   - İhlal teyidi
   - Etki alanı tespiti
   - Erişimi engelleme

2. **Kısa vadeli (15-60 dk)**:
   - İhlal kaynağı tespiti
   - Etkilenen kişileri belirleme
   - Hukuk birimi bilgilendirme

3. **Orta vadeli (1-24 saat)**:
   - KVKK bildirimi (72 saat içinde)
   - Etkilenen kişileri bilgilendirme
   - Medeni tazminat hesaplama

4. **Uzun vadeli (24+ saat)**:
   - Savcılığa bildirim (gerekirse)
   - Teknik önlemler
   - Politikalarını gözden geçirme

#### Tip 3: Aktif Saldırı
**Tanım**: Dış kaynaklı siber saldırı

**Belirtiler**:
- Anormal trafik
- Gecikme artışı
- Hatalı davranış
- IDS/IPS alarmı

**Müdahale Süreci**:
1. **Anlık (0-5 dk)**:
   - Saldırı tespiti
   - Kaynağı engelleme
   - Trafik filtreleme

2. **Kısa vadeli (5-30 dk)**:
   - Saldırı tipi belirleme
   - Savunma stratejisi
   - USOM bildirimi (24 saat)

3. **Orta vadeli (30 dk - 4 saat)**:
   - Saldırı analizi
   - Kalıcı savunma
   - Rapor hazırlama

4. **Uzun vadeli (4+ saat)**:
   - İyileştirme
   - Personel eğitimi
   - Teknik güncelleme

#### Tip 4: Yasal Talep / Arama
**Tanım**: Resmi makamlardan talep veya arama

**Belirtiler**:
- Savcılık yazısı
- Polis araması
- Mahkeme kararı

**Müdahale Süreci**:
1. **Anlık**:
   - Talep kabulü
   - Yetkili yönetici bilgilendirme
   - Hukuk birimi çağırma

2. **Kısa vadeli**:
   - Kararı inceleme
   - Bilgi toplama
   - Resmi yanıt

3. **Orta/Uzun vadeli**:
   - İşbirliği
   - Gerekli belgeleri sağlama
   - Duruşma/kanıt sunumu

#### Tip 5: İç İhlal
**Tanım**: Personelin kasıtlı veya ihmalci davranışı

**Belirtiler**:
- Yetki aşımı
- Log eksikliği
- Şüpheli aktivite
- Raporlama hatası

**Müdahale Süreci**:
1. **Anlık**:
   - Aktiviteyi durdurma
   - Erişimi kısıtlama
   - Kanıt toplama

2. **Kısa vadeli**:
   - İhlal analizi
   - Personel bilgilendirme
   - Disiplin süreci

3. **Orta/Uzun vadeli**:
   - Cezai işlem
   - Sistem iyileştirme
   - Personel eğitimi

### 10.2 Acil Durum Ekibi

#### Ekip Yapısı
**Lider**: Yönetici
**Üyeler**:
- Sistem Yöneticisi
- Güvenlik Analisti
- Hukuk Danışmanı
- İletişim Sorumlusu
- İlgili Operatörler

#### Rol Dağılımı
**Yönetici**:
- Ekibe liderlik
- Karar alma
- İletişim yönetimi

**Sistem Yöneticisi**:
- Teknik müdahale
- Sistem geri yükleme
- Log analizi

**Güvenlik Analisti**:
- Saldırı analizi
- Savunma stratejisi
- Risk değerlendirmesi

**Hukuk Danışmanı**:
- Yasal danışmanlık
- Resmi yazılar
- Mahkeme ilişkileri

**İletişim Sorumlusu**:
- Dış iletişim
- Basın açıklaması
- Paydaş bilgilendirme

### 10.3 İletişim Planı

#### İç İletişim
**Acil durum ekibi**: Anlık bildirim (SMS/e-posta)
**Tüm personel**: 15 dakika içinde toplu e-posta
**Yönetim**: 1 saat içinde detaylı rapor

#### Dış İletişim
**USOM**: 24 saat içinde (siber olay)
**KVKK**: 72 saat içinde (veri ihlali)
**Savcılık**: Gerekirse (yasa ihlali)
**Medya**: Sadece gerekli ve onaylı

#### İletişim Kanalları
- **Birincil**: E-posta
- **İkincil**: Telefon
- **Acil**: SMS
- **Yedek**: Şirket içi mesajlaşma

### 10.4 Kurtarma Planı

#### Veri Kurtarma
1. **Yedekten yükleme**: Son temiz yedek
2. **Log analizi**: Bozulma noktası tespiti
3. **Veri doğrulama**: Bütünlük kontrolü
4. **Hizmete alma**: Kademeli restart

#### Sistem Kurtarma
1. **Kalibre etme**: Donanım testi
2. **Yazılım yükleme**: Temiz kopya
3. **Yapılandırma**: Son çalışan ayarlar
4. **Test**: Fonksiyon doğrulama

#### İş Sürekliliği
1. **Yedek sistem**: Kritik servisler için
2. **Yedek lokasyon**: Fiziksel felaket
3. **Alternatif yöntemler**: Manuel prosedürler
4. **Müşteri bilgilendirme**: Hizmet durumu

### 10.5 Sonrası ve İyileştirme

#### Olay Analizi
**Neler oldu?**: Detaylı kronoloji
**Neden oldu?**: Kök neden analizi
**Etkisi ne?**: Maddi/manevi zarar
**Ne yapılmalı?**: İyileştirme önerileri

#### Raporlama
**İç rapor**: Yönetim için (24 saat)
**Dış rapor**: İlgili kurumlar (gerekirse)
**Kamu raporu**: Bilgi açıklama (gerekirse)

#### İyileştirme
**Teknik**: Sistem güçlendirme
**İdari**: Politika güncelleme
**Eğitim**: Personel eğitimi
**Test**: Düzenli drills

---

## 11. EKLER

### Ek 1: KVKK Aydınlatma Metni (Örnek)

```
TSUNAMI Siber Gözetleme Merkezi - Kişisel Verilerin İşlenmesine İlişkin
Aydınlatma Metni

1. VERİ SORUMLUSU:
TSUNAMI Siber Güvenlik Merkezi
Adres: [Adres]
Telefon: [Telefon]
E-posta: [E-posta]
Web: [Web sitesi]

2. KİŞİSEL VERİLERİNİZİN İŞLENME AMACI:
Siber güvenlik faaliyetleri, tehdit tespiti ve analiz,
sistem güvenliği, istihbarat toplama, yasal yükümlülükler.

3. İŞLENEN KİŞİSEL VERİLERİNİZ:
- Kimlik bilgileri (ad, soyad, TC kimlik no)
- İletişim bilgileri (e-posta, telefon)
- Lokasyon verileri (IP, GPS)
- Cihaz bilgileri (MAC, IMEI)
- Erişim logları
- Güvenlik olayları

4. VERİLERİNİN AKTARILDIĞI TARAFLAR:
- Resmi makamlar (yasa uyarınca)
- Yurt içindeki iş ortakları (gerekirse)
- Yurt dışı aktarım yok (yeterli koruma)

5. VERİ TOPLAMA YÖNTEMİ:
- Otomatik sistemler
- Kullanıcı girişleri
- Operasyonel kayıtlar
- Açık kaynaklar

6. VERİ İŞLEME HUKUKİ SEBEPLERİ:
- Açık rızanız
- Kanuni yükümlülük
- Sözleşme gerekçesi
- Meşru menfaat

7. HAKLARINIZ (Madde 11):
- Kendi verinizin işlenip işlenmediğini öğrenme
- Bilgi talep etme
- İşleme amacını öğrenme
- Aktarımı bilme
- Düzeltme isteme
- Silme/yok etme isteme (şartlar dahilinde)
- İtiraz etme
- Zararına tazminat talep etme

8. VERİ SAKLAMA SÜRESİ:
- Kritik olaylar: 5 yıl
- Normal olaylar: 2 yıl
- Erişim logları: 1 yıl
- Geçici veriler: 90 gün

9. İRTİBAT KİŞİSİ:
Unvan: [Unvan]
E-posta: [E-posta]
Telefon: [Telefon]

10. ŞİKAYET HAKKI:
KVKK'ye veya mahkemeye başvuru hakkınız vardır.
KVKK Adresi: [Adres]
Telefon: [Telefon]
Web: [Web sitesi]
```

### Ek 2: Yetkilendirme Formu (Örnek)

```
TSUNAMI KULLANICI YETKİLENDİRME FORMU

Tarih: GG/AA/YYYY
Referans: TSUNAMI-2026-XXX

KİŞİSEL BİLGİLER:
Ad: [ ]
Soyad: [ ]
TC Kimlik No: [ ]
Görev Unvanı: [ ]
Departman: [ ]
E-posta: [ ]
Telefon: [ ]

YETKİ TALEBİ:
İstenen Yetki Seviyesi: [ ] Viewer [ ] Analyst [ ] Operator
[ ] Admin [ ] Auditor
Gerekçe: [ ]
Kullanım Amacı: [ ]
İstenen Süre: [ ] 3 ay [ ] 6 ay [ ] 1 yıl

TAHİDİT DEĞERLENDİRMESİ:
Adli Sicil Kaydı: [ ] Temiz [ ] Açıklama gerekli
Güvenlik Eğitimi: [ ] Tamamlandı [ ] Planlandı
Referanslar: [ ]
Diğer: [ ]

BEYAN:
TSUNAMI Beyaz Şapka Kuralları'nı okudum, anladım ve kabul ederim.
Veri güvenliği kurallarına uygun davranacağımı taahhüt ederim.
İhlal durumunda disiplin ve hukuki süreçleri kabul ederim.

İmza: _________________________
Tarih: _________________________

YÖNETİCİ ONAYI:
Talep İncelendi: [ ] Kabul [ ] Red
Gerekçe: [ ]
Onlayan: _________________________
Unvan: _________________________
İmza: _________________________
Tarih: _________________________

EĞİTİM VE TEST:
Eğitim Tamamlandı: [ ] Evet [ ] Hayır (Tarih: ______)
Test Sonucu: [ ] Geçti (%_____) [ ] Kaldı
Eğitmen: _________________________

AKTİVASYON:
Hesap Oluşturuldu: [ ] Evet (Kullanıcı adı: ______)
İlk Şifre İletildi: [ ] Evet [ ] Hayır
Aktivasyon Tarihi: _________________________
Sistem Yöneticisi: _________________________

İMZALAR:
Kullanıcı: _________________ Yönetici: _________________
Eğitmen: _________________ Sistem Yöneticisi: _________________
```

### Ek 3: Operasyon İzin Formu (Örnek)

```
TSUNAMI OPERASYON İZİN FORMU

Tarih: GG/AA/YYYY
Referans: TSUNAMI-OP-2026-XXX

OPERASYON BİLGİLERİ:
Operasyon Adı: [ ]
Tipi: [ ] WiFi Tarama [ ] Bluetooth [ ] Baz İstasyonu
[ ] IoT Keşif [ ] Zafiyet Tarama [ ] Paket Capture
[ ] Video Gözetleme [ ] OSINT [ ] Diğer: [ ]

HEDEF SİSTEM:
Hedef: [ ]
Adres: [ ]
Sahibi: [ ]
İletişim: [ ]
İzni: [ ] Evet [ ] Hayır

KAPSAM:
Taranacak IP Aralığı: [ ]
Taranacak Portlar: [ ]
Tarama Yöntemi: [ ]
Süre: [ ]
Veri Saklama: [ ] Evet [ ] Hayir

RİSK ANALİZİ:
Teknik Risk: [ ] Düşük [ ] Orta [ ] Yüksek
Hukuki Risk: [ ] Düşük [ ] Orta [ ] Yüksek
Gizlilik Riski: [ ] Düşük [ ] Orta [ ] Yüksek

ÖNLEMLER:
[ ] Veri şifreleme
[ ] Loglama aktif
[ ] Erişim kontrolü
[ ] İmha garantisi
[ ] Diğer: [ ]

YASAL DAYANAK:
[ ] Sözleşme (Ek: ___)
[ ] Kanun (Madde: ___)
[ ] Mahkeme kararı (Ek: ___)
[ ] Açık rıza (Ek: ___)
[ ] Diğer: [ ]

ONAYLAR:
Operatör: _________________________ (İmza & Tarih)
Yönetici: _________________________ (İmza & Tarih)
Hukuk: _________________________ (İmza & Tarih)
USOM Bildirimi: [ ] Yapıldı (No: ___) [ ] Gerekli değil

BAŞLATMA:
Planlanan Başlangıç: _________________________
Planlanan Bitiş: _________________________
Gerçek Başlangıç: _________________________
Gerçek Bitiş: _________________________

SONUÇLAR:
Tespit Edilen: [ ]
Olaylar: [ ]
İhlaller: [ ]
Zarar: [ ]

RAPORLAMA:
Rapor Hazırlandı: [ ] Evet [ ] Hayır
Rapor Tarihi: _________________________
Onaylandı: _________________________

İMZALAR:
Operatör: _________________ Yönetici: _________________
Denetçi: _________________ Yönetim Kurulu: _________________
```

### Ek 4: İhlal Bildirim Formu (Örnek)

```
TSUNAMI İHLAL BİLDİRİM FORMU

Bildirim Tarihi: GG/AA/YYYY Saat: HH:MM
Bildirim Tipi: [ ] Adli [ ] İdari [ ] Teknik
Gizlilik: [ ] Özel [ ] Gizli [ ] Çok Gizli

BİLDİRİCİ:
Ad Soyad: [ ]
Unvan: [ ]
İletişim: [ ]
Anonim: [ ] Evet [ ] Hayır

İHLAL BİLGİLERİ:
İhlal Tipi: [ ] Veri İhlali [ ] Yetki Aşımı [ ] Sistem İhlali
[ ] Güvenlik İhlali [ ] Diğer: [ ]
Tespit Tarihi: _________________________
Tespit Yeri: [ ]
Tespit Şekli: [ ]

ETKİ ANALİZİ:
Etkilenen Veri: [ ]
Etkilenen Kişiler: [ ]
Etkilenen Sistemler: [ ]
Maddi Zarar: [ ]
Manevi Zarar: [ ]

İHLAL KAYNAĞI:
Kişi: [ ]
Rol: [ ]
Neden: [ ]
Yöntem: [ ]

MÜDAHALE:
Anlık Müdahale: [ ]
Kısa Vadeli: [ ]
Uzun Vadeli: [ ]
Etkili mi: [ ] Evet [ ] Hayır

BİLDİRİMLER:
Yönetim: [ ] Evet (Tarih: ______) [ ] Hayır
Hukuk: [ ] Evet (Tarih: ______) [ ] Hayır
KVKK: [ ] Evet (Tarih: ______) [ ] Hayır
USOM: [ ] Evet (Tarih: ______) [ ] Hayır
Savcılık: [ ] Evet (Tarih: ______) [ ] Hayır

ÖNERİLER:
Teknik: [ ]
İdari: [ ]
Eğitim: [ ]

EKLER:
[ ] Loglar
[ ] Ekran görüntüleri
[ ] Diğer kanıtlar
[ ] Raporlar

ONAY:
Bildirimi Hazırlayan: _________________________ (İmza)
Yönetici Onayı: _________________________ (İmza)
Denetçi Onayı: _________________________ (İmza)
Tarih: _________________________

İZLEME:
İnceleme Başladı: _________________________
İnceleme Bitti: _________________________
Sonuç: [ ]
Cezai İşlem: [ ] Evet [ ] Hayır
İyileştirme: [ ] Evet [ ] Hayır
```

---

## 12. SÖZLÜK VE TANIMLAR

### 12.1 Teknik Terimler

- **Bilgi Güvenliği**: Bilginin gizliliğini, bütünlüğünü ve erişilebilirliğini sağlama
- **Bilişim Sistemi**: Bilgisayar, program, veri ve ağların tümü
- **Veri**: Bilginin ham hali
- **Veri İşleme**: Veri üzerinde yapılan işlem (toplama, kaydetme, değiştirme vb.)
- **Veri İhracı**: Veriyi sistemden dışarı çıkarma
- **Veri İmha**: Veriyi geri döndürülemez şekilde kaldırma
- **Kişisel Veri**: Belirlenen veya belirlenebilir gerçek kişiye ait veri
- **Özellikle Zararlı Veri**: Irk, siyasi görüş, sağlık, cinsel hayat vb.
- **Veri Sorumlusu**: Veri işleme amaç ve vasıtalarını belirleyen kişi
- **Veri İşleyen**: Veri sorlusu adına veri işleyen kişi
- **İlgili Kişi**: Kişisel verisi işlenen gerçek kişi
- **Açık Rıza**: Belirli, bilgilendirilmiş ve özgür irade beyanı
- **Anonimleştirme**: Veriyle ilişkilendirmeyi imkansız kılma
- **Şifreleme**: Veriyi okunamaz hale getirme
- **Loglama**: Olayları kaydetme
- **Denetim**: Sistem ve faaliyetlerin incelenmesi
- **İzleme**: Gerçek zamanlı takip
- **Tespit**: Tehdit veya olay bulma
- **Müdahale**: Olaya karşı eylem
- **Kurtarma**: Olay sonrası normale dönme
- **Operasyon**: Belirli amaçlı siber güvenlik faaliyeti
- **Saldırı**: Zararlı niyetli siber eylem
- **Zafiyet**: Sistem açığı
- **Tehdit**: Zarar verme potansiyeli
- **Risk**: Tehdit × Zafiyet × Etki
- **OSINT**: Açık kaynak istihbaratı
- **Pentest**: Yetkili siber güvenlik testi
- **Red Team**: Saldıran takım
- **Blue Team**: Savunan takım
- **Purple Team**: İşbirlikçi test

### 12.2 Yasal Terimler

- **KVKK**: 6698 Sayılı Kişisel Verilerin Korunması Kanunu
- **Siber Güvenlik Yasası**: 7469 Sayılı Kanun (2025)
- **TCK**: 5237 Sayılı Türk Ceza Kanunu
- **CMK**: 5271 Sayılı Ceza Muhakemesi Kanunu
- **5651**: İnternet yayınlarını düzenleyen kanun
- **USOM**: Ulusal Siber Olaylara Müdahale Merkezi
- **KVKK Kurumu**: Kişisel Verileri Koruma Kurumu
- **Bilgi Teknolojileri ve İletişim Kurumu (BTK)**: Telekomünikasyon düzenleyicisi
- **Cumhuriyet Savcısı**: Soruşturma başlatma yetkisi
- **Hakim**: Arama, elkoyma kararları
- **Adli Bilişim**: Hukuki amaçlı bilgisayar incelemesi

### 12.3 Kısaltmalar

- **RBAC**: Role-Based Access Control (Role Erişim Kontrolü)
- **IDS**: Intrusion Detection System (Saldırı Tespit Sistemi)
- **IPS**: Intrusion Prevention System (Saldırı Önleme Sistemi)
- **TLS**: Transport Layer Security (Taşıma Katmanı Güvenliği)
- **AES**: Advanced Encryption Standard
- **HMAC**: Hash-based Message Authentication Code
- **GDPR**: General Data Protection Regulation (AB Veri Koruma Tüzüğü)
- **DDoS**: Distributed Denial of Service
- **MITM**: Man-in-the-Middle
- **SQLi**: SQL Injection
- **XSS**: Cross-Site Scripting
- **CSRF**: Cross-Site Request Forgery
- **APT**: Advanced Persistent Threat
- **RaaS**: Ransomware as a Service
- **MFA**: Multi-Factor Authentication
- **SIEM**: Security Information and Event Management
- **SOC**: Security Operations Center
- **CTF**: Capture the Flag
- **CVE**: Common Vulnerabilities and Exposures
- **CVSS**: Common Vulnerability Scoring System
- **NDA**: Non-Disclosure Agreement (Gizlilik Sözleşmesi)
- **SLA**: Service Level Agreement
- **KPI**: Key Performance Indicator
- **ROI**: Return on Investment

### 12.4 TSUNAMI Özellikli Terimler

- **Beyaz Şapka**: Etik siber güvenlik uzmanı
- **Siyah Şapka**: Zararlı niyetli hacker
- **Gri Şapka**: Belirsiz niyetli hacker
- **Palantir**: Gelişmiş veri füzyon ve görselleştirme
- **Shannon**: Pentest modülü
- **Ghost**: Gizlilik modu
- **Faz**: Proje aşaması
- **TSUNAMI**: Proje kod adı
- **Harita**: Ana dashboard
- **Modüller**: Alt sistemler
- **Operatör**: Yetkili kullanıcı
- **Denetçi**: Bağımsiz gözetmen
- **Yönetici**: Admin
- **Viewer**: Sadece görüntüleme yetkisi
- **Analyst**: Analiz yetkisi
- **Operator**: Operasyon yetkisi
- **Admin**: Tam yetki
- **Auditor**: Denetim yetkisi

---

## 13. REVİZYON TARİHİ

| Versiyon | Tarih | Değişiklik | Yazar |
|----------|-------|-----------|-------|
| 1.0 | 20/02/2026 | İlk sürüm | TSUNAMI Ekibi |

---

## 14. İLETİŞİM

**TSUNAMI Güvenlik Konseyi**
E-posta: security@tsunami.local
Tel: +90 (XXX) XXX XX XX
Web: https://tsunami.local

**Denetim Birimi**
E-posta: auditor@tsunami.local
Tel: +90 (XXX) XXX XX XX

**Hukuk Danışmanlığı**
E-posta: legal@tsunami.local
Tel: +90 (XXX) XXX XX XX

**Acil Durum Hattı**
7/24: +90 (XXX) XXX XX XX

**Etik Hotline (Anonim)**
Web: https://tsunami.local/ethics
E-posta: ethics@tsunami.local

---

## 15. ONAY

Bu belge TSUNAMI Güvenlik Konseyi tarafından onaylanmış ve yürürlüğe girmiştir.

**Konsey Başkanı**: _________________________
**İmza**: _________________________
**Tarih**: 20/02/2026

**Hukuk Danışmanı**: _________________________
**İmza**: _________________________
**Tarih**: 20/02/2026

**Denetçi**: _________________________
**İmza**: _________________________
**Tarih**: 20/02/2026

---

**Bu belge TSUNAMI platformunun tüm kullanıcıları için bağlayıcıdır.
İhlal durumunda disiplin ve hukuki süreçler uygulanır.**

© 2026 TSUNAMI Siber Güvenlik Merkezi - Tüm hakları saklıdır.
