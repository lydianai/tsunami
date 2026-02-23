# KVKK UYUM REHBERİ - TSUNAMI Platformu

## 📋 Version 1.0
**Tarih**: 20 Şubat 2026
**Kapsam**: TSUNAMI Siber Gözetleme Merkezi
**Yasal Dayanak**: 6698 Sayılı Kişisel Verilerin Korunması Kanunu

---

## 1. GENEL BAKIŞ

### 1.1 KVKK Nedir?

6698 Sayılı Kişisel Verilerin Korunması Kanunu (KVKK), 7 Nisan 2016'da kabul edilen ve 24 Mart 2016'da Resmi Gazete'de yayınlanarak yürürlüğe giren bir Türk yasasıdır. Bu kanun:

- Kişisel verilerin işlenmesini düzenler
- Veri sahiplerinin haklarını korur
- Veri sorumlularının yükümlülüklerini belirler
- AB GDPR ile benzerlik gösterir
- İhlal durumunda ağır cezalar öngörür

### 1.2 TSUNAMI ve KVKK

TSUNAMI platformu **kişisel veri işleyen** olarak tanımlanır:
- Siber güvenlik faaliyetleri kapsamında veri toplar
- İstihbarat ve analiz amaçlı veri işler
- Kullanıcı faaliyetlerini izler
- Operasyonel verileri saklar

**Bu rehber**, TSUNAMI'ın KVKK'ya tam uyum sağlaması için gereken adımları açıklar.

---

## 2. TEMEL KAVRAMLAR

### 2.1 Kişisel Veri (Madde 3/1)

**Tanım**: Kimliği belirli veya belirlenebilir gerçek kişiye ilişkin her türlü bilgi.

**TSUNAMI'da Örnekler**:
- ✅ Kullanıcı adı ve e-posta
- ✅ IP adresleri
- ✅ MAC adresleri
- ✅ Cihaz IMEI numaraları
- ✅ Konum verileri (GPS, baz istasyonu)
- ✅ Erişim logları
- ✅ Kamera kayıtları (yüz tanıma dahil)
- ✅ Ses kayıtları

**Kişisel Veri Olmayanlar**:
- ❌ Anonimleştirilmiş veriler
- ❌ İstatistiki veriler
- ❌ Kurumsal veriler (kişiye atfedilemezse)

### 2.2 Özellikle Zararlı Veri (Madde 6)

**Tanım**: Irk, etnik köken, siyasi düşünce, felsefi inanç, din, mezhep,
cinsel hayat, sağlık verileri, ceza mahkumiyeti gibi hassas veriler.

**KVKK Uyarısı**: Bu veriler için **açık rıza şarttır** (Madde 5/2-e).

**TSUNAMI'da Örnekler**:
- ⚠️ Sağlık verisi (IoT cihaz sağlık verileri)
- ⚠️ Biyometrik veri (yüz tanıma, parmak izi)
- ⚠️ Konum verisi (sürekli takip)

**Gerekli Önlemler**:
- Açık rıza alımı (yazılı)
- Ek güvenlik önlemleri
- Veri minimize etme
- İmha garantisi

### 2.3 Veri İşleme (Madde 3/1-ç)

**Tanım**: Kişisel verilerin tamamen veya kısmen otomatik meanslerle
elde edilmesi, kaydedilmesi, depolanması, muhafaza edilmesi, değiştirilmesi,
yeniden düzenlenmesi, açıklanması, aktarılması, devralınması, elde edilebilir
hale getirilmesi, sınıflandırılması veya kullanılmasının engellenmesi gibi
veriler üzerinde gerçekleştirilen her türlü işlem.

**TSUNAMI'da Veri İşleme Faaliyetleri**:

| Faaliyet | İşleme Türü | KVKK Madde |
|----------|-------------|-----------|
| Kullanıcı girişi | Kaydetme | 5/2-ç |
| Loglama | Muhafaza etme | 5/2-ç |
| Paket capture | Elde etme | 5/2-ç |
| Analiz | Değiştirme, yeniden düzenleme | 5/2-ç |
| Raporlama | Açıklama | 5/2-ç |
| Yedekleme | Depolama | 5/2-ç |
| İmha | Kullanılmasını engelleme | 7 |

### 2.4 Veri Sorumlusu (Madde 3/1-i)

**Tanım**: Kişisel verilerin işleme amaçlarını ve vasıtalarını belirleyen,
veri kayıt sisteminin kurulmasından ve yönetilmesinden sorum olan gerçek veya
tüzel kişi.

**TSUNAMI'da Veri Sorumlusu**:
- TSUNAMI'yı işleten kurum/kuruluş
- Yönetim Kurulu Başkanı
- Veri Sorumlusu temsilcisi

**Yükümlülükleri**:
- Aydınlatma yükümlülüğü (Madde 10)
- Veri güvenliği (Madde 12)
- İhlal bildirimi (Madde 12 - 2018 Ek 1)
- İlgili kişi hakları (Madde 11)
- Veri işleme şartları (Madde 5)

### 2.5 Veri İşleyen (Madde 3/1-ı)

**Tanım**: Veri sorlusu adına kişisel verileri işleyen gerçek veya tüzel kişi.

**TSUNAMI'da Veri İşleyenler**:
- Sistem yöneticileri
- Güvenlik analistleri
- Operatörler
- Alt yükleniciler (varsa)

**Yükümlülükleri**:
- Veri sorlusunun talimatlarına uymak
- Gizlilik yükümlülüğü
- Güvenlik önlemleri
- İhlal bildirimi

---

## 3. VERİ İŞLEME ŞARTLARI (Madde 5)

### 3.1 Geçerli İşleme Şartları

Kişisel veriler **sadece aşağıdaki şartlardan birinin varlığında** işlenebilir:

#### Şart 1: Açık Rıza (Madde 5/1-a)

**Tanım**: İlgili kişinin, belirli bir konuda, bilgilendirilmeyi gerektiren
şekilde, özgür iradesiyle açıklamış olduğu onayı.

**TSUNAMI'da Kullanım**:
- Kullanıcı kaydı oluşturma
- İsteğe bağlı özellikler
- Pazarlama iletişimi
- Çerez kullanımı

**Açık Rıza Şartları**:
- ✅ Spesifik konu
- ✅ Bilgilendirilmiş
- ✅ Özgür irade
- ✅ Açık beyan
- ✅ Yazılı (veya elektronik) onay

**Örnek Metin**:
```
"TSUNAMI platformunun güvenlik özelliklerini kullanmak için kişisel verilerimin
işlenmesine açık rıza veriyorum. Bu rıza, KVKK Madde 5/1-a uyarınca geçerlidir."
```

#### Şart 2: Kanuni Yükümlülük (Madde 5/1-ç)

**Tanım**: Kişisel verilerin işlenmesinin kanunlarda açıkça öngörülmesi.

**TSUNAMI'da Kullanım**:
- 7469 Sayılı Siber Güvenlik Yasası uyarınca log tutma
- Adli kovuşturma için kayıt saklama
- 5651 Sayılı Kanun uyarınca erişim logları
- Karaparanca aklama yasası (MASAK) raporlama

**Örnek Kanunlar**:
- TCK Madde 134: Adli bilişim incelemesi
- 5651 Madde 7: Log tutma zorunluluğu
- 7469 Madde X: Siber olay bildirimi

#### Şart 3: Sözleşme (Madde 5/1-d)

**Tanım**: Sözleşmenin kurulması veya ifası için veri işlemenin gerekli olması.

**TSUNAMI'da Kullanım**:
- Müşteri sözleşmesi kapsamında
- Hizmet sağlama sözleşmesi
- İş birliği anlaşmaları

**Örnek**: Bir kuruma siber güvenlik hizmeti verilirken, sözleşme kapsamında
veri işlenmesi gerekir.

#### Şart 4: Hukuki Yükümlülük (Madde 5/1-e)

**Tanım**: Veri işlemenin, veri sorumlusunun hukuki yükümlülüğünü yerine
getirmesi için zorunlu olması.

**TSUNAMI'da Kullanım**:
- Mahkeme kararı yerine getirme
- Savcılık talebi
- İdari para cezası önleme

#### Şart 5: Haklar (Madde 5/1-f)

**Tanım**: İlgili kişinin temel hak ve özgürlüklerine zarar vermemek kaydıyla,
veri sorumlusunun meşru menfaatleri için veri işlemenin zorunlu olması.

**TSUNAMI'da Kullanım**:
- Sistem güvenliğini sağlama
- Dolandırıcılığı önleme
- Siber saldırı tespiti
- Performans optimizasyonu

**Meşru Menfaat Değerlendirmesi**:
- ✅ Veri işleme meşru bir amacı var mı?
- ✅ Veri işlemek zaruri mi?
- ✅ Daha az invaziv yol var mı?
- ✅ İlgili kişinin hakları gözetiliyor mu?

#### Şart 6: Alenileştirme (Madde 5/1-g)

**Tanım**: İlgili kişinin kendisi tarafından alenileştirilmiş verilerin işlenmesi.

**TSUNAMI'da Kullanım**:
- Açık kaynak istihbarat (OSINT)
- Sosyal medya analizi
- Public IP taraması

#### Şart 7: Aktif Çaba (Madde 5/1-h)

**Tanım**: Veri sorlusu olarak hak ve menfaatleri korumak için veri işlemenin
zorunlu olması ve ilgili kişinin haklarını zedelememesi.

**TSUNAMI'da Kullanım**:
- Kullanıcı hesap güvenliği
- Şifre karmaşıklık kontrolü
- Hesap çalınması tespiti
- Kimlik hırsızlığı önleme

### 3.2 İşleme Şartı Seçim Rehberi

| Senaryo | Öncelikli Şart | Alternatif |
|---------|----------------|------------|
| Kullanıcı kayıt | Açık rıza | Sözleşme |
| Log tutma | Kanuni yükümlülük | Meşru menfaat |
| Güvenlik analizi | Meşru menfaat | Kanuni yükümlülük |
| Mahkeme kararı | Hukuki yükümlülük | - |
| Hizmet sağlama | Sözleşme | Meşru menfaat |
| OSINT | Alenileştirme | - |

---

## 4. AYDINLATMA YÜKÜMLÜLÜĞÜ (Madde 10)

### 4.1 Genel Kural

Veri sorlusu, ilgili kişileri **veri işleme faaliyetleri hakkında**
bilgilendirmelidir.

### 4.2 Zamanı

**Veri Toplanmadan Önce**: Mümkün olan en erken aşamada

**İstisnalar**:
- Veri başka kaynaktan elde edildiyse: **30 gün içinde**
- İlgili kişi zaten bilgilendirildiyse: Gerekli değil

### 4.3 İçerik (Madde 10/1)

Aydınlatma metni aşağıdaki bilgileri içermelidir:

#### 1. Veri Sorumlusunun Kimliği
- Ad, unvan, adres
- İletişim bilgileri
- Varsa temsilci

**Örnek**:
```
Veri Sorumlusu: TSUNAMI Siber Güvenlik A.Ş.
Adres: [Adres]
Tel: +90 (XXX) XXX XX XX
E-posta: info@tsunami.local
Web: https://tsunami.local
```

#### 2. Verilerin İşleme Amacı
- Neden veri toplanıyor?
- Ne için kullanılacak?

**Örnek**:
```
Verileriniz:
- Sistem güvenliğini sağlamak
- Siber tehditleri tespit etmek
- Hizmetlerimizi sunmak
- Yasal yükümlülüklerimizi yerine getirmek
amacıyla işlenmektedir.
```

#### 3. İşlenen Verilerin Kategorisi
- Hangi veriler toplanıyor?

**Örnek**:
```
İşlenen Veriler:
- Kimlik bilgileri (ad, soyad, TC kimlik no)
- İletişim bilgileri (e-posta, telefon)
- Teknik bilgiler (IP adresi, MAC adresi)
- Konum bilgileri (GPS, baz istasyonu)
- Kullanım verileri (log, aktivite)
```

#### 4. Alıcılar veya Alıcı Kategorileri
- Veriler kime/nerelere aktarılıyor?

**Örnek**:
```
Veri Aktarımı:
- Resmi makamlar (yasa uyarınca)
- İş ortakları (gerekirse)
- Yurt dışı aktarım yok
```

#### 5. Yurt Dışına Aktarım
- Veriler yurt dışına çıkıyor mu?
- Hangi ülkelere?

**TSUNAMI'da**: Yurt dışına aktarım yok (KVKK uyumlu).

#### 6. Veri Toplama Yöntemi
- Nasıl toplanıyor?

**Örnek**:
```
Veri Toplama Yöntemleri:
- Otomatik sistemler (web, uygulama)
- Kullanıcı girişleri
- Operasyonel kayıtlar
- Açık kaynaklar
```

#### 7. Hukuki Sebebi
- Hangi Madde 5 şartı?

**Örnek**:
```
Hukuki Sebep:
- KVKK Madde 5/1-ç: Kanuni yükümlülük
- KVKK Madde 5/1-f: Meşru menfaat
- KVKK Madde 5/1-g: Alenileştirme (OSINT)
```

#### 8. Haklar (Madde 11)
- İlgili kişi hakları

**Örnek**:
```
Haklarınız:
- Verinizin işlenip işlenmediğini öğrenme
- Bilgi talep etme
- İşleme amacını öğrenme
- Aktarımı bilme
- Düzeltme isteme
- Silme/yok etme isteme (şartlar dahilinde)
- İtiraz etme
- Zararına tazminat talep etme
```

### 4.4 Aydınlatma Metni Örneği

**TSUNAMI Aydınlatma Metni** (Ek 1'de tam metin mevcuttur)

---

## 5. VERİ GÜVENLİĞİ (Madde 12)

### 5.1 Genel Yükümlülük

Veri sorlusu ve veri işleyen:
1. Verilerin hukuka aykırı işlenmesini önlemek
2. Verilere hukuka aykırı erişimi önlemek
3. Verilerin muhafazasını sağlamak

zorundadır.

### 5.2 Alınması Gereken Önlemler

#### Teknik Önlemler

**1. Erişim Kontrolü**
- ✅ Kullanıcı kimlik doğrulama (multi-factor)
- ✅ Role-based access control (RBAC)
- ✅ Yetki sınırlandırma
- ✅ Oturum yönetimi (timeout, limit)

**TSUNAMI Uygulaması**:
```python
# Kullanıcı rolleri
- Viewer: Sadece görüntüleme
- Analyst: Görüntüleme + analiz
- Operator: Tam operasyon
- Admin: Tam yetki
- Auditor: Denetim erişimi
```

**2. Şifreleme**
- ✅ TLS 1.3 (veri transferi)
- ✅ AES-256 (veri saklama)
- ✅ HMAC (bütünlük)
- ✅ Hash (şifreler için)

**TSUNAMI Uygulaması**:
```python
# Şifreleme standartları
- HTTPS zorunlu (TLS 1.3)
- Veritabanı şifreleme (SQLCipher)
- Log dosyaları şifreli
- Yedekler şifreli
```

**3. Güncelleme ve Bakım**
- ✅ Düzenli yazılım güncellemeleri
- ✅ Güvenlik patch'leri
- ✅ Güvenlik taramaları
- ✅ Zafiyet değerlendirmeleri

**TSUNAMI Uygulaması**:
```python
# Otomatik güncelleme kontrolü
- Haftalık güvenlik taraması
- Aylık zafiyet analizi
- Çeyrek dönem pen-test
- Yıllık dış denetim
```

**4. Loglama ve İzleme**
- ✅ Tüm erişimler loglanır
- ✅ Anomali tespiti
- ✅ Gerçek zamanlı izleme
- ✅ Uyarı sistemi

**TSUNAMI Uygulaması**:
```python
# Audit trail sistemi
- Kullanıcı aktivitesi
- Sistem olayları
- Güvenlik olayları
- Veri ihracı
```

**5. Yedekleme**
- ✅ Düzenli yedekleme (günlük)
- ✅ Yedek şifreleme
- ✅ Yedek testi (aylık)
- ✅ Kurtarma planı

**TSUNAMI Uygulaması**:
```python
# Yedekleme stratejisi
- Günlük artımlı yedek
- Haftalık tam yedek
- Aylık arşiv
- Coğrafi dağıtım
```

#### İdari Önlemler

**1. Personel Eğitimi**
- KVKK bilinçlendirme (yıllık)
- Güvenlik eğitimi (çeyrek dönem)
- Operasyonel prosedürler
- Acil durum drills

**TSUNAMI Uygulaması**:
```python
# Eğitim takibi
- Eğitim takip sistemi
- Sınav/quiz (min %80)
- Sertifika
- Yenileme (yıllık)
```

**2. Gizlilik Sözleşmeleri**
- Tüm personel gizlilik anlaşması imzalar
- Taahhütname
- Sorumluluk beyanı
- İhlal cezaları

**TSUNAMI Uygulaması**:
```python
# Gizlilik sözleşmesi
- KVKK uyumluluğu taahhüdü
- Veri güvenliği sorumluluğu
- İhlal bildirim zorunluluğu
- Tazminat şartı
```

**3. Yetki Yönetimi**
- En az yetki ilkesi
- Yetki rotasyonu (yıllık)
- Zorunlu izin (kritik işlemler)
- İki yönetici onayı

**TSUNAMI Uygulaması**:
```python
# Yetki politikası
- Default: En az yetki
- Onay: 2 yönetici
- Rotasyon: 6 ayda bir
- İnceleme: 3 ayda bir
```

**4. Denetim**
- İç denetim (yılda en az 2 kez)
- Dış denetim (yılda en az 1 kez)
- Uyumluluk kontrolü (aylık)
- Performans izleme (haftalık)

**TSUNAMI Uygulaması**:
```python
# Denetim takvimi
- İç denetim: Mart, Eylül
- Dış denetim: Haziran
- Uyumluluk: Her ayın 1'i
- Performans: Her Pazartesi
```

**5. Acil Durum Planı**
- Veri ihlali prosedürü
- Sistem çökmesi planı
- Kurtarma prosedürleri
- İletişim planı

**TSUNAMI Uygulaması**:
```python
# Acil durum prosedürleri
- Tip 1: Kritik çökme
- Tip 2: Veri ihlali
- Tip 3: Aktif saldırı
- Tip 4: Yasal talep
- Tip 5: İç ihlal
```

### 5.3 Veri İhlali Bildirimi (2018 Ek 1)

#### Bildirim Zamanları

**Kuruma (KVKK)**: 72 saat içinde
**İlgili Kişiye**: Gecikmeksizin

#### Bildirim İçeriği

**1. Kuruma Bildirim**:
- İhlal niteliği
- Etkilenen veri kategorisi
- Olası sonuçları
- Alınan/alınacak önlemler
- Öneriler

**2. İlgili Kişiye Bildirim**:
- İhlal açıklaması
- Etkilenen veriler
- Olası etkiler
- Alınan önlemler
- İletişim bilgileri

#### Bildirim Adımları

```
1. İhlal Tespiti (0-1 saat)
   ↓
2. Etki Analizi (1-4 saat)
   ↓
3. Önlem Alma (4-24 saat)
   ↓
4. Kuruma Bildirim (24-72 saat)
   ↓
5. İlgili Kişiyi Bilgilendirme (Gecikmeksizin)
   ↓
6. Belgeleme (72 saat içinde)
   ↓
7. İyileştirme (Sürekli)
```

#### Bildirim Formatı

**TSUNAMI Veri İhlali Bildirim Formu** (Ek 4'te mevcuttur)

---

## 6. İLGİLİ KİŞİNİN HAKLARI (Madde 11)

### 6.1 Hak Listesi

İlgili kişi, veri sorlusuna başvurarak aşağıdaki haklara sahiptir:

#### Hak 1: Bilgi Edinme (Madde 11/a)

**Ne?**: Kişisel verisinin işlenip işlenmediğini öğrenme

**Nasıl?**: Başvuru formu ile

**Cevap**: 30 gün içinde

**Ücret**: İlk başvuru ücretsiz

#### Hak 2: Bilgi Talep Etme (Madde 11-b)

**Ne?**: Veriler hakkında bilgi talep etme

**İçerik**:
- İşleme amaçları
- İşlenen veriler
- Alıcılar
- Aktarım yapılan ülkeler

#### Hak 3: Amaç Bilgisi (Madde 11-c)

**Ne?**: Verilerin işleme amacını öğrenme

**Soru**: Bu veri neden toplanıyor?

#### Hak 4: Aktarım Bilgisi (Madde 11-d)

**Ne?**: Yurt içi/yurt dışı aktarım bilgisi

**Soru**: Veriler kime aktarılıyor?

#### Hak 5: Düzeltme (Madde 11-e)

**Ne?**: Eksik/yanlış verilerin düzeltilmesini isteme

**Süreç**:
1. Başvuru
2. İnceleme (30 gün)
3. Düzeltme veya ret
4. İtiraz hakkı

#### Hak 6: Silme/Yok Etme (Madde 11-f)

**Ne?**: Verilerin silinmesini/yok edilmesini isteme

**Şartlar (Madde 7)**:
- İşleme amacı ortadan kalktıysa
- Rıza geri çekildiyse
- İhlal tespit edildiyse
- Yasal zorunluluk bitti ise

**İstisnalar**:
- Yasal yükümlülük devam ediyorsa
- İfade özgürlüğü
- Bilgi edinme özgürlüğü
- Kurul kararı

#### Hak 7: Aktarım İsteme (Madde 11-g)

**Ne?**: Verinin aktarılmasını isteme

**Koşul**: Madde 7 şartları sağlanmalı

#### Hak 8: İtiraz (Madde 11-h)

**Ne?**: Kararlara itiraz etme

**Süreç**:
1. Veri sorlusu cevabı (30 gün)
2. İtiraz (30 gün)
3. Kurula başvuru

#### Hak 9: Zararın Giderilmesi (Madde 11-i)

**Ne?**: İhlal nedeniyle zarar uğraması durumunda tazminat talep etme

**Koşullar**:
- İhlal tespiti
- Zarar kanıtı
- İlliyet bağı

### 6.2 Başvuru Süreci

#### Adım 1: Başvuru Formu

**Gerekli Bilgiler**:
- Ad, soyad
- TC kimlik no
- İletişim bilgileri
- Talep konusu
- İlgili kişi kimliği
- İmza

**Yöntemler**:
- Yazılı başvuru
- Noter ile
- Güvenli elektronik imza
- Kurul web sitesi

#### Adım 2: İnceleme

**Süre**: 30 gün

**İçerik**:
- Başvuru doğrulama
- İlgili kişi kimliği
- Veri mevcut mu?
- Şartlar sağlanıyor mu?

#### Adım 3: Cevap

**Olumlu**:
- Talep yerine getirilir
- Belge verilir
- Loglanır

**Olumsuz**:
- Gerekçe açıklanır
- Hukuki dayanak
- İtiraz yolu
- Belge verilir

#### Adım 4: İtiraz

**Süre**: Cevaptan 30 gün

**Yer**: KVKK Kurulu veya Mahkeme

---

## 7. VERİ İMHA (Madde 7)

### 7.1 İmha Şartları

Veriler, **işleme amaçlarının ortadan kalkması durumunda**
erased, destroyed veya anonimized edilir.

**Otomatik İmha**:
- Saklama süresi dolduğunda
- Rıza geri çekildiğinde
- İlgili kişi talep ettiğinde (şartlar dahilinde)

**Manuel İmha**:
- Yönetici kararı
- Denetçi önerisi
- Hukuki süreç bittiğinde

### 7.2 İmha Yöntemleri

#### 1. Silme (Deletion)

**Tanım**: Veriye erişimi tamamen engelleme

**Uygulama**:
```python
# Veritabanından silme
DELETE FROM audit_logs WHERE id = ?

# Dosyadan silme
os.remove(filepath)

# Backup'tan silme
# (Yedekten de temizle)
```

#### 2. Yok Etme (Destruction)

**Tanım**: Veriyi geri döndürülemez şekilde kaldırma

**Uygulama**:
```python
# Overwrite (3-pass)
for i in range(3):
    with open(filepath, 'w') as f:
        f.write(random_bytes(size))

# Shred (Linux)
subprocess.run(['shred', '-u', '-z', '-n', '3', filepath])
```

#### 3. Anonimleştirme (Anonymization)

**Tanım**: Veriyle ilişkilendirmeyi imkansiz hale getirme

**Uygulama**:
```python
# IP anonimleştirme
ip = "192.168.1.100"
anon_ip = ".".join(ip.split('.')[:3]) + ".0"  # 192.168.1.0

# Hash ile anonimleştirme
import hashlib
anon_id = hashlib.sha256(user_id.encode()).hexdigest()

# Veri maskeleme
email = "user@example.com"
anon_email = email[:3] + "***@" + email.split('@')[1]
```

### 7.3 İmha Prosedürü

```
1. İmha Talebi
   ↓
2. İnceleme ve Onay
   ↓
3. İmha İşlemi
   ↓
4. Doğrulama
   ↓
5. Loglama
   ↓
6. Raporlama
```

---

## 8. KVKK UYUM LİSTESİ

### 8.1 Başlangıç Kontrol Listesi

#### Kurumsal
- [ ] Veri sorlusu belirlendi
- [ ] Temsilci atandı (gerekirse)
- [ ] KVKK politikası hazırlandı
- [ ] Aydınlatma metni hazırlandı
- [ ] Başvuru formu hazırlandı

#### Teknik
- [ ] Audit trail sistemi kuruldu
- [ ] Şifreleme uygulandı
- [ ] Erişim kontrolü sağlandı
- [ ] Loglama aktif
- [ ] Yedekleme sistemi

#### İdari
- [ ] Personel eğitimi verildi
- [ ] Gizlilik sözleşmeleri imzalandı
- [ ] Yetki matrisi hazırlandı
- [ ] Acil durum planı hazırlandı
- [ ] Denetim programı belirlendi

#### Yasal
- [ ] Veri işme envanteri
- [ ] VERB (Veri İşleme Envanteri) hazırlandı
- [ ] Rıza formları hazırlandı
- [ ] İmha prosedürü belirlendi
- [ ] İhlal bildirim prosedürü

### 8.2 Sürekli Kontrol Listesi

#### Aylık
- [ ] Uyumluluk kontrolü
- [ ] Log incelemesi
- [ ] Personel aktivitesi
- [ ] Sistem güvenliği
- [ ] Zafiyet taraması

#### Çeyrek Dönem
- [ ] Denetim gerçekleştirildi
- [ ] Eğitim verildi
- [ ] Performans değerlendirmesi
- [ ] Risk analizi güncellendi
- [ ] Politika gözden geçirme

#### Yıllık
- [ ] Dış denetim
- [ ] VERB güncelleme
- [ ] Politika revizyonu
- [ ] Büyük ölçekli drill
- [ ] Stratejik planlama

---

## 9. CEZALAR VE YAPTIRIMLAR

### 9.1 İdari Para Cezaları (Madde 18)

**Hafif İhlaller**: 20.000 TL - 1.000.000 TL
- Aydınlatma yükümlülüğü ihlali
- Veri güvenliği ihlali (teknik)
- İlgili kişi hakları ihlali (hafif)

**Orta İhlaller**: 1.000.000 TL - 3.000.000 TL
- Veri işme şartları ihlali
- Veri güvenliği ihlali (idari)
- İlgili kişi hakları ihlali (orta)

**Ağır İhlaller**: 3.000.000 TL - 7.000.000 TL
- Özellikle zararlı veri ihlali
- Veri aktarım ihlali (yurt dışı)
- İlgili kişi hakları ihlali (ağır)
- Kurul kararına uymama

### 9.2 Ceza Hukuku Yaptırımları (TCK)

**Madde 135-138**: Kişisel verilerin hukuka aykırı elde edilmesi,
paylaşılması vb.

**Cezalar**:
- 1 yıldan 4 yıla kadar hapis
- Adli para cezası
- Hakkın mahrumiyeti

### 9.3 Medeni Sorumluluk

**Tazminat**: İlgili kişi, uğradığı zararın tazminini talep edebilir
(Madde 12 - 2019 Ek 1).

**Sınırlar**:
- Maddi zarar
- Manevi zarar
- İtibar kaybı
- Yasal masraflar

---

## 10. TSUNAMI KVKK UYUM MAP

### 10.1 Veri İşleme Faaliyetleri

| Faaliyet | Şart | Saklama | Güvenlik | İmha |
|----------|------|---------|----------|------|
| **Kullanıcı Yönetimi** | Rıza | 2 yıl | Şifreli, RBAC | İstifa + 2 yıl |
| **Log Kayıtları** | Kanuni | 1 yıl | Şifreli, loglama | 1 yıl |
| **Operasyon Verileri** | Kanuni/Meşru | 2 yıl | Şifreli, erişim | 2 yıl |
| **Kritik Olaylar** | Kanuni | 5 yıl | Ek güvenlik | 5 yıl |
| **Video Kayıtları** | Kanuni | 90 gün | Şifreli, erişim | 90 gün |
| **Paket Capture** | Kanuni | 7 gün | Yüksek güvenlik | 7 gün |
| **OSINT Verileri** | Alenileştirme | 6 ay | Loglama | 6 ay |
| **Şikayet/Rapor** | Rıza/Kanuni | 3 yıl | Şifreli | 3 yıl |

### 10.2 Rol Bazlı Yetkilendirme

| Rol | Veri Erişimi | İşleme | İmha | İhracat |
|-----|--------------|--------|------|---------|
| **Viewer** | Sadece kendi | ❌ | ❌ | ❌ |
| **Analyst** | Kendi + atanan | ✅ (sınırlı) | ❌ | ✅ (onaylı) |
| **Operator** | Tüm operasyonel | ✅ | ❌ | ✅ (onaylı) |
| **Admin** | Tümü | ✅ | ✅ (onaylı) | ✅ |
| **Auditor** | Loglar | ❌ | ❌ | ✅ (denetim) |

---

## 11. EKLER

### Ek 1: KVKK Aydınlatma Metni (Örnek)

*(BEYAZ_SAPKA_KURALLARI.md Ek 1'e bakın)*

### Ek 2: VERB (Veri İşleme Envanteri) Örneği

```
TSUNAMI VERİ İŞLEME ENVANTERİ (VERB)

Veri Kategorisi: KULLANICI VERİLERİ
Veri Türü: Kimlik, İletişim, Teknik
Veri Kaynağı: Kullanıcı girişi, Sistem logları
İşleme Amacı: Kullanıcı yönetimi, Güvenlik, Hizmet sunumu
Hukuki Sebep: KVKK Madde 5/1-ç, 5/1-f
Saklama Süresi: Hesap kapanışından 2 yıl
Aktarım: Resmi makamlar (yasa uyarınca)
Güvenlik: Şifreleme, RBAC, Loglama
İmha: Otomatik (süre dolumunda)
```

### Ek 3: Başvuru Formu (Örnek)

```
KVKK BAŞVURU FORMU

Ad Soyad: [ ]
TC Kimlik No: [ ]
Adres: [ ]
İletişim: [ ]

Talep Konusu:
[ ] Bilgi edinme
[ ] Düzeltme
[ ] Silme
[ ] Aktarım
[ ] İtiraz
[ ] Tazminat

Açıklama: [ ]

İmza: ____________________
Tarih: ____________________
```

### Ek 4: Veri İhlali Bildirim Formu

*(BEYAZ_SAPKA_KURALLARI.md Ek 4'e bakın)*

---

## 12. SIK SORULAN SORULAR (SSS)

### SSS 1: TSUNAMI KVKK'ya uyumlu mu?

**Cevap**: Evet, bu rehber ve BEYAZ_SAPKA_KURALLARI.md
uyumluluğu sağlamak için tasarlanmıştır.

### SSS 2: Hangi veriler KVKK kapsamında?

**Cevap**: Tüm kişisel veriler (kimlik, iletişim, teknik, konum).

### SSS 3: Verileri ne kadar saklamalıyız?

**Cevap**: Loglar 1 yıl, operasyon verileri 2 yıl, kritik olaylar 5 yıl.

### SSS 4: Veri ihlali ne zaman bildirilmeli?

**Cevap**: KVKK'ya 72 saat, ilgili kişiye gecikmeksizin.

### SSS 5: Kullanıcı hakları nasıl karşılanır?

**Cevap**: Başvuru formu ile 30 gün içinde cevap verilmelidir.

### SSS 6: Yurt dışına veri aktarımı yapılır mı?

**Cevap**: Hayır, tüm veri Türkiye içinde işlenir ve saklanır.

### SSS 7: Şeffaflık raporu nasıl hazırlanır?

**Cevap**: Yıllık aktivite raporu, VERB, uyumluluk durumu.

### SSS 8: Denetimler ne sıklıkla yapılır?

**Cevap**: İç denetim (yılda 2), dış denetim (yılda 1).

---

## 13. İLETİŞİM VE DESTEK

**KVKK Danışmanlığı**:
- E-posta: kvkk@tsunami.local
- Tel: +90 (XXX) XXX XX XX

**Veri Sorlusu Temsilcisi**:
- E-posta: vkb@tsunami.local
- Tel: +90 (XXX) XXX XX XX

**KVKK Kurumu**:
- Web: https://www.kvkk.gov.tr
- Tel: +90 (312) XXX XX XX
- Adres: [Ankara Adresi]

---

**© 2026 TSUNAMI Siber Güvenlik Merkezi**

Bu rehber bilgilendirme amaçlıdır ve yasal tavsiye niteliği taşımaz.
Konusunda uzman hukuk danışmanından yardım almalısınız.
