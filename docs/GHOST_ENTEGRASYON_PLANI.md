# GHOST-OSINT-CRM TSUNAMI Entegrasyon Plani

## Ozet
GHOST (Global Human Operations & Surveillance Tracking) OSINT CRM sisteminin TSUNAMI'ye entegrasyonu.

**Kaynak:** https://github.com/elm1nst3r/GHOST-osint-crm
**Lisans:** CC BY-NC-SA 4.0 (Ticari olmayan kullanim serbest)
**Atif:** elm1nst3r

---

## 1. GHOST Orijinal Ozellikler

### Kisi/Varlik Yonetimi
- Kategori bazli siniflandirma (Suphe, Tanik, POI, Iliskili, Magdur)
- Kapsamli iletisim takibi (adres, telefon, email, sosyal medya)
- Seyahat gecmisi dokumantasyonu
- Gelismis coklu parametre arama

### Ag Gorsellestirme
- ReactFlow ile interaktif iliski diyagramlari
- Coklu varlik tipleri (kisi, isletme, konum, iletisim)
- Yapilandirilabilir iliski kategorileri (aile, is, suclu)

### Cografi Istihbarat
- Geocoded konum isaretleyicileri
- Performans optimize kumeleme
- Kisi-konum korelasyonu

### Kablosuz Ag Istihbarati
- WiGLE KML dosya import
- WiFi 7 frekans bandi destegi (2.4GHz, 5GHz, 6GHz)
- Coklu varlik iliskilendirmesi

### Operasyonel Araclar
- OSINT arac envanteri
- Gorev yonetimi
- Coklu dava destegi

---

## 2. TSUNAMI Entegrasyon Mimarisi

```
+------------------------------------------+
|           TSUNAMI HARITA.HTML            |
|  (Leaflet + D3.js + Socket.IO)           |
+------------------------------------------+
              |
              v
+------------------------------------------+
|     /api/ghost/* Flask Endpoints         |
|  - /api/ghost/entities                   |
|  - /api/ghost/relationships              |
|  - /api/ghost/cases                      |
|  - /api/ghost/wireless                   |
|  - /api/ghost/graph                      |
+------------------------------------------+
              |
              v
+------------------------------------------+
|    modules/tsunami_ghost/                |
|  - ghost_manager.py (Ana yonetici)       |
|  - entity_manager.py (Kisi/Varlik)       |
|  - case_manager.py (Dava yonetimi)       |
|  - relationship_graph.py (Iliski grafi)  |
|  - wireless_intel.py (WiFi istihbarat)   |
|  - kml_parser.py (WiGLE import)          |
+------------------------------------------+
              |
              v
+------------------------------------------+
|         SQLite Database                  |
|  - ghost_entities                        |
|  - ghost_relationships                   |
|  - ghost_cases                           |
|  - ghost_wireless_networks               |
|  - ghost_travel_history                  |
|  - ghost_osint_data                      |
+------------------------------------------+
```

---

## 3. Veritabani Semasi

### ghost_entities (Varliklar)
```sql
CREATE TABLE ghost_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,          -- person, organization, device, account
    first_name TEXT,
    last_name TEXT,
    full_name TEXT,
    aliases TEXT,                        -- JSON array
    date_of_birth DATE,
    category TEXT,                       -- suspect, witness, poi, associate, victim
    status TEXT DEFAULT 'active',        -- active, archived, investigating
    crm_status TEXT DEFAULT 'new',       -- new, engaged, qualified, converted
    risk_level TEXT DEFAULT 'unknown',   -- low, medium, high, critical
    nationality TEXT,
    profile_picture_url TEXT,
    notes TEXT,

    -- Iletisim
    phone_numbers TEXT,                  -- JSON array
    email_addresses TEXT,                -- JSON array
    social_media TEXT,                   -- JSON object
    physical_addresses TEXT,             -- JSON array

    -- OSINT Verileri
    osint_data TEXT DEFAULT '[]',        -- JSON array
    attachments TEXT DEFAULT '[]',       -- JSON array
    custom_fields TEXT DEFAULT '{}',     -- JSON object

    -- Iliskiler
    case_id INTEGER,
    parent_entity_id INTEGER,

    -- Meta
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (case_id) REFERENCES ghost_cases(id),
    FOREIGN KEY (parent_entity_id) REFERENCES ghost_entities(id)
);
```

### ghost_relationships (Iliskiler)
```sql
CREATE TABLE ghost_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_entity_id INTEGER NOT NULL,
    target_entity_id INTEGER NOT NULL,
    relationship_type TEXT NOT NULL,     -- family, business, criminal, social, communication
    relationship_subtype TEXT,           -- parent, child, employer, partner, associate
    direction TEXT DEFAULT 'bidirectional', -- unidirectional, bidirectional
    strength INTEGER DEFAULT 50,         -- 0-100
    confidence INTEGER DEFAULT 50,       -- 0-100
    evidence TEXT,                       -- JSON array
    notes TEXT,
    start_date DATE,
    end_date DATE,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (source_entity_id) REFERENCES ghost_entities(id) ON DELETE CASCADE,
    FOREIGN KEY (target_entity_id) REFERENCES ghost_entities(id) ON DELETE CASCADE,
    UNIQUE(source_entity_id, target_entity_id, relationship_type)
);
```

### ghost_cases (Davalar)
```sql
CREATE TABLE ghost_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT UNIQUE,
    name TEXT NOT NULL,
    case_type TEXT DEFAULT 'investigation', -- investigation, research, threat_hunt, surveillance
    status TEXT DEFAULT 'open',          -- open, closed, suspended, archived
    priority INTEGER DEFAULT 3,          -- 1-5 (1=critical)
    classification TEXT DEFAULT 'unclassified', -- unclassified, confidential, secret, top_secret
    description TEXT,
    objectives TEXT,                     -- JSON array
    scope TEXT,
    methodology TEXT,

    -- Atama
    lead_analyst TEXT,
    team_members TEXT,                   -- JSON array

    -- Tarihler
    start_date DATE,
    target_end_date DATE,
    actual_end_date DATE,

    -- Meta
    tags TEXT,                           -- JSON array
    metadata TEXT DEFAULT '{}',
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### ghost_wireless_networks (Kablosuz Aglar)
```sql
CREATE TABLE ghost_wireless_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL,
    bssid TEXT,                          -- MAC address
    latitude REAL,
    longitude REAL,
    accuracy REAL,

    -- Teknik
    encryption TEXT,                     -- WPA2, WPA3, WEP, Open, Unknown
    auth_mode TEXT,                      -- PSK, Enterprise, Open
    signal_strength INTEGER,             -- dBm
    frequency TEXT,                      -- 2.4GHz, 5GHz, 6GHz
    channel INTEGER,
    network_type TEXT DEFAULT 'WIFI',    -- WIFI, BLUETOOTH, CELL

    -- Iliskilendirme
    entity_id INTEGER,
    case_id INTEGER,
    association_type TEXT,               -- owned, accessed, nearby
    association_confidence INTEGER,      -- 0-100
    association_note TEXT,

    -- Import
    import_source TEXT,                  -- manual, wigle_kml, sigint_scan
    import_file TEXT,
    password TEXT,                       -- Elde edilen sifre (encrypted)

    -- Meta
    first_seen TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (entity_id) REFERENCES ghost_entities(id),
    FOREIGN KEY (case_id) REFERENCES ghost_cases(id)
);
```

### ghost_travel_history (Seyahat Gecmisi)
```sql
CREATE TABLE ghost_travel_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,

    -- Konum
    location_type TEXT,                  -- residence, work, visited, transit
    address TEXT,
    city TEXT,
    country TEXT,
    latitude REAL,
    longitude REAL,

    -- Zaman
    arrival_date TIMESTAMP,
    departure_date TIMESTAMP,
    duration_days INTEGER,

    -- Detaylar
    purpose TEXT,                        -- business, personal, unknown
    transportation_mode TEXT,            -- air, land, sea, unknown
    verified INTEGER DEFAULT 0,
    evidence TEXT,                       -- JSON array
    notes TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (entity_id) REFERENCES ghost_entities(id) ON DELETE CASCADE
);
```

### ghost_osint_findings (OSINT Bulgulari)
```sql
CREATE TABLE ghost_osint_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER,
    case_id INTEGER,

    -- Bulgu
    finding_type TEXT NOT NULL,          -- social_media, breach, domain, phone, email
    source TEXT NOT NULL,
    platform TEXT,
    identifier TEXT,                     -- username, email, phone, etc.
    url TEXT,

    -- Icerik
    raw_data TEXT,                       -- JSON
    summary TEXT,
    risk_indicators TEXT,                -- JSON array

    -- Meta
    confidence INTEGER DEFAULT 50,
    verified INTEGER DEFAULT 0,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (entity_id) REFERENCES ghost_entities(id),
    FOREIGN KEY (case_id) REFERENCES ghost_cases(id)
);
```

---

## 4. API Endpoints

### Entity Management
```
GET    /api/ghost/entities              - Tum varliklari listele
POST   /api/ghost/entities              - Yeni varlik olustur
GET    /api/ghost/entities/<id>         - Varlik detayi
PUT    /api/ghost/entities/<id>         - Varlik guncelle
DELETE /api/ghost/entities/<id>         - Varlik sil
GET    /api/ghost/entities/<id>/osint   - Varlik OSINT verileri
POST   /api/ghost/entities/<id>/osint   - OSINT verisi ekle
```

### Relationship Management
```
GET    /api/ghost/relationships                    - Tum iliskiler
POST   /api/ghost/relationships                    - Iliski olustur
DELETE /api/ghost/relationships/<id>               - Iliski sil
GET    /api/ghost/entities/<id>/relationships      - Varlik iliskileri
GET    /api/ghost/graph                            - Iliski grafi (D3 format)
GET    /api/ghost/graph/<case_id>                  - Dava grafi
```

### Case Management
```
GET    /api/ghost/cases                 - Tum davalar
POST   /api/ghost/cases                 - Yeni dava
GET    /api/ghost/cases/<id>            - Dava detayi
PUT    /api/ghost/cases/<id>            - Dava guncelle
DELETE /api/ghost/cases/<id>            - Dava sil
GET    /api/ghost/cases/<id>/entities   - Dava varliklari
POST   /api/ghost/cases/<id>/entities   - Davaya varlik ekle
GET    /api/ghost/cases/<id>/timeline   - Dava zaman cizgisi
```

### Wireless Intelligence
```
GET    /api/ghost/wireless              - Kablosuz aglar
POST   /api/ghost/wireless              - Manuel ag ekle
POST   /api/ghost/wireless/import-kml   - WiGLE KML import
GET    /api/ghost/wireless/stats        - Istatistikler
GET    /api/ghost/wireless/nearby       - Yakin aglar
POST   /api/ghost/wireless/<id>/associate - Varlikla iliskilendir
GET    /api/ghost/wireless/map-data     - Harita verisi
```

### Travel & Geographic
```
GET    /api/ghost/entities/<id>/travel  - Seyahat gecmisi
POST   /api/ghost/entities/<id>/travel  - Seyahat ekle
GET    /api/ghost/locations             - Tum konumlar
GET    /api/ghost/locations/heatmap     - Isil harita verisi
POST   /api/ghost/geocode               - Adres geocode
```

---

## 5. Frontend Entegrasyonu (harita.html)

### Yeni Flyout Panel: GHOST CRM
```html
<div id="ghostCrmFlyout" class="flyout-panel">
    <!-- Tab Navigation -->
    <div class="ghost-tabs">
        <button data-tab="entities">Varliklar</button>
        <button data-tab="cases">Davalar</button>
        <button data-tab="graph">Iliski Grafi</button>
        <button data-tab="wireless">WiFi Intel</button>
    </div>

    <!-- Entity List -->
    <div id="ghostEntitiesTab">
        <div class="entity-filters">...</div>
        <div class="entity-list">...</div>
    </div>

    <!-- Relationship Graph (D3) -->
    <div id="ghostGraphTab">
        <svg id="ghostRelationshipGraph"></svg>
    </div>
</div>
```

### Harita Katmanlari
```javascript
// GHOST Entity Markers
const ghostEntityLayer = L.layerGroup();
const ghostTravelLayer = L.layerGroup();
const ghostWirelessLayer = L.layerGroup();
const ghostHeatmapLayer = L.heatLayer([], {radius: 25});

// Iliski cizgileri
const ghostRelationshipLines = L.layerGroup();
```

### D3 Iliski Grafi
```javascript
function renderGhostRelationshipGraph(data) {
    const svg = d3.select('#ghostRelationshipGraph');

    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.edges).id(d => d.id))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width/2, height/2));

    // ... render nodes and edges
}
```

---

## 6. Turkce AI Komutlari

```python
# _akilli_komut_isle() icine eklenecek

# GHOST CRM - Varlik Olustur
if re.search(r'(kisi|varlik|suphe|tanik).*(ekle|olustur|kaydet)', mesaj_lower):
    return {
        'basarili': True,
        'cikti': '**GHOST CRM** - Yeni varlik formu aciliyor...',
        'aksiyon': 'openGhostEntityForm();'
    }

# GHOST CRM - Dava Olustur
if re.search(r'(dava|sorusturma|arastirma).*(ekle|olustur|ac)', mesaj_lower):
    return {
        'basarili': True,
        'cikti': '**GHOST CRM** - Yeni dava olusturuluyor...',
        'aksiyon': 'openGhostCaseForm();'
    }

# GHOST CRM - Iliski Grafi
if re.search(r'(iliski|ag|graf).*(goster|ciz|analiz)', mesaj_lower):
    return {
        'basarili': True,
        'cikti': '**Iliski Grafi** yukleniyor...',
        'aksiyon': 'showGhostRelationshipGraph();'
    }

# GHOST CRM - WiGLE Import
if re.search(r'(wigle|kml).*(import|yukle|aktar)', mesaj_lower):
    return {
        'basarili': True,
        'cikti': '**WiGLE KML** import paneli aciliyor...',
        'aksiyon': 'openWigleImportDialog();'
    }
```

---

## 7. Guvenlik

### Sifreleme
- Hassas veriler (sifreler, OSINT) AES-256-GCM ile sifrelenir
- Entity metadata JSON sifreleme
- Travel history konum verileri opsiyonel sifreleme

### Erisim Kontrolu
- Dava bazli erisim yetkilendirmesi
- Role-based access (admin, analyst, viewer)
- Audit logging tum islemler icin

### Veri Koruma
- PII (Personal Identifiable Information) maskeleme
- Export onay mekanizmasi
- Otomatik veri temizleme (retention policy)

---

## 8. SIGINT Entegrasyonu

Mevcut SIGINT modulu ile senkronizasyon:

```python
# dalga_sigint ile entegrasyon
def sync_sigint_to_ghost():
    """SIGINT tarama sonuclarini GHOST'a aktar"""
    sigint_db = SigintDatabase()
    ghost_manager = GhostManager()

    # WiFi aglari
    wifi_networks = sigint_db.get_all_wifi()
    for network in wifi_networks:
        ghost_manager.wireless.add_network({
            'ssid': network.ssid,
            'bssid': network.bssid,
            'latitude': network.latitude,
            'longitude': network.longitude,
            'encryption': network.encryption,
            'signal_strength': network.signal,
            'import_source': 'sigint_scan'
        })
```

---

## 9. Dosya Yapisi

```
/home/lydian/Desktop/TSUNAMI/
├── modules/
│   └── tsunami_ghost/
│       ├── __init__.py
│       ├── ghost_manager.py        # Ana yonetici sinif
│       ├── entity_manager.py       # Varlik CRUD
│       ├── case_manager.py         # Dava yonetimi
│       ├── relationship_graph.py   # Iliski grafi
│       ├── wireless_intel.py       # WiFi istihbarat
│       ├── kml_parser.py           # WiGLE KML parser
│       ├── travel_tracker.py       # Seyahat takibi
│       ├── osint_collector.py      # OSINT veri toplama
│       ├── geocoder.py             # Geocoding servisi
│       ├── db.py                   # Veritabani islemleri
│       ├── crypto.py               # Sifreleme
│       └── LICENSE_GHOST.txt       # Lisans atfi
├── templates/
│   └── harita.html                 # +GHOST UI eklentileri
└── dalga_web.py                    # +GHOST API endpoints
```

---

## 10. Uygulama Adimlari

1. **Modul Olustur** - `/modules/tsunami_ghost/`
2. **Veritabani Tablolari** - SQLite schema
3. **Flask API Endpoints** - dalga_web.py'ye ekle
4. **Frontend UI** - harita.html'e GHOST paneli
5. **D3 Graf** - Iliski gorsellestirme
6. **AI Komutlari** - Turkce NLP entegrasyonu
7. **SIGINT Sync** - Mevcut tarama sonuclari
8. **Test** - Tum islevleri dogrula

---

## Lisans Uyumu

```
GHOST-osint-crm
Copyright (c) elm1nst3r
Licensed under CC BY-NC-SA 4.0

Bu modul GHOST-osint-crm projesinden esinlenmistir.
Ticari olmayan kullanim icin uygundur.
Atif: https://github.com/elm1nst3r/GHOST-osint-crm
```
