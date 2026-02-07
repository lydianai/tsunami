# TSUNAMI Real-Time API Reference

Quick reference for developers working with TSUNAMI's WebSocket/SocketIO real-time features.

---

## Connection Setup

### Client-Side (JavaScript)

```javascript
// Load Socket.IO library
<script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>

// Connect to server
const socket = io();

// Listen for connection
socket.on('connect', () => {
    console.log('Connected to TSUNAMI');
});

// Handle disconnection
socket.on('disconnect', () => {
    console.log('Disconnected from TSUNAMI');
});
```

---

## Event Reference

### 1. Live Attack Feed

#### Start Attack Stream
```javascript
// Client emits
socket.emit('saldiri_akisi_baslat');

// Server responds
socket.on('saldiri_akisi_durumu', (data) => {
    // data.aktif: boolean
    // data.mesaj: string
});

// Receive attacks
socket.on('canli_saldiri', (attack) => {
    console.log('Attack:', attack);
    /*
    {
      id: "ATK-1770228646571",
      zaman: "2026-02-04T21:10:46",
      saldiri: {
        tip: "DDoS",
        ciddiyet: "critical",  // critical, high, medium, low
        protokol: "TCP",
        port: 80
      },
      kaynak: {
        ip: "185.141.63.237",
        ulke: "Rusya",
        sehir: "Moscow"
      },
      hedef: {
        sehir: "Antalya",
        lat: 36.8969,
        lng: 30.7133
      }
    }
    */
});
```

#### Stop Attack Stream
```javascript
socket.emit('saldiri_akisi_durdur');
```

---

### 2. BEYIN (Brain) System

#### Request Status
```javascript
// Request current BEYIN status
socket.emit('beyin_durum_iste');

// Receive status updates
socket.on('beyin_durum', (status) => {
    console.log('BEYIN Status:', status);
    /*
    {
      aktif: true,
      zaman: "2026-02-04T21:10:46",
      defcon: {
        defcon_numara: 5,  // 1=CRITICAL, 5=SAFE
        aciklama: "Guvenli"
      },
      gizli_mod: "hayalet",  // normal, sessiz, hayalet, kapali
      saglik: {
        kalp_atisi: "2026-02-04T21:10:46",
        hata_sayisi: 0
      },
      son_kararlar: [...]
    }
    */
});

// Critical alerts
socket.on('beyin_alarm', (alarm) => {
    console.error('BEYIN ALARM:', alarm);
    /*
    {
      tip: 'kritik_saldiri',
      mesaj: 'Kritik saldiri tespit edildi: DDoS - Rusya',
      detay: {...}
    }
    */
});
```

#### Send Manual Command
```javascript
socket.emit('beyin_komut', {
    komut: 'ip_engelle',
    parametre: {
        ip: '192.168.1.100',
        sebep: 'Suspicious activity'
    }
});

socket.on('beyin_komut_sonuc', (result) => {
    console.log('Command result:', result);
});
```

**Available Commands:**
- `defcon_goster` - Display DEFCON level
- `mod_degistir` - Change stealth mode (parametre: {mod: 'hayalet'})
- `otonom_ac` - Enable autonomous mode
- `otonom_kapat` - Disable autonomous mode
- `ip_engelle` - Block IP (parametre: {ip: '1.2.3.4', sebep: 'reason'})
- `tehdit_simule` - Simulate threat for testing

---

### 3. Network Scanning

#### Start Scan
```javascript
socket.emit('tarama_baslat', {
    tip: 'wifi'  // 'wifi', 'bluetooth', or 'tum'
});

// Scan status
socket.on('tarama_durumu', (status) => {
    // status.durum: 'baslatildi' | 'tamamlandi'
    // status.tip: 'wifi' | 'bluetooth'
});

// Scan results
socket.on('tarama_sonuc', (results) => {
    console.log('Scan results:', results);
    /*
    {
      tip: 'wifi',
      sonuclar: [
        {
          ssid: 'NetworkName',
          bssid: '00:11:22:33:44:55',
          channel: 6,
          signal: -45,
          encryption: 'WPA2'
        },
        ...
      ]
    }
    */
});
```

#### Live Continuous Scan
```javascript
socket.emit('canli_tarama', {
    tip: 'wifi',
    sure: 30  // duration in seconds
});

// Live data (emitted every 5 seconds)
socket.on('canli_veri', (data) => {
    console.log('Live scan:', data);
});

socket.on('canli_durumu', (status) => {
    // status.durum: 'baslatildi' | 'tamamlandi'
});
```

---

### 4. Geolocation Search

```javascript
socket.emit('konum_ara', {
    enlem: 41.0082,
    boylam: 28.9784
});

// Progress updates
socket.on('arama_ilerleme', (progress) => {
    console.log('Searching:', progress.kaynak, progress.sonuc);
});

// Final results
socket.on('arama_sonuc', (results) => {
    console.log('Location results:', results);
    /*
    {
      wifi: [...],
      bluetooth: [...],
      baz: [...],      // cell towers
      iot: [...]       // IoT devices
    }
    */
});

socket.on('arama_durumu', (status) => {
    // status.durum: 'baslatildi' | 'tamamlandi'
});
```

---

### 5. Port Scanning

```javascript
socket.emit('port_tara', {
    hedef: '192.168.1.1',
    portlar: '1-1000'  // range or comma-separated
});

socket.on('port_sonuc', (results) => {
    console.log('Open ports:', results);
    /*
    {
      hedef: '192.168.1.1',
      sonuclar: [
        {port: 22, service: 'ssh', state: 'open'},
        {port: 80, service: 'http', state: 'open'},
        ...
      ]
    }
    */
});
```

---

### 6. Vulnerability Scanning

```javascript
socket.emit('zafiyet_tara', {
    hedef: '192.168.1.1'
});

socket.on('zafiyet_sonuc', (results) => {
    console.log('Vulnerabilities:', results);
    /*
    {
      hedef: '192.168.1.1',
      sonuclar: [
        {
          tip: 'outdated_service',
          ciddiyet: 'high',
          aciklama: 'OpenSSH 7.4 - known vulnerabilities',
          cozum: 'Update to OpenSSH 8.x'
        },
        ...
      ]
    }
    */
});
```

---

### 7. Cyber Operations

#### OSINT Investigation
```javascript
socket.emit('siber_osint_baslat', {
    hedef: 'example.com'
});

socket.on('siber_osint_basladi', (data) => {
    console.log('OSINT started:', data.hedef);
});

socket.on('siber_osint_sonuc', (result) => {
    console.log('OSINT result:', result);
});
```

#### Threat Hunting
```javascript
socket.emit('siber_tehdit_avi', {
    hedefler: ['192.168.1.100', '10.0.0.50']
});

socket.on('siber_tehdit_avi_basladi', (data) => {
    console.log('Hunting', data.hedef_sayisi, 'targets');
});

socket.on('siber_tehdit_avi_sonuc', (result) => {
    console.log('Hunt results:', result);
});
```

---

### 8. Terminal/CLI

```javascript
socket.emit('cli_komut', {
    komut: 'durum'
});

socket.on('cli_sonuc', (result) => {
    console.log(result.cikti);
});

// Interactive terminal
socket.emit('terminal_komut', {
    komut: 'ls -la'
});

socket.on('terminal_cikti', (output) => {
    console.log(output.cikti);
});
```

---

### 9. Map Updates

```javascript
// Stealth routing
socket.emit('stealth_harita_iste');

socket.on('stealth_rota_degisti', (route) => {
    console.log('Stealth route:', route);
    /*
    {
      nodes: [
        {ip: '1.2.3.4', ulke: 'USA', lat: 37.7749, lng: -122.4194},
        ...
      ],
      edges: [
        {from: '1.2.3.4', to: '5.6.7.8'},
        ...
      ]
    }
    */
});
```

---

### 10. Notifications

```javascript
socket.on('bildirim', (notification) => {
    console.log('Notification:', notification);
    /*
    {
      baslik: 'System Alert',
      mesaj: 'VPN connection established',
      tip: 'info'  // info, basari, uyari, hata, kritik
    }
    */
});
```

---

## Server-Side (Python)

### Emit to All Clients
```python
from dalga_web import socketio

socketio.emit('event_name', {
    'data': 'value'
}, namespace='/')
```

### Emit to Specific Client
```python
from flask_socketio import emit

@socketio.on('custom_event')
def handle_custom(data):
    # Process data
    emit('response_event', {'result': 'success'})
```

### Background Thread Emission
```python
import threading

def background_task():
    while running:
        socketio.emit('periodic_update', {'timestamp': time.time()})
        time.sleep(5)

thread = threading.Thread(target=background_task, daemon=True)
thread.start()
```

---

## React Component Example

```jsx
import { useEffect, useState } from 'react';
import io from 'socket.io-client';

function AttackFeed() {
    const [attacks, setAttacks] = useState([]);
    const [socket, setSocket] = useState(null);

    useEffect(() => {
        // Connect to server
        const newSocket = io('http://localhost:8080');
        setSocket(newSocket);

        // Listen for attacks
        newSocket.on('canli_saldiri', (attack) => {
            setAttacks(prev => [attack, ...prev].slice(0, 100));
        });

        // Start attack feed
        newSocket.emit('saldiri_akisi_baslat');

        // Cleanup
        return () => {
            newSocket.emit('saldiri_akisi_durdur');
            newSocket.disconnect();
        };
    }, []);

    return (
        <div className="attack-feed">
            <h2>Live Attack Feed</h2>
            {attacks.map(attack => (
                <div key={attack.id} className={`attack ${attack.saldiri.ciddiyet}`}>
                    <span className="type">{attack.saldiri.tip}</span>
                    <span className="source">{attack.kaynak.ulke}</span>
                    <span className="target">{attack.hedef.sehir}</span>
                    <span className="time">{attack.zaman}</span>
                </div>
            ))}
        </div>
    );
}

export default AttackFeed;
```

---

## Error Handling

```javascript
socket.on('connect_error', (error) => {
    console.error('Connection error:', error);
});

socket.on('error', (error) => {
    console.error('Socket error:', error);
});

socket.on('siber_hata', (error) => {
    console.error('Cyber ops error:', error.hata);
});
```

---

## Performance Tips

1. **Throttle Updates:** Use throttle/debounce for high-frequency events
2. **Batch Processing:** Group multiple updates into single emit
3. **Selective Listening:** Only subscribe to needed events
4. **Cleanup:** Always disconnect sockets when components unmount
5. **Reconnection:** Implement auto-reconnect logic for reliability

---

## Security Notes

- All WebSocket connections require session authentication
- CORS is restricted to allowed origins
- Sensitive commands log to `dalga_denetim.log`
- Rate limiting is enforced server-side
- Use HTTPS in production

---

## Testing with `curl` (HTTP Fallback)

While WebSocket is primary, some endpoints have HTTP fallbacks:

```bash
# Check BEYIN status
curl http://localhost:8080/api/beyin/durum

# Get attack feed status
curl http://localhost:8080/api/canli-saldiri/durum

# Manual command (requires auth)
curl -X POST http://localhost:8080/api/beyin/komut \
  -H "Content-Type: application/json" \
  -d '{"komut": "defcon_goster"}'
```

---

## File Locations

- **Server Implementation:** `/home/lydian/Desktop/TSUNAMI/dalga_web.py`
- **BEYIN System:** `/home/lydian/Desktop/TSUNAMI/dalga_beyin.py`
- **Client Templates:** `/home/lydian/Desktop/TSUNAMI/templates/`
- **Test Suite:** `/home/lydian/Desktop/TSUNAMI/test_realtime_audit.py`

---

*Generated by Claude Code - Frontend Developer Agent*
