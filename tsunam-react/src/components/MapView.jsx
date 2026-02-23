import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import './MapView.css';

function MapView({ data, onRefresh }) {
  const mapRef = useRef(null);
  const mapInstanceRef = useRef(null);

  useEffect(() => {
    // Initialize map
    if (!mapInstanceRef.current) {
      const map = L.map(mapRef.current).setView([39.9334, 32.8597], 6); // Turkey center

      // Add tile layer (Dark Matter theme)
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
        subdomains: 'abcd',
        maxZoom: 19
      }).addTo(map);

      mapInstanceRef.current = map;
    }

    // Add markers for IoT devices
    if (data.iotDevices && data.iotDevices.length > 0) {
      data.iotDevices.forEach(device => {
        const icon = L.divIcon({
          className: 'custom-marker iot-marker',
          html: '<div class="marker-icon">📡</div>'
        });

        L.marker([device.lat, device.lng], { icon })
          .bindPopup(`
            <div class="popup-content">
              <h4>${device.adi}</h4>
              <p><strong>Tür:</strong> ${device.tur}</p>
              <p><strong>Durum:</strong> ${device.durum}</p>
              <p><strong>Lokasyon:</strong> ${device.lokasyon}</p>
            </div>
          `)
          .addTo(mapInstanceRef.current);
      });
    }

    // Add markers for cameras
    if (data.cameras && data.cameras.length > 0) {
      data.cameras.forEach(camera => {
        const icon = L.divIcon({
          className: 'custom-marker camera-marker',
          html: '<div class="marker-icon">📹</div>'
        });

        L.marker([camera.lat, camera.lng], { icon })
          .bindPopup(`
            <div class="popup-content">
              <h4>${camera.adi}</h4>
              <p><strong>Tür:</strong> ${camera.kamera_tur}</p>
              <p><strong>Durum:</strong> ${camera.durum}</p>
              <p><strong>Lokasyon:</strong> ${camera.lokasyon}</p>
              ${camera.stream_url ? `<a href="${camera.stream_url}" target="_blank">Canlı Akış</a>` : ''}
            </div>
          `)
          .addTo(mapInstanceRef.current);
      });
    }

    // Add markers for threats
    if (data.threats && data.threats.length > 0) {
      data.threats.forEach(threat => {
        const icon = L.divIcon({
          className: 'custom-marker threat-marker',
          html: '<div class="marker-icon">⚠️</div>'
        });

        L.marker([threat.lat || 39.9334, threat.lng || 32.8597], { icon })
          .bindPopup(`
            <div class="popup-content">
              <h4>${threat.baslik || 'Tehdit'}</h4>
              <p><strong>Şiddet:</strong> ${threat.severity}</p>
              <p><strong>Tür:</strong> ${threat.vuln_type}</p>
              <p><strong>Açıklama:</strong> ${threat.aciklama}</p>
            </div>
          `)
          .addTo(mapInstanceRef.current);
      });
    }

    // Add markers for AI predictions
    if (data.aiPredictions && data.aiPredictions.length > 0) {
      data.aiPredictions.forEach(prediction => {
        const icon = L.divIcon({
          className: 'custom-marker ai-marker',
          html: '<div class="marker-icon">🤖</div>'
        });

        L.marker([prediction.lat || 39.9334, prediction.lng || 32.8597], { icon })
          .bindPopup(`
            <div class="popup-content">
              <h4>AI Tahmini</h4>
              <p><strong>Skor:</strong> ${prediction.risk_score}</p>
              <p><strong>Tahmin:</strong> ${prediction.tahmin}</p>
              <p><strong>Güven:</strong> %${prediction.confidence}</p>
            </div>
          `)
          .addTo(mapInstanceRef.current);
      });
    }

  }, [data]);

  return (
    <div className="map-view">
      <div ref={mapRef} className="map-container"></div>
      <div className="map-controls">
        <button onClick={onRefresh} className="control-btn refresh-btn">
          🔄 Yenile
        </button>
        <div className="map-stats">
          <span>📡 IoT: {data.iotDevices?.length || 0}</span>
          <span>📹 Kamera: {data.cameras?.length || 0}</span>
          <span>⚠️ Tehdit: {data.threats?.length || 0}</span>
          <span>🤖 AI: {data.aiPredictions?.length || 0}</span>
        </div>
      </div>
    </div>
  );
}

export default MapView;
