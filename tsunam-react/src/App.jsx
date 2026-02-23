import React, { useState, useEffect } from 'react';
import MapView from './components/MapView';
import Timeline from './components/Timeline';
import NetworkGraph from './components/NetworkGraph';
import Heatmap from './components/Heatmap';
import DataFusion from './components/DataFusion';
import Kurallar from './components/Kurallar';
import VideoStream from './components/VideoStream';
import './App.css';

function App() {
  const [activePanel, setActivePanel] = useState(null);
  const [mapData, setMapData] = useState({
    wifi: [],
    bluetooth: [],
    iotDevices: [],
    vulnerabilities: [],
    baseStations: [],
    threats: [],
    alarms: []
  });

  useEffect(() => {
    // Load initial data from Flask API
    fetchMapData();
  }, []);

  const fetchMapData = async () => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8082';

      // Fetch all map data using the correct API endpoints
      const haritaRes = await fetch(`${API_URL}/api/harita/veriler`);
      const wifiRes = await fetch(`${API_URL}/api/wifi/liste`);
      const bluetoothRes = await fetch(`${API_URL}/api/bluetooth/liste`);
      const iotRes = await fetch(`${API_URL}/api/iot/liste`);
      const zafiyetRes = await fetch(`${API_URL}/api/zafiyetler/liste`);

      const [haritaData, wifiData, bluetoothData, iotData, zafiyetData] = await Promise.all([
        haritaRes.json(),
        wifiRes.json(),
        bluetoothRes.json(),
        iotRes.json(),
        zafiyetRes.json()
      ]);

      // Process and set the data
      setMapData({
        wifi: wifiData.basarili ? wifiData.wifi : [],
        bluetooth: bluetoothData.basarili ? bluetoothData.bluetooth : [],
        iotDevices: iotData.basarili ? iotData.data : [],
        vulnerabilities: zafiyetData.basarili ? zafiyetData.data : [],
        baseStations: haritaData.basarili ? haritaData.baz_istasyonlari : [],
        threats: haritaData.basarili ? [] : [], // Placeholder for threat data
        alarms: haritaData.basarili ? [] : []  // Placeholder for alarm data
      });
    } catch (error) {
      console.error('Error loading map data:', error);
    }
  };

  const togglePanel = (panelName) => {
    setActivePanel(activePanel === panelName ? null : panelName);
  };

  return (
    <div className="App">
      {/* Header */}
      <header className="tsunami-header">
        <div className="header-title">
          <h1>🌊 TSUNAMI</h1>
          <span className="header-subtitle">Siber Komuta ve İstihbarat Merkezi</span>
        </div>

        <nav className="header-nav">
          <button
            className={`header-btn ${activePanel === 'timeline' ? 'active' : ''}`}
            onClick={() => togglePanel('timeline')}
            title="📅 Event Timeline - Palantir-Style Görselleştirme"
          >
            <span className="btn-icon">📅</span>
            <span className="btn-label">TIMELINE</span>
          </button>

          <button
            className={`header-btn ${activePanel === 'graph' ? 'active' : ''}`}
            onClick={() => togglePanel('graph')}
            title="🕸️ Network Graph - Entity Relationship Mapping"
          >
            <span className="btn-icon">🕸️</span>
            <span className="btn-label">GRAPH</span>
          </button>

          <button
            className={`header-btn ${activePanel === 'heatmap' ? 'active' : ''}`}
            onClick={() => togglePanel('heatmap')}
            title="🔥 Heatmap - Geographic Density Analysis"
          >
            <span className="btn-icon">🔥</span>
            <span className="btn-label">HEATMAP</span>
          </button>

          <button
            className={`header-btn ${activePanel === 'fusion' ? 'active' : ''}`}
            onClick={() => togglePanel('fusion')}
            title="🔄 Data Fusion - Multi-Source Correlation"
          >
            <span className="btn-icon">🔄</span>
            <span className="btn-label">FUSION</span>
          </button>

          <button
            className={`header-btn ${activePanel === 'kurallar' ? 'active' : ''}`}
            onClick={() => togglePanel('kurallar')}
            title="⚖️ Beyaz Şapka Kuralları"
          >
            <span className="btn-icon">⚖️</span>
            <span className="btn-label">KURALLAR</span>
          </button>

          <button
            className={`header-btn ${activePanel === 'video' ? 'active' : ''}`}
            onClick={() => togglePanel('video')}
            title="📹 Video Streams - Canlı Kamera Akışları"
          >
            <span className="btn-icon">📹</span>
            <span className="btn-label">VİDEO</span>
          </button>
        </nav>
      </header>

      {/* Main Map View */}
      <main className="main-content">
        <MapView
          data={mapData}
          onRefresh={fetchMapData}
        />
      </main>

      {/* Side Panels */}
      {activePanel === 'timeline' && (
        <Timeline
          data={mapData}
          onClose={() => setActivePanel(null)}
        />
      )}

      {activePanel === 'graph' && (
        <NetworkGraph
          data={mapData}
          onClose={() => setActivePanel(null)}
        />
      )}

      {activePanel === 'heatmap' && (
        <Heatmap
          data={mapData}
          onClose={() => setActivePanel(null)}
        />
      )}

      {activePanel === 'fusion' && (
        <DataFusion
          data={mapData}
          onClose={() => setActivePanel(null)}
        />
      )}

      {activePanel === 'kurallar' && (
        <Kurallar
          onClose={() => setActivePanel(null)}
        />
      )}

      {activePanel === 'video' && (
        <VideoStream
          cameras={mapData.cameras}
          onClose={() => setActivePanel(null)}
        />
      )}
    </div>
  );
}

export default App;
