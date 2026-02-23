// API Service for TSUNAMI React Frontend
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8082';

export const api = {
  // Get all map data (WiFi, Bluetooth, IoT) from Flask backend
  getHaritaVeriler: async () => {
    const response = await fetch(`${API_URL}/api/harita/veriler`);
    return response.json();
  },

  // Get IoT devices
  getIoTDevices: async () => {
    const response = await fetch(`${API_URL}/api/iot/liste`);
    return response.json();
  },

  // Get WiFi networks
  getWiFiNetworks: async () => {
    const response = await fetch(`${API_URL}/api/wifi/liste`);
    return response.json();
  },

  // Get Bluetooth devices
  getBluetoothDevices: async () => {
    const response = await fetch(`${API_URL}/api/bluetooth/liste`);
    return response.json();
  },

  // Get base stations
  getBaseStations: async () => {
    const response = await fetch(`${API_URL}/api/baz/liste`);
    return response.json();
  },

  // Get vulnerabilities
  getVulnerabilities: async () => {
    const response = await fetch(`${API_URL}/api/zafiyetler/liste`);
    return response.json();
  },

  // Get alarms
  getAlarms: async () => {
    const response = await fetch(`${API_URL}/api/alarmlar/liste`);
    return response.json();
  },

  // Get system status
  getSystemStatus: async () => {
    const response = await fetch(`${API_URL}/api/durum`);
    return response.json();
  },

  // Get security status
  getSecurityStatus: async () => {
    const response = await fetch(`${API_URL}/api/guvenlik/durum`);
    return response.json();
  },

  // Scan WiFi networks
  scanWiFi: async () => {
    const response = await fetch(`${API_URL}/api/wifi/tara`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    return response.json();
  },

  // Scan Bluetooth devices
  scanBluetooth: async () => {
    const response = await fetch(`${API_URL}/api/bluetooth/tara`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    return response.json();
  },

  // Scan ports
  scanPorts: async (target) => {
    const response = await fetch(`${API_URL}/api/port/tara`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hedef: target })
    });
    return response.json();
  },

  // Scan vulnerabilities
  scanVulnerabilities: async (target) => {
    const response = await fetch(`${API_URL}/api/zafiyet/tara`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hedef: target })
    });
    return response.json();
  },

  // Health Check
  healthCheck: async () => {
    const response = await fetch(`${API_URL}/health`);
    return response.json();
  },

  // Session Check
  checkSession: async () => {
    const response = await fetch(`${API_URL}/api/session`);
    return response.json();
  }
};

export default api;
