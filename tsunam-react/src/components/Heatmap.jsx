import React from 'react';
import './Heatmap.css';

function Heatmap({ data, onClose }) {
  return (
    <div className="panel heatmap-panel">
      <div className="panel-header">
        <div className="panel-title">
          <span>🔥</span>
          <span>Heatmap</span>
        </div>
        <button className="panel-close" onClick={onClose}>✕</button>
      </div>
      <div className="panel-content">
        <div className="heatmap-controls">
          <select className="heatmap-select">
            <option value="threat">Tehdit Yoğunluğu</option>
            <option value="camera">Kamera Yoğunluğu</option>
            <option value="iot">IoT Yoğunluğu</option>
          </select>
        </div>
        <div className="heatmap-legend">
          <div className="legend-item">
            <span className="legend-color" style={{background: '#00ff88'}}></span>
            <span>Düşük</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{background: '#ffcc00'}}></span>
            <span>Orta</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{background: '#ff3355'}}></span>
            <span>Yüksek</span>
          </div>
        </div>
        <div className="heatmap-display" style={{height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.3)', borderRadius: '10px'}}>
          <p style={{color: 'var(--text-secondary)'}}>Geographic Density Heatmap</p>
          <p style={{fontSize: '11px', marginTop: '10px'}}>Multi-layer visualization</p>
        </div>
      </div>
    </div>
  );
}

export default Heatmap;
