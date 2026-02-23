import React from 'react';
import './DataFusion.css';

function DataFusion({ data, onClose }) {
  return (
    <div className="panel fusion-panel">
      <div className="panel-header">
        <div className="panel-title">
          <span>🔄</span>
          <span>Data Fusion</span>
        </div>
        <button className="panel-close" onClick={onClose}>✕</button>
      </div>
      <div className="panel-content">
        <div className="fusion-sources">
          <div className="source-card">
            <h4>📡 IoT Devices</h4>
            <p className="source-count">{data.iotDevices?.length || 0} aktif</p>
          </div>
          <div className="source-card">
            <h4>📹 Kameralar</h4>
            <p className="source-count">{data.cameras?.length || 0} aktif</p>
          </div>
          <div className="source-card threat-card">
            <h4>⚠️ Tehditler</h4>
            <p className="source-count">{data.threats?.length || 0} bildirim</p>
          </div>
          <div className="source-card ai-card">
            <h4>🤖 AI Tahminleri</h4>
            <p className="source-count">{data.aiPredictions?.length || 0} tahmin</p>
          </div>
        </div>
        <div className="correlation-matrix">
          <h3>Correlation Matrix</h3>
          <div className="matrix-grid" style={{display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '5px', marginTop: '15px'}}>
            {['IoT', 'Camera', 'Threat', 'AI'].map((source, i) => (
              <div key={i} className="matrix-cell">
                {source}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default DataFusion;
