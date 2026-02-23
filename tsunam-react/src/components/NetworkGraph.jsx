import React from 'react';
import './NetworkGraph.css';

function NetworkGraph({ data, onClose }) {
  return (
    <div className="panel network-graph-panel">
      <div className="panel-header">
        <div className="panel-title">
          <span>🕸️</span>
          <span>Network Graph</span>
        </div>
        <button className="panel-close" onClick={onClose}>✕</button>
      </div>
      <div className="panel-content">
        <div className="graph-toolbar">
          <button className="toolbar-btn">📊 Cluster</button>
          <button className="toolbar-btn">🏷️ Labels</button>
          <button className="toolbar-btn">⚡ Physics</button>
        </div>
        <div className="graph-stats">
          <span>Nodes: {data.iotDevices?.length + data.cameras?.length || 0}</span>
          <span>Links: Calculating...</span>
        </div>
        <div className="graph-container" style={{height: '400px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.3)', borderRadius: '10px'}}>
          <p style={{color: 'var(--text-secondary)'}}>D3.js Force Graph</p>
          <p style={{fontSize: '11px', marginTop: '10px'}}>Entity relationship visualization</p>
        </div>
      </div>
    </div>
  );
}

export default NetworkGraph;
