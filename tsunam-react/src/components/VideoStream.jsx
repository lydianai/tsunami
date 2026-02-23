import React, { useState } from 'react';
import './VideoStream.css';

function VideoStream({ cameras, onClose }) {
  const [selectedCamera, setSelectedCamera] = useState(null);

  return (
    <div className="panel video-panel">
      <div className="panel-header">
        <div className="panel-title">
          <span>📹</span>
          <span>Canlı Video Akışları</span>
        </div>
        <button className="panel-close" onClick={onClose}>✕</button>
      </div>
      <div className="panel-content">
        <div className="video-grid">
          {cameras?.slice(0, 4).map((camera, index) => (
            <div
              key={index}
              className={`video-card ${selectedCamera === index ? 'active' : ''}`}
              onClick={() => setSelectedCamera(index)}
            >
              <div className="video-thumbnail">
                <span className="camera-icon">📹</span>
                <span className="camera-status">{camera.durum}</span>
              </div>
              <div className="video-info">
                <h4>{camera.adi}</h4>
                <p>{camera.lokasyon}</p>
              </div>
            </div>
          ))}
        </div>
        {selectedCamera !== null && (
          <div className="video-player">
            <h3>{cameras[selectedCamera].adi}</h3>
            <div className="video-container">
              <p style={{color: 'var(--text-secondary)', textAlign: 'center', padding: '20px'}}>
                Video player placeholder
              </p>
              <p style={{fontSize: '11px', marginTop: '10px', textAlign: 'center'}}>
                Stream URL: {cameras[selectedCamera].stream_url || 'N/A'}
              </p>
            </div>
            <div className="video-controls">
              <button className="control-btn">▶️ Play</button>
              <button className="control-btn">⏸️ Pause</button>
              <button className="control-btn">🔊 Mute</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default VideoStream;
