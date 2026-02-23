import React from 'react';
import './Timeline.css';

function Timeline({ data, onClose }) {
  return (
    <div className="panel timeline-panel">
      <div className="panel-header">
        <div className="panel-title">
          <span>📅</span>
          <span>Event Timeline</span>
        </div>
        <button className="panel-close" onClick={onClose}>✕</button>
      </div>
      <div className="panel-content">
        <div className="timeline-filters">
          <select className="filter-select">
            <option value="all">Tüm Türler</option>
            <option value="threat">Tehditler</option>
            <option value="camera">Kameralar</option>
            <option value="iot">IoT Cihazlar</option>
          </select>
          <select className="filter-select">
            <option value="all">Tüm Şiddetler</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
        </div>
        <div className="timeline-events">
          {data.threats?.map((threat, index) => (
            <div key={index} className="timeline-event critical">
              <div className="event-time">{threat.timestamp}</div>
              <div className="event-content">
                <div className="event-title">{threat.baslik}</div>
                <div className="event-desc">{threat.aciklama}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default Timeline;
