import React from 'react';
import './Kurallar.css';

function Kurallar({ onClose }) {
  return (
    <div className="panel kurallar-panel">
      <div className="panel-header">
        <div className="panel-title">
          <span>⚖️</span>
          <span>Beyaz Şapka Kuralları</span>
        </div>
        <button className="panel-close" onClick={onClose}>✕</button>
      </div>
      <div className="panel-content">
        <div className="rules-disclaimer">
          <h3>⚠️ Yasal Uyarı</h3>
          <p className="disclaimer-text">
            TSUNAMI siber gözetleme merkezi sadece yetkili ve resmi kullanım için tasarlanmıştır.
            Tüm operasyonlar KVKK 6698 ve 7469 sayılı kanunlar çerçevesinde gerçekleştirilmelidir.
          </p>
        </div>
        <div className="rules-list">
          <div className="rule-item">
            <span className="rule-icon">✅</span>
            <div>
              <h4>Yetkili Erişim</h4>
              <p>Sadece yetkilendirilmiş personel tarafından kullanılabilir</p>
            </div>
          </div>
          <div className="rule-item">
            <span className="rule-icon">✅</span>
            <div>
              <h4>Audit Loglama</h4>
              <p>Tüm işlemler kayıt altına alınır</p>
            </div>
          </div>
          <div className="rule-item">
            <span className="rule-icon">✅</span>
            <div>
              <h4>Etik Kullanım</h4>
              <p>Sadece beyaz şapka testleri için kullanılabilir</p>
            </div>
          </div>
          <div className="rule-item">
            <span className="rule-icon">✅</span>
            <div>
              <h4>Data Koruma</h4>
              <p>Kişisel veriler korunur ve gizli tutulur</p>
            </div>
          </div>
        </div>
        <div className="compliance-status">
          <h3>Uyumluluk Durumu</h3>
          <div className="compliance-item">
            <span>KVKK 6698</span>
            <span className="status-badge compliant">Uyumlu</span>
          </div>
          <div className="compliance-item">
            <span>7469 Siber Güvenlik</span>
            <span className="status-badge compliant">Uyumlu</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Kurallar;
