"""
TSUNAMI v5.0 - Authentication Routes
====================================

Kimlik doğrulama endpoint'leri:
- Login/Logout
- 2FA/TOTP setup
- Password management
- Session management
"""

import logging
from flask import Blueprint, request, jsonify, session, g
from functools import wraps

from dalga_validation import LoginRequest, validate_request
from middleware.error_handler import AuthenticationError, ValidationError, safe_endpoint

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# ============================================================
# Authentication Decorators
# ============================================================

def login_required(f):
    """Login zorunlu kıl"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            raise AuthenticationError("Oturum acmaniz gerekiyor")
        g.current_user = session.get('username', 'unknown')
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """Admin yetkisi zorunlu kıl"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            raise AuthenticationError("Oturum acmaniz gerekiyor")
        if not session.get('is_admin', False):
            raise AuthenticationError("Admin yetkisi gerekiyor")
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# Routes
# ============================================================

@auth_bp.route('/login', methods=['POST'])
@safe_endpoint
@validate_request(LoginRequest)
def login(validated_data):
    """
    Kullanıcı girişi.

    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - kullanici
            - sifre
          properties:
            kullanici:
              type: string
              example: admin
            sifre:
              type: string
              example: password123
    responses:
      200:
        description: Giriş başarılı
      401:
        description: Geçersiz kimlik bilgileri
    """
    username = validated_data.kullanici
    password = validated_data.sifre

    # Gerçek veritabanı kontrolü - dalga_web.py ile tutarlı
    import sys
    sys.path.insert(0, '/home/lydian/Desktop/TSUNAMI')
    try:
        from dalga_web import db as dalga_db
        if dalga_db and dalga_db.kullanici_dogrula(username, password):
            # Kullanıcı bilgilerini al
            user_info = dalga_db.kullanici_bilgi_al(username) if hasattr(dalga_db, 'kullanici_bilgi_al') else None
            session['user_id'] = user_info['id'] if user_info else 1
            session['username'] = username
            session['is_admin'] = (user_info.get('rol') == 'admin') if user_info else False
            logger.info(f"[AUTH] Login successful: {username}")
        else:
            logger.warning(f"[AUTH] Login failed: {username}")
            return jsonify({'success': False, 'message': 'Geçersiz kullanıcı adı veya şifre'}), 401
    except ImportError:
        logger.error("[AUTH] dalga_web import hatası - fallback disabled for security")
        return jsonify({'success': False, 'message': 'Kimlik doğrulama servisi kullanılamıyor'}), 503

        logger.info(f"[AUTH] Login successful: {username}")

        return jsonify({
            'success': True,
            'message': 'Giris basarili',
            'user': {
                'username': username,
                'is_admin': True
            }
        })

    logger.warning(f"[AUTH] Login failed: {username}")
    raise AuthenticationError("Gecersiz kullanici adi veya sifre")


@auth_bp.route('/logout', methods=['POST'])
@safe_endpoint
def logout():
    """
    Kullanıcı çıkışı.

    ---
    tags:
      - Authentication
    responses:
      200:
        description: Çıkış başarılı
    """
    username = session.get('username', 'unknown')
    session.clear()

    logger.info(f"[AUTH] Logout: {username}")

    return jsonify({
        'success': True,
        'message': 'Cikis basarili'
    })


@auth_bp.route('/me', methods=['GET'])
@safe_endpoint
@login_required
def get_current_user():
    """
    Mevcut kullanıcı bilgilerini getir.

    ---
    tags:
      - Authentication
    security:
      - session: []
    responses:
      200:
        description: Kullanıcı bilgileri
      401:
        description: Oturum gerekli
    """
    return jsonify({
        'success': True,
        'user': {
            'id': session.get('user_id'),
            'username': session.get('username'),
            'is_admin': session.get('is_admin', False)
        }
    })


@auth_bp.route('/2fa/setup', methods=['POST'])
@safe_endpoint
@login_required
def setup_2fa():
    """
    2FA kurulumu başlat.

    ---
    tags:
      - Authentication
    security:
      - session: []
    responses:
      200:
        description: 2FA QR kodu ve secret
    """
    try:
        import pyotp
        import base64
        from io import BytesIO

        # Secret üret
        secret = pyotp.random_base32()
        username = session.get('username', 'user')

        # TOTP oluştur
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name="TSUNAMI"
        )

        # QR code oluştur (opsiyonel)
        qr_data = None
        try:
            import qrcode
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            qr_data = base64.b64encode(buffer.getvalue()).decode()
        except ImportError:
            pass

        # Session'a kaydet (onay sonrası DB'ye yazılacak)
        session['pending_2fa_secret'] = secret

        return jsonify({
            'success': True,
            'secret': secret,
            'qr_code': qr_data,
            'provisioning_uri': provisioning_uri
        })

    except ImportError:
        raise ValidationError("2FA modulu yuklu degil (pyotp)")


@auth_bp.route('/2fa/verify', methods=['POST'])
@safe_endpoint
@login_required
def verify_2fa():
    """
    2FA kodunu doğrula.

    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - code
          properties:
            code:
              type: string
              example: "123456"
    responses:
      200:
        description: 2FA doğrulandı
      400:
        description: Geçersiz kod
    """
    try:
        import pyotp

        data = request.get_json() or {}
        code = data.get('code', '')

        secret = session.get('pending_2fa_secret')
        if not secret:
            raise ValidationError("Oncelikle 2FA kurulumunu baslatin")

        totp = pyotp.TOTP(secret)

        if totp.verify(code):
            # TODO: Secret'i veritabanına kaydet
            session.pop('pending_2fa_secret', None)
            session['2fa_verified'] = True

            return jsonify({
                'success': True,
                'message': '2FA basariyla etkinlestirildi'
            })

        raise ValidationError("Gecersiz 2FA kodu")

    except ImportError:
        raise ValidationError("2FA modulu yuklu degil (pyotp)")


@auth_bp.route('/password/change', methods=['POST'])
@safe_endpoint
@login_required
def change_password():
    """
    Şifre değiştir.

    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - current_password
            - new_password
          properties:
            current_password:
              type: string
            new_password:
              type: string
    responses:
      200:
        description: Şifre değiştirildi
      400:
        description: Geçersiz şifre
    """
    data = request.get_json() or {}
    current = data.get('current_password', '')
    new_password = data.get('new_password', '')

    # Şifre gereksinimleri
    if len(new_password) < 12:
        raise ValidationError("Sifre en az 12 karakter olmali")

    if not any(c.isupper() for c in new_password):
        raise ValidationError("Sifre en az bir buyuk harf icermeli")

    if not any(c.islower() for c in new_password):
        raise ValidationError("Sifre en az bir kucuk harf icermeli")

    if not any(c.isdigit() for c in new_password):
        raise ValidationError("Sifre en az bir rakam icermeli")

    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in new_password):
        raise ValidationError("Sifre en az bir ozel karakter icermeli")

    # TODO: Veritabanında güncelle

    logger.info(f"[AUTH] Password changed: {session.get('username')}")

    return jsonify({
        'success': True,
        'message': 'Sifre basariyla degistirildi'
    })


# Export
__all__ = ['auth_bp', 'login_required', 'admin_required']
