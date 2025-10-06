import base64
import hashlib
import hmac
import json
import time
import binascii

from django.conf import settings

from auth2.models import AnonymousUser, User


class JwtService:

    def __init__(self, secret_key):
        self.secret_key = secret_key

    @staticmethod
    def base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def base64url_decode(data: str) -> bytes:
        padding = '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)

    def sign(self, payload, expire):
        encoded_header = self.base64url_encode(json.dumps({
            'alg': 'HS256',
            'typ': 'JWT',
        }).encode())

        encoded_payload = self.base64url_encode(json.dumps({
            'exp': int(time.time()) + expire,
            **payload
        }).encode())

        signature = hmac.new(
            self.secret_key.encode(),
            f'{encoded_header}.{encoded_payload}'.encode(),
            hashlib.sha256
        ).hexdigest()

        return f'{encoded_header}.{encoded_payload}.{signature}'

    def validate(self, token):
        try:
            encoded_header, encoded_payload, signature = token.split('.')
        except ValueError:
            return None, None

        try:
            header_bytes = self.base64url_decode(encoded_header)
            payload_bytes = self.base64url_decode(encoded_payload)
            header = json.loads(header_bytes.decode('utf-8'))
            payload = json.loads(payload_bytes.decode('utf-8'))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
            return None, None

        if header.get('alg') != 'HS256' or header.get('typ') != 'JWT':
            return None, None

        if 'exp' in payload and time.time() > payload['exp']:
            return None, None

        signature_check = hmac.new(
            self.secret_key.encode(),
            f'{encoded_header}.{encoded_payload}'.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, signature_check):
            return None, None

        return payload, header


class JwtAuthService:

    @staticmethod
    def get_user(auth_value):
        if auth_value is None:
            return AnonymousUser()

        keyword, token = auth_value.split(' ')

        if keyword != 'Bearer':
            return AnonymousUser()

        jwt = JwtService(settings.ACCESS_SECRET_KEY)
        payload, _ = jwt.validate(token)

        if payload is None:
            return AnonymousUser()

        user_id = payload['sub']
        user = User.objects.filter(id=user_id).first()
        if user is None:
            return AnonymousUser()

        if not user.is_active:
            return AnonymousUser()

        return user

    @staticmethod
    def get_tokens(user: User):
        payload = {
            'sub': user.id,
            'email': user.email,
            'role': user.role,
        }

        jwt_service = JwtService(settings.ACCESS_SECRET_KEY)
        access_token = jwt_service.sign(payload, 120)

        jwt_service = JwtService(settings.REFRESH_SECRET_KEY)
        refresh_token = jwt_service.sign(payload, 2592 * 1000)

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }

    @staticmethod
    def refresh_token(token):
        jwt = JwtService(settings.REFRESH_SECRET_KEY)
        payload, _ = jwt.validate(token)

        if payload is None:
            return None

        user_id = payload['sub']
        user = User.objects.filter(id=user_id).first()

        if user is None:
            return None

        if not user.is_active:
            return None

        return JwtAuthService.get_tokens(user)