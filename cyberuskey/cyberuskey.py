import base64
import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import jwt
import requests

from cyberuskey.exceptions import InvalidValueError, InvalidAuthenticateValueError, AuthenticateException, \
    MissingAuthorizationCode


@dataclass
class CyberusKey:
    client_id: str
    client_secret: str
    redirect_uri: str
    _API_URI: str = "https://api.cyberuskey.com"
    _OPENID_PUBLIC: str = "-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHElKnuERpCN/WcD6RtS9rKhJODM\nIdr2Y1yFrS255cOaG10CLwFPhSVK5z4HQv5/VN3GB2Ft+fbu9OZRTqdA4lHo0PB3\nKaj3yByDUdIoTHd4RmZMLSFVHKR0KAW193nI7s/pzeqDL0oFpHnRNZGUqhRbm2UK\nfHHDWKkTn/iGIV7XAgMBAAE=\n-----END PUBLIC KEY-----"
    __access_token: str = field(init=False, default=None)
    __id_token: str = field(init=False, default=None)

    def _is_uri(self, uri: str):
        try:
            result = urlparse(uri)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    @property
    def api_uri(self) -> str:
        return self._API_URI

    @api_uri.setter
    def api_uri(self, uri: str) -> None:
        if not self._is_uri(uri):
            raise InvalidValueError(uri)

        self._API_URI = uri

    @property
    def openid_public(self) -> str:
        return self._OPENID_PUBLIC

    @openid_public.setter
    def openid_public(self, key: str) -> None:
        self._OPENID_PUBLIC = key

    @property
    def access_token(self) -> str:
        if self.__access_token is None:
            raise InvalidAuthenticateValueError

        return self.__access_token

    @property
    def id_token(self) -> str:
        if self.__id_token is None:
            raise InvalidAuthenticateValueError

        return self.__id_token

    def _compute_claim_hash(self, value: str) -> str:
        hash_obj = hashlib.sha256()
        hash_obj.update(value.encode('utf-8'))
        first128bits = hash_obj.digest()[0:16]

        return base64.urlsafe_b64encode(first128bits).decode("utf-8")

    def _validate_claim_hash(self, original_hash: str, value: str) -> bool:
        computed_hash = self._compute_claim_hash(value)

        if original_hash != computed_hash:
            return False

        return True

    def authenticate(
        self,
        query_arguments: dict = None,
        state: str = None,
        nonce: str = None,
        code: str = None,
        error: str = None,
        error_description: str = None,
    ) -> dict:
        #TODO some description

        if query_arguments is None:
            query_arguments = {}

        error = query_arguments.get("error") or error
        if error:
            raise AuthenticateException(error, error_description)

        code = query_arguments.get("code") or code
        if not code:
            raise MissingAuthorizationCode

        if isinstance(code, list):
            code = code[0].decode("utf-8")

        if state:
            original_state = query_arguments.get('state')
            if original_state != state:
                raise AuthenticateException("invalid_state", "Invalid state value")

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        headers = {
            'Authorization':
                f'Basic {base64.b64encode(str.encode(f"{self.client_id}:{self.client_secret}")).decode("utf-8")}'
        }

        token_response = requests.post(urljoin(self._API_URI, 'api/v2/tokens'), data=data, headers=headers)
        token_body = token_response.json()

        if token_body.get('error'):
            return token_body['error']

        id_token = token_body['id_token']
        self.__id_token = id_token
        id_data = jwt.decode(id_token, self._OPENID_PUBLIC, algorithms=['RS256'], audience=self.client_id)

        if id_data.get("nonce") and nonce:
            if id_data['nonce'] != nonce:
                raise AuthenticateException("invalid_nonce", "Invalid nonce value")

        access_token = token_body['access_token']
        original_at_hash = id_data.get('at_hash')
        original_c_hash = id_data.get('c_hash')

        if original_at_hash:
            if not self._validate_claim_hash(original_at_hash, access_token):
                raise AuthenticateException("invalid_at_hash", "Access token hash is invalid")

        if original_c_hash:
            if not self._validate_claim_hash(original_c_hash, code):
                raise AuthenticateException("invalid_c_hash", "Authorization code hash is invalid")

        self.__access_token = access_token

        return id_data

