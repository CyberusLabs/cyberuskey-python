import base64
from dataclasses import dataclass, field
from typing import Dict, Tuple
from urllib.parse import urljoin

import jwt
import requests

from cyberuskey.exceptions import (
    InvalidValueError,
    InvalidAuthenticateValueError,
    AuthenticateException,
    MissingAuthorizationCode,
)
from cyberuskey.utils import is_uri, compute_claim_hash


@dataclass
class CyberusKey:
    client_id: str
    client_secret: str
    redirect_uri: str
    _API_URI: str = "https://api.cyberuskey.com"
    _OPENID_PUBLIC: str = "-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHElKnuERpCN/WcD6RtS9rKhJODM\nIdr2Y1yFrS255cOaG10CLwFPhSVK5z4HQv5/VN3GB2Ft+fbu9OZRTqdA4lHo0PB3\nKaj3yByDUdIoTHd4RmZMLSFVHKR0KAW193nI7s/pzeqDL0oFpHnRNZGUqhRbm2UK\nfHHDWKkTn/iGIV7XAgMBAAE=\n-----END PUBLIC KEY-----"
    __access_token: str = field(init=False, default=None)
    __id_token: str = field(init=False, default=None)

    @property
    def api_uri(self) -> str:
        return self._API_URI

    @api_uri.setter
    def api_uri(self, uri: str) -> None:
        if not is_uri(uri):
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

    def _validate_claim_hash(self, original_hash: str, value: str) -> bool:
        computed_hash = compute_claim_hash(value)

        if original_hash != computed_hash:
            return False

        return True

    def authorize(
        self,
        query_arguments: Dict = None,
        state: str = None,
        nonce: str = None,
        code: str = None,
        error: str = None,
        error_description: str = None,
    ) -> Tuple[Dict, str]:
        """Cyberus Key authorization function. You can pass arguments in Dict format ($query_arguments)
         or separately like keywords args.
        IF state value is present in $query_arguments, it will be compared to the $state value
         you passed (e.g. coming from a secure cookie)
        IF you pass $nonce value it will be compared from id token decoded data.
        All exceptions you can catch by AuthenticateBaseException.
        :raises AuthenticateException, MissingAuthorizationCode
        :return Tuple (Dict: {
            str: 'iss': client domain,
            str: 'sub': user openid identifier,
            str: 'aud': client key,
            str: 'alg': jwt decode algorithm, in our case 'RS256',
            int: 'exp': token expiration timestamp,
            int: 'iat': token generation timestamp,
            str: 'mobile': app instance identifier,
            str: 'at_hash': access token claim hash, base64 encoded from first 128 bytes,
            str: 'c_hash': authorization code claim hash, the same as above,
            str: 'email': user email,
            str: 'name': full user name ex. 'John Cook',
            str: 'given_name': first user name, ex. 'John',
            str: 'family_name': user surname, ex. 'Cook',
        },
        str: access token value)
        """

        if query_arguments is None:
            query_arguments = {}

        error = query_arguments.get("error") or error
        error_description = (
            query_arguments.get("error_description") or error_description
        )

        if error:
            raise AuthenticateException(error, error_description)

        code = query_arguments.get("code") or code
        if not code:
            raise MissingAuthorizationCode

        if isinstance(code, list):
            code = code[0].decode("utf-8")

        if query_arguments.get("state"):
            if query_arguments["state"] != state:
                raise AuthenticateException("invalid_state", "Invalid state value")

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        headers = {
            "Authorization": f'Basic {base64.b64encode(str.encode(f"{self.client_id}:{self.client_secret}")).decode("utf-8")}'
        }

        token_response = requests.post(
            urljoin(self._API_URI, "api/v2/tokens"), data=data, headers=headers
        )
        token_body = token_response.json()

        if token_body.get("error"):
            return token_body["error"]

        id_token = token_body["id_token"]
        self.__id_token = id_token
        id_data = jwt.decode(
            id_token, self._OPENID_PUBLIC, algorithms=["RS256"], audience=self.client_id
        )

        if id_data.get("nonce"):
            if id_data["nonce"] != nonce:
                raise AuthenticateException("invalid_nonce", "Invalid nonce value")

        access_token = token_body["access_token"]
        original_at_hash = id_data.get("at_hash")
        original_c_hash = id_data.get("c_hash")

        if original_at_hash:
            if not self._validate_claim_hash(original_at_hash, access_token):
                raise AuthenticateException(
                    "invalid_at_hash", "Access token hash is invalid"
                )

        if original_c_hash:
            if not self._validate_claim_hash(original_c_hash, code):
                raise AuthenticateException(
                    "invalid_c_hash", "Authorization code hash is invalid"
                )

        self.__access_token = access_token

        return id_data, access_token
