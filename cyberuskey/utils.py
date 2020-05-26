import base64
import hashlib
from urllib.parse import urlparse


def compute_claim_hash(value: str) -> str:
    hash_obj = hashlib.sha256()
    hash_obj.update(value.encode("utf-8"))
    first128bits = hash_obj.digest()[0:16]

    return base64.urlsafe_b64encode(first128bits).decode("utf-8")


def is_uri(uri: str):
    try:
        result = urlparse(uri)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False
