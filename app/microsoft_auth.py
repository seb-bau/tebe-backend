import jwt
from jwt import PyJWKClient
import secrets
import requests
from urllib.parse import urlencode
import logging

_jwk_clients = {}
logger = logging.getLogger('root')


def _strip_quotes(value: str) -> str:
    if value is None:
        return ""
    v = str(value).strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        return v[1:-1].strip()
    return v


def get_ms_config(app):
    cfg = app.config.get("INI_CONFIG")
    if cfg is None:
        return None
    tenant_id = _strip_quotes(cfg.get("MicrosoftAuth", "tenant_id", fallback=""))
    client_id = _strip_quotes(cfg.get("MicrosoftAuth", "client_id", fallback=""))
    if not tenant_id or not client_id:
        return None
    return {"tenant_id": tenant_id, "client_id": client_id}


def validate_id_token(id_token: str, tenant_id: str, client_id: str):
    jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"

    if tenant_id not in _jwk_clients:
        _jwk_clients[tenant_id] = PyJWKClient(jwks_url)

    jwk_client = _jwk_clients[tenant_id]
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)

    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=client_id,
        options={"verify_iss": False}
    )

    iss = claims.get("iss", "")
    allowed_prefix = f"https://login.microsoftonline.com/{tenant_id}/"
    if not isinstance(iss, str) or not iss.startswith(allowed_prefix):
        raise ValueError("bad_issuer")

    tid = claims.get("tid")
    if tid != tenant_id:
        raise ValueError("tenant_mismatch")

    oid = claims.get("oid")
    if not oid:
        raise ValueError("missing_oid")

    return claims


def build_authorize_url(tenant_id: str, client_id: str, redirect_uri: str, state: str, nonce: str) -> str:
    authorize_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
    }
    return authorize_url + "?" + urlencode(params)


def exchange_code_for_tokens(tenant_id: str, client_id: str, client_secret: str, code: str, redirect_uri: str) -> dict:
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
    }
    r = requests.post(token_url, data=data, timeout=10)
    if r.status_code != 200:
        logger.error("MS /token failed: %s %s", r.status_code, r.text)
    r.raise_for_status()
    return r.json()


def generate_state_nonce() -> tuple[str, str]:
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32)


def normalize_email_from_claims(claims: dict) -> str:
    v = (
        claims.get("email")
        or claims.get("preferred_username")
        or claims.get("upn")
        or ""
    )
    return str(v).strip().lower()
