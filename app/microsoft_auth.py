import time
import requests
import jwt
from jwt import PyJWKClient

_jwk_clients = {}


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
