import logging
import secrets
import requests

from app.extensions import db
from app.models import User, Role


logger = logging.getLogger()


def _strip_quotes(value: str) -> str:
    if value is None:
        return ""
    v = str(value).strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        return v[1:-1].strip()
    return v


def _get_ini(app):
    return app.config.get("INI_CONFIG")


def _get_graph_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    resp = requests.post(token_url, data=data, timeout=30)
    if resp.status_code != 200:
        raise ValueError("token_request_failed")
    js = resp.json()
    token = js.get("access_token")
    if not token:
        raise ValueError("missing_access_token")
    return token


def _graph_get(url: str, access_token: str) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code != 200:
        raise ValueError("graph_request_failed")
    return resp.json()


def _get_entra_sync_config(app) -> dict:
    cfg = app.config.get("INI_CONFIG")
    if cfg is None:
        return {}

    mode = _strip_quotes(cfg.get("EntraSync", "mode", fallback=""))
    group_id = _strip_quotes(cfg.get("EntraSync", "group_id", fallback=""))
    default_role = _strip_quotes(cfg.get("EntraSync", "default_role", fallback=""))
    role_override_group_id = _strip_quotes(cfg.get("EntraSync", "role_override_group_id", fallback=""))
    role_override_role = _strip_quotes(cfg.get("EntraSync", "role_override_role", fallback=""))

    return {
        "mode": mode.lower(),
        "group_id": group_id,
        "default_role": default_role,
        "role_override_group_id": role_override_group_id,
        "role_override_role": role_override_role,
    }


def _resolve_role_id(role_name: str | None) -> int | None:
    if role_name:
        r = db.session.query(Role).filter(Role.name == role_name).first()
        if r:
            return int(r.id)
    return None


def _resolve_default_role_id(default_role: str | None) -> int | None:
    rid = _resolve_role_id(default_role)
    if rid is not None:
        return rid
    r = db.session.query(Role).order_by(Role.id.asc()).first()
    if r:
        return int(r.id)
    return None


def _collect_users_all(access_token: str) -> list:
    users = []
    url = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,mail,userPrincipalName,accountEnabled&$top=999"
    while url:
        js = _graph_get(url, access_token)
        values = js.get("value", [])
        if isinstance(values, list):
            users.extend(values)
        url = js.get("@odata.nextLink")
    return users


def _collect_users_group(access_token: str, group_id: str) -> list:
    users = []
    url = (f"https://graph.microsoft.com/v1.0/groups/{group_id}/"
           f"transitiveMembers?$select=id,displayName,mail,userPrincipalName,accountEnabled&$top=999")

    while url:
        js = _graph_get(url, access_token)
        values = js.get("value", [])
        if isinstance(values, list):
            for v in values:
                odata_type = str(v.get("@odata.type", "")).lower()
                if "user" in odata_type:
                    users.append(v)
        url = js.get("@odata.nextLink")
    return users


def _collect_user_ids_group(access_token: str, group_id: str) -> set:
    ids = set()
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/transitiveMembers?$select=id&$top=999"
    while url:
        js = _graph_get(url, access_token)
        values = js.get("value", [])
        if isinstance(values, list):
            for v in values:
                odata_type = str(v.get("@odata.type", "")).lower()
                if "user" in odata_type:
                    oid = str(v.get("id") or "").strip()
                    if oid:
                        ids.add(oid)
        url = js.get("@odata.nextLink")
    return ids


def _normalize_email(mail: str | None, upn: str | None, allow_upn: bool) -> str:
    v = (mail or "").strip().lower()
    if v:
        return v
    if not allow_upn:
        return ""
    v = (upn or "").strip().lower()
    if "@" in v:
        return v
    return ""


def _lower_email(value: str | None) -> str:
    return (value or "").strip().lower()


def sync_entra_users(app) -> dict:
    created = 0
    updated = 0
    skipped = 0
    errors = 0

    cfg = _get_ini(app)
    if cfg is None:
        raise ValueError("missing_ini_config")

    tenant_id = _strip_quotes(cfg.get("MicrosoftAuth", "tenant_id", fallback=""))
    client_id = _strip_quotes(cfg.get("MicrosoftAuth", "client_id", fallback=""))
    client_secret = _strip_quotes(cfg.get("MicrosoftAuth", "client_secret", fallback=""))
    if not tenant_id or not client_id or not client_secret:
        raise ValueError("missing_microsoft_auth_config")

    sync_cfg = _get_entra_sync_config(app)
    mode = (sync_cfg.get("mode") or "group").lower().strip()
    group_id = (sync_cfg.get("group_id") or "").strip()
    default_role_name = (sync_cfg.get("default_role") or "").strip()

    access_token = _get_graph_access_token(tenant_id, client_id, client_secret)
    default_role_id = _resolve_default_role_id(default_role_name)
    if default_role_id is None:
        raise ValueError("no_role_available")

    override_group_id = (sync_cfg.get("role_override_group_id") or "").strip()
    override_role_name = (sync_cfg.get("role_override_role") or "").strip()
    override_role_id = _resolve_role_id(override_role_name) if override_group_id and override_role_name else None
    override_oids = set()

    if mode == "group" and override_group_id and override_role_id:
        override_oids = _collect_user_ids_group(access_token, override_group_id)

    if mode == "all":
        ms_users = _collect_users_all(access_token)
    else:
        if not group_id:
            raise ValueError("missing_group_id")
        ms_users = _collect_users_group(access_token, group_id)

    for msu in ms_users:
        try:
            microsoft_oid = str(msu.get("id") or "").strip()
            if not microsoft_oid:
                skipped += 1
                continue

            email = _normalize_email(msu.get("mail"), msu.get("userPrincipalName"), allow_upn=(mode == "group"))
            if not email:
                skipped += 1
                continue

            display_name = str(msu.get("displayName") or "").strip()
            account_enabled = msu.get("accountEnabled")
            is_active = True if account_enabled is None else bool(account_enabled)
            effective_role_id = override_role_id if (
                        mode == "group" and override_role_id and microsoft_oid in override_oids) else default_role_id

            local = User.query.filter(User.microsoft_tid == tenant_id, User.microsoft_oid == microsoft_oid).first()
            if local:
                changed = False

                if _lower_email(local.email) != email:
                    local.email = email
                    changed = True

                if display_name and (local.name or "").strip() != display_name:
                    local.name = display_name
                    changed = True

                if local.is_active != is_active:
                    local.is_active = is_active
                    changed = True

                if local.role_id != effective_role_id:
                    local.role_id = effective_role_id
                    changed = True

                if changed:
                    db.session.commit()
                    updated += 1
                else:
                    skipped += 1
                continue

            local_by_email = User.query.filter(User.email.ilike(email)).first()
            if local_by_email:
                if local_by_email.microsoft_oid and local_by_email.microsoft_oid != microsoft_oid:
                    skipped += 1
                    continue

                changed = False

                if local_by_email.microsoft_tid != tenant_id:
                    local_by_email.microsoft_tid = tenant_id
                    changed = True

                if local_by_email.microsoft_oid != microsoft_oid:
                    local_by_email.microsoft_oid = microsoft_oid
                    changed = True

                if display_name and (local_by_email.name or "").strip() != display_name:
                    local_by_email.name = display_name
                    changed = True

                if local_by_email.is_active != is_active:
                    local_by_email.is_active = is_active
                    changed = True

                if local_by_email.role_id != effective_role_id:
                    local_by_email.role_id = effective_role_id
                    changed = True

                if changed:
                    db.session.commit()
                    updated += 1
                else:
                    skipped += 1
                continue

            # noinspection PyArgumentList
            user = User(email=email)
            user.set_password(secrets.token_urlsafe(32))
            user.name = display_name if display_name else None
            user.is_active = is_active
            user.microsoft_tid = tenant_id
            user.microsoft_oid = microsoft_oid
            user.role_id = effective_role_id

            db.session.add(user)
            db.session.commit()
            created += 1

        except Exception as e:
            logger.error(f"sync_entra_users: {str(e)}")
            db.session.rollback()
            errors += 1

    return {"created": created, "updated": updated, "skipped": skipped, "errors": errors}
