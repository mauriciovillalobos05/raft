"""HTTP Basic identities and short-lived, server-side browser sessions."""
import secrets
import threading
import time
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from security.auth import get_auth, hash_password, verify_password, Principal

basic = HTTPBasic(auto_error=False)
COOKIE = "__Host-raft-session"
_sessions = {}
_lock = threading.Lock()
_dummy_hash = hash_password(secrets.token_urlsafe(24))


def authenticate(credentials: HTTPBasicCredentials | None = Depends(basic)):
    users = get_auth().users
    user = users.get(credentials.username) if credentials else None
    valid = verify_password(credentials.password if credentials else "", user["password_hash"] if user else _dummy_hash)
    if not credentials or not user or not valid:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Basic"})
    return Principal(credentials.username, user["role"])


def require(*roles):
    def check(principal=Depends(authenticate)):
        if principal.role not in roles:
            raise HTTPException(403, "Operation forbidden")
        return principal
    return check


def check_origin(origin):
    if origin not in get_auth().origins:
        raise HTTPException(403, "Origin forbidden")


def create_session(principal):
    now = time.time()
    token = secrets.token_urlsafe(32)
    with _lock:
        for old, (_, expiry) in list(_sessions.items()):
            if expiry <= now:
                del _sessions[old]
        # Bound memory even when a valid account creates many sessions.
        if len(_sessions) >= 1000:
            del _sessions[next(iter(_sessions))]
        _sessions[token] = (principal, now + get_auth().session_ttl)
    return token


def session_principal(token):
    with _lock:
        item = _sessions.get(token)
        if not item:
            return None
        principal, expiry = item
        user = get_auth().users.get(principal.identity)
        if expiry <= time.time() or not user or user["role"] != principal.role:
            _sessions.pop(token, None)
            return None
        return principal


def revoke_session(token):
    with _lock:
        _sessions.pop(token, None)
