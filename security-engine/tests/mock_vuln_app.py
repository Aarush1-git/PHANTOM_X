"""
Mock vulnerable FastAPI application used exclusively by the PHANTOM-X test suite.

Endpoints:
  GET /vuln/bookings/{id}    - BOLA-vulnerable: returns any booking for any valid token.
  GET /secure/bookings/{id}  - Secure: 403 unless the token owner matches the booking owner.
  GET /public/bookings/{id}  - Public: no auth required.
  GET /flaky/bookings/{id}   - Vulnerable on the very first request, 403 afterward
                               (tests that proof engine rejects flaky findings).

Token → user mapping:
  "Bearer tokA"  → user_id=1
  "Bearer tokB"  → user_id=2

Booking → owner mapping:
  booking 101 owned by user 1
  booking 102 owned by user 2

The app binds exclusively to 127.0.0.1 so the safety policy allowlist is satisfied.
"""

from fastapi import FastAPI, Header, HTTPException, Response
from typing import Optional

app = FastAPI(title="PHANTOM-X Mock Vulnerable App")

# ── Static data ───────────────────────────────────────────────────────────────
TOKENS = {
    "Bearer tokA": 1,
    "Bearer tokB": 2,
}

BOOKINGS = {
    101: {"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3},
    102: {"id": 102, "owner_id": 2, "destination": "Tokyo", "nights": 7},
}


def _get_user(authorization: Optional[str]) -> int:
    """Resolve a bearer token to a user_id, raising 401 on failure."""
    if authorization not in TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return TOKENS[authorization]


def _get_booking(booking_id: int) -> dict:
    """Return booking data or raise 404."""
    if booking_id not in BOOKINGS:
        raise HTTPException(status_code=404, detail="Booking not found")
    return BOOKINGS[booking_id]


# ── BOLA-vulnerable endpoint ──────────────────────────────────────────────────
@app.get("/vuln/bookings/{booking_id}")
async def vuln_get_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """Returns ANY booking to any authenticated user (BOLA vulnerable)."""
    _get_user(authorization)   # validates token; ignores ownership
    return _get_booking(booking_id)


# ── Secure endpoint ───────────────────────────────────────────────────────────
@app.get("/secure/bookings/{booking_id}")
async def secure_get_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """Returns the booking ONLY if the token owner matches the booking owner."""
    user_id = _get_user(authorization)
    booking = _get_booking(booking_id)
    if booking["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return booking


# ── Public endpoint ───────────────────────────────────────────────────────────
@app.get("/public/bookings/{booking_id}")
async def public_get_booking(booking_id: int):
    """Returns booking data to anyone, no auth required."""
    return _get_booking(booking_id)


# ── Flaky endpoint ────────────────────────────────────────────────────────────
_flaky_hits: dict = {}


@app.get("/flaky/bookings/{booking_id}")
async def flaky_get_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """
    Vulnerable only on the first request per (booking_id, user) pair.
    Subsequent requests return 403, simulating a race-condition / flaky bug
    that the proof engine must reject (reproducibility < 1.0).
    """
    user_id = _get_user(authorization)
    key = (booking_id, user_id)
    if key not in _flaky_hits:
        _flaky_hits[key] = 0
    _flaky_hits[key] += 1

    booking = _get_booking(booking_id)
    if _flaky_hits[key] == 1 and booking["owner_id"] != user_id:
        # First cross-user access leaks the booking
        return booking
    if booking["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return booking



@app.get("/leaky/bookings/{booking_id}")
async def leaky_get_booking(
    booking_id: int,
    response: Response,
    authorization: Optional[str] = Header(default=None),
):
    """BOLA-vulnerable AND leaks credentials (cookie + token field) in the response."""
    _get_user(authorization)
    booking = dict(_get_booking(booking_id))
    booking["access_token"] = "SECRET-TOKEN-XYZ"
    response.set_cookie("session", "SECRET-COOKIE-123")
    return booking


# =============================================================================
# TENANT & RBAC ADDITIONS
# New tokens, identities and endpoints added for tenant isolation / RBAC tests.
# Existing TOKENS dict is NOT changed; new entries are merged in below.
# =============================================================================

TOKENS.update({
    "Bearer adminTok": 3,
    "Bearer custTok": 4,
})

IDENTITIES = {
    1: {"user_id": 1, "tenant": "agencyA", "role": "agent"},
    2: {"user_id": 2, "tenant": "agencyB", "role": "agent"},
    3: {"user_id": 3, "tenant": "agencyA", "role": "admin"},
    4: {"user_id": 4, "tenant": "agencyA", "role": "customer"},
}

TENANT_BOOKINGS = {
    201: {"id": 201, "tenant_id": "agencyA", "destination": "Paris"},
    202: {"id": 202, "tenant_id": "agencyB", "destination": "Tokyo"},
}

# Counter for DELETE calls (never actually mutates data; lets tests assert the
# safety policy blocked the request before it arrived here).
DELETE_CALLS: int = 0


def _get_identity(authorization: Optional[str]) -> dict:
    """Resolve token → full identity dict; raises 401 for unknown/missing tokens."""
    if authorization not in TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return IDENTITIES[TOKENS[authorization]]


def _get_tenant_booking(booking_id: int) -> dict:
    if booking_id not in TENANT_BOOKINGS:
        raise HTTPException(status_code=404, detail="Booking not found")
    return TENANT_BOOKINGS[booking_id]


# ── Tenant: vulnerable object endpoint ───────────────────────────────────────
@app.get("/tenant/vuln/bookings/{booking_id}")
async def tenant_vuln_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """Returns ANY tenant booking to any authenticated user (cross-tenant leak)."""
    _get_identity(authorization)
    return _get_tenant_booking(booking_id)


# ── Tenant: secure object endpoint ───────────────────────────────────────────
@app.get("/tenant/secure/bookings/{booking_id}")
async def tenant_secure_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """Returns booking only if caller's tenant matches booking's tenant_id."""
    identity = _get_identity(authorization)
    booking = _get_tenant_booking(booking_id)
    if identity["tenant"] != booking["tenant_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return booking


# ── Tenant: public object endpoint ───────────────────────────────────────────
@app.get("/tenant/public/bookings/{booking_id}")
async def tenant_public_booking(booking_id: int):
    """Returns booking to anyone; no auth required."""
    return _get_tenant_booking(booking_id)


# ── Tenant: spoof endpoint (honours X-Tenant-ID header) ──────────────────────
@app.get("/tenant/spoof/bookings/{booking_id}")
async def tenant_spoof_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
    x_tenant_id: Optional[str] = Header(default=None),
):
    """
    Derives tenant from X-Tenant-ID header if present, else from token.
    Returns 403 when the resolved tenant != booking tenant_id.
    This is intentionally vulnerable to tenant-header spoofing.
    """
    identity = _get_identity(authorization)
    effective_tenant = x_tenant_id if x_tenant_id is not None else identity["tenant"]
    booking = _get_tenant_booking(booking_id)
    if effective_tenant != booking["tenant_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return booking


# ── Tenant: vulnerable collection endpoint ────────────────────────────────────
@app.get("/tenant/vuln/bookings")
async def tenant_vuln_bookings(
    authorization: Optional[str] = Header(default=None),
):
    """Returns ALL bookings to any authenticated user (cross-tenant collection leak)."""
    _get_identity(authorization)
    return list(TENANT_BOOKINGS.values())


# ── Tenant: secure collection endpoint ───────────────────────────────────────
@app.get("/tenant/secure/bookings")
async def tenant_secure_bookings(
    authorization: Optional[str] = Header(default=None),
):
    """Returns only the caller's tenant bookings."""
    identity = _get_identity(authorization)
    return [b for b in TENANT_BOOKINGS.values() if b["tenant_id"] == identity["tenant"]]


# ── RBAC: vulnerable admin endpoint (GET) ────────────────────────────────────
@app.get("/rbac/vuln/admin/users")
async def rbac_vuln_users(
    authorization: Optional[str] = Header(default=None),
):
    """Returns user list to ANY authenticated caller (RBAC vulnerable)."""
    _get_identity(authorization)
    return [{"id": 1, "email": "a@x.test"}, {"id": 2, "email": "b@x.test"}]


# ── RBAC: secure admin endpoint (GET) ────────────────────────────────────────
@app.get("/rbac/secure/admin/users")
async def rbac_secure_users(
    authorization: Optional[str] = Header(default=None),
):
    """Returns user list only to admin-role callers; 403 otherwise."""
    identity = _get_identity(authorization)
    if identity["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return [{"id": 1, "email": "a@x.test"}, {"id": 2, "email": "b@x.test"}]


# ── RBAC: public admin endpoint (GET) ────────────────────────────────────────
@app.get("/rbac/public/admin/users")
async def rbac_public_users():
    """Returns user list to anyone; no auth required."""
    return [{"id": 1, "email": "a@x.test"}, {"id": 2, "email": "b@x.test"}]


# ── RBAC: vulnerable DELETE endpoint ─────────────────────────────────────────
@app.delete("/rbac/vuln/users/{user_id}")
async def rbac_vuln_delete_user(
    user_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """
    Accepts DELETE from any authenticated caller (RBAC vulnerable).
    Does NOT mutate any data; increments DELETE_CALLS so tests can assert
    whether the request reached the application layer.
    """
    global DELETE_CALLS
    _get_identity(authorization)
    DELETE_CALLS += 1
    return {"deleted": user_id}


# =============================================================================
# TENANT & RBAC ADDITIONS
# New tokens, identities and endpoints added for tenant isolation / RBAC tests.
# Existing TOKENS dict is NOT changed; new entries are merged in below.
# =============================================================================

TOKENS.update({
    "Bearer adminTok": 3,
    "Bearer custTok": 4,
})

IDENTITIES = {
    1: {"user_id": 1, "tenant": "agencyA", "role": "agent"},
    2: {"user_id": 2, "tenant": "agencyB", "role": "agent"},
    3: {"user_id": 3, "tenant": "agencyA", "role": "admin"},
    4: {"user_id": 4, "tenant": "agencyA", "role": "customer"},
}

TENANT_BOOKINGS = {
    201: {"id": 201, "tenant_id": "agencyA", "destination": "Paris"},
    202: {"id": 202, "tenant_id": "agencyB", "destination": "Tokyo"},
}

# Counter for DELETE calls (never actually mutates data; lets tests assert the
# safety policy blocked the request before it arrived here).
DELETE_CALLS: int = 0


def _get_identity(authorization: Optional[str]) -> dict:
    """Resolve token → full identity dict; raises 401 for unknown/missing tokens."""
    if authorization not in TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return IDENTITIES[TOKENS[authorization]]


def _get_tenant_booking(booking_id: int) -> dict:
    if booking_id not in TENANT_BOOKINGS:
        raise HTTPException(status_code=404, detail="Booking not found")
    return TENANT_BOOKINGS[booking_id]


# ── Tenant: vulnerable object endpoint ───────────────────────────────────────
@app.get("/tenant/vuln/bookings/{booking_id}")
async def tenant_vuln_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """Returns ANY tenant booking to any authenticated user (cross-tenant leak)."""
    _get_identity(authorization)
    return _get_tenant_booking(booking_id)


# ── Tenant: secure object endpoint ───────────────────────────────────────────
@app.get("/tenant/secure/bookings/{booking_id}")
async def tenant_secure_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """Returns booking only if caller's tenant matches booking's tenant_id."""
    identity = _get_identity(authorization)
    booking = _get_tenant_booking(booking_id)
    if identity["tenant"] != booking["tenant_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return booking


# ── Tenant: public object endpoint ───────────────────────────────────────────
@app.get("/tenant/public/bookings/{booking_id}")
async def tenant_public_booking(booking_id: int):
    """Returns booking to anyone; no auth required."""
    return _get_tenant_booking(booking_id)


# ── Tenant: spoof endpoint (honours X-Tenant-ID header) ──────────────────────
@app.get("/tenant/spoof/bookings/{booking_id}")
async def tenant_spoof_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
    x_tenant_id: Optional[str] = Header(default=None),
):
    """
    Derives tenant from X-Tenant-ID header if present, else from token.
    Returns 403 when the resolved tenant != booking tenant_id.
    This is intentionally vulnerable to tenant-header spoofing.
    """
    identity = _get_identity(authorization)
    effective_tenant = x_tenant_id if x_tenant_id is not None else identity["tenant"]
    booking = _get_tenant_booking(booking_id)
    if effective_tenant != booking["tenant_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return booking


# ── Tenant: vulnerable collection endpoint ────────────────────────────────────
@app.get("/tenant/vuln/bookings")
async def tenant_vuln_bookings(
    authorization: Optional[str] = Header(default=None),
):
    """Returns ALL bookings to any authenticated user (cross-tenant collection leak)."""
    _get_identity(authorization)
    return list(TENANT_BOOKINGS.values())


# ── Tenant: secure collection endpoint ───────────────────────────────────────
@app.get("/tenant/secure/bookings")
async def tenant_secure_bookings(
    authorization: Optional[str] = Header(default=None),
):
    """Returns only the caller's tenant bookings."""
    identity = _get_identity(authorization)
    return [b for b in TENANT_BOOKINGS.values() if b["tenant_id"] == identity["tenant"]]


# ── RBAC: vulnerable admin endpoint (GET) ────────────────────────────────────
@app.get("/rbac/vuln/admin/users")
async def rbac_vuln_users(
    authorization: Optional[str] = Header(default=None),
):
    """Returns user list to ANY authenticated caller (RBAC vulnerable)."""
    _get_identity(authorization)
    return [{"id": 1, "email": "a@x.test"}, {"id": 2, "email": "b@x.test"}]


# ── RBAC: secure admin endpoint (GET) ────────────────────────────────────────
@app.get("/rbac/secure/admin/users")
async def rbac_secure_users(
    authorization: Optional[str] = Header(default=None),
):
    """Returns user list only to admin-role callers; 403 otherwise."""
    identity = _get_identity(authorization)
    if identity["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return [{"id": 1, "email": "a@x.test"}, {"id": 2, "email": "b@x.test"}]


# ── RBAC: public admin endpoint (GET) ────────────────────────────────────────
@app.get("/rbac/public/admin/users")
async def rbac_public_users():
    """Returns user list to anyone; no auth required."""
    return [{"id": 1, "email": "a@x.test"}, {"id": 2, "email": "b@x.test"}]


# ── RBAC: vulnerable DELETE endpoint ─────────────────────────────────────────
@app.delete("/rbac/vuln/users/{user_id}")
async def rbac_vuln_delete_user(
    user_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """
    Accepts DELETE from any authenticated caller (RBAC vulnerable).
    Does NOT mutate any data; increments DELETE_CALLS so tests can assert
    whether the request reached the application layer.
    """
    global DELETE_CALLS
    _get_identity(authorization)
    DELETE_CALLS += 1
    return {"deleted": user_id}


# ── Cache check endpoint ─────────────────────────────────────────────────────
@app.get("/cache/vuln/bookings/{booking_id}")
async def cache_vuln_get_booking(
    booking_id: int,
    response: Response,
    authorization: Optional[str] = Header(default=None),
):
    """Like /vuln but adds response headers Age: 30 and X-Cache: HIT."""
    _get_user(authorization)
    booking = _get_booking(booking_id)
    response.headers["Age"] = "30"
    response.headers["X-Cache"] = "HIT"
    return booking


# ── Lenient auth endpoint ────────────────────────────────────────────────────
@app.get("/lenient/bookings/{booking_id}")
async def lenient_get_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """401 if there is no Authorization header at all; ANY value -> returns the booking."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return _get_booking(booking_id)


# ── Partial/intermittent endpoint ────────────────────────────────────────────
_partial_hits: dict = {}


@app.get("/partial/bookings/{booking_id}")
async def partial_get_booking(
    booking_id: int,
    authorization: Optional[str] = Header(default=None),
):
    """
    Cross-user requests are counted per (booking_id, user_id); every 3rd one
    returns 403, the others return the booking; owner requests are never counted.
    """
    user_id = _get_user(authorization)
    booking = _get_booking(booking_id)
    if user_id != booking["owner_id"]:
        key = (booking_id, user_id)
        _partial_hits[key] = _partial_hits.get(key, 0) + 1
        if _partial_hits[key] % 3 == 0:
            raise HTTPException(status_code=403, detail="Forbidden")
    return booking


# ── Feature 17: Authentication endpoints ─────────────────────────────────────
_authn_flaky_hits: int = 0


@app.get("/authn/secure/profile")
async def authn_secure_profile(authorization: Optional[str] = Header(default=None)):
    if authorization == "Bearer tokA":
        return {"id": 1, "email": "a@x.test"}
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/authn/missing/profile")
async def authn_missing_profile():
    return {"id": 1, "email": "a@x.test"}


@app.get("/authn/lax/profile")
async def authn_lax_profile(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.strip():
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.strip()
    if token == "Bearer":
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Reject JWTs so unsigned_jwt is not accepted (CWE-287 is tested via bearer_null / garbage_token)
    if "eyJ" in token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"id": 1, "email": "a@x.test"}


@app.get("/authn/jwtnone/profile")
async def authn_jwtnone_profile(authorization: Optional[str] = Header(default=None)):
    if authorization == "Bearer tokA":
        return {"id": 1, "email": "a@x.test"}
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        parts = token.split(".")
        if len(parts) == 3 and parts[2] == "":
            return {"id": 1, "email": "a@x.test"}
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/authn/flaky/profile")
async def authn_flaky_profile(authorization: Optional[str] = Header(default=None)):
    global _authn_flaky_hits
    if not authorization:
        _authn_flaky_hits += 1
        if _authn_flaky_hits == 1:
            return {"id": 1, "email": "a@x.test"}
        raise HTTPException(status_code=401, detail="Unauthorized")
    if authorization == "Bearer tokA":
        return {"id": 1, "email": "a@x.test"}
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/authn/public/info")
async def authn_public_info():
    return {"info": "public"}


# ── Feature 17: Input validation endpoints ───────────────────────────────────
_validate_flaky_seen: set = set()


@app.get("/validate/secure/items")
async def validate_secure_items(id: Optional[str] = None):
    if id is not None and id.isdigit():
        return {"id": int(id)}
    raise HTTPException(status_code=422, detail="invalid id")


@app.get("/validate/vuln/items")
async def validate_vuln_items(id: Optional[str] = None):
    if id is not None and id.isdigit():
        return {"id": int(id)}
    # Trigger 500 with stack trace disclosure
    return Response(
        content="Traceback (most recent call last)\nValueError: invalid literal for int()",
        status_code=500,
        media_type="text/plain",
    )


@app.get("/validate/500only/items")
async def validate_500only_items(id: Optional[str] = None):
    if id is not None and id.isdigit():
        return {"id": int(id)}
    return Response(
        content="Internal Server Error",
        status_code=500,
        media_type="text/plain",
    )


@app.get("/validate/flaky/items")
async def validate_flaky_items(id: Optional[str] = None):
    global _validate_flaky_seen
    if id is not None and id.isdigit():
        return {"id": int(id)}
    if id not in _validate_flaky_seen:
        _validate_flaky_seen.add(id)
        return Response(
            content="Internal Server Error",
            status_code=500,
            media_type="text/plain",
        )
    raise HTTPException(status_code=422, detail="invalid id")


@app.get("/validate/ratelimited/items")
async def validate_ratelimited_items(id: Optional[str] = None):
    if id is not None and id.isdigit():
        return {"id": int(id)}
    raise HTTPException(status_code=429, detail="Rate limit exceeded")


# ── Feature 17: CORS and HTTP Methods endpoints ──────────────────────────────
@app.get("/cors/vuln/data")
async def cors_vuln_data(response: Response, origin: Optional[str] = Header(default=None)):
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return {"data": "cors_vuln"}


@app.get("/cors/reflect-nocreds/data")
async def cors_reflect_nocreds_data(response: Response, origin: Optional[str] = Header(default=None)):
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
    return {"data": "cors_reflect_nocreds"}


@app.get("/cors/wildcard/data")
async def cors_wildcard_data(response: Response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return {"data": "cors_wildcard"}


@app.get("/cors/secure/data")
async def cors_secure_data():
    return {"data": "cors_secure"}


@app.options("/methods/vuln/thing")
async def methods_vuln_thing(response: Response):
    response.headers["Allow"] = "GET, HEAD, OPTIONS, TRACE, DELETE"
    return Response(status_code=200, headers={"Allow": "GET, HEAD, OPTIONS, TRACE, DELETE"})


@app.options("/methods/secure/thing")
async def methods_secure_thing(response: Response):
    response.headers["Allow"] = "GET, HEAD, OPTIONS"
    return Response(status_code=200, headers={"Allow": "GET, HEAD, OPTIONS"})


def reset_counters():
    """Clears the /flaky, /partial, and feature 17 counters."""
    global _flaky_hits, _partial_hits, _authn_flaky_hits, _validate_flaky_seen
    _flaky_hits.clear()
    _partial_hits.clear()
    _authn_flaky_hits = 0
    _validate_flaky_seen.clear()
