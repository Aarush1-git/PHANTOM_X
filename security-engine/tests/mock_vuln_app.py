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