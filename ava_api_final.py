"""
AVA API v5  —  Atom Vanguard Array
════════════════════════════════════════════════════════════
Changes from v4:
  • bcrypt password hashing (replaces SHA-256 + fixed salt)
  • CORS locked to env-configurable origin whitelist
  • Login rate-limiting (5 attempts / 10 min per discord_id)
  • New panel routes:
      POST /panel/{guild_id}/start      — mark task started
      POST /panel/{guild_id}/cancel     — mark task cancelled
      GET  /panel/{guild_id}/task/{otp} — full task detail (notes, due, tags, history)
  • Cross-server assignment:
      POST /panel/{guild_id}/assign     — assign OTP to staff in ANY registered guild
      GET  /panel/{guild_id}/crossstaff — list all staff across all guilds (for selector)
  • _svc() serialiser now includes notes, tags, due_date, source_guild_name
  • API key split: BOT_KEY (full access) vs PANEL_KEY (Lua — login + session only)
  • All DB writes use proper $push history entries
  • Version bump → 5.0.0
════════════════════════════════════════════════════════════
"""

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import pymongo
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import os
import secrets
import time
import bcrypt

# ════════════════════════════════════════════════════════════
#  CONFIG  (all via environment variables)
# ════════════════════════════════════════════════════════════
MONGO_URI           = os.getenv("MONGO_URI",       "YOUR_MONGO_URI_HERE")
BOT_API_KEY         = os.getenv("BOT_API_KEY",     "ava_bot_secret_change_this")
PANEL_API_KEY       = os.getenv("PANEL_API_KEY",   "ava_panel_secret_change_this")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL", "3600"))   # 1 hour sliding

# CORS — comma-separated origins e.g. "https://yourdomain.com,https://panel.yourdomain.com"
# Leave blank to allow all (dev only — NOT for production)
_CORS_RAW    = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _CORS_RAW.split(",") if o.strip()] or ["*"]

# Rate limit: max login attempts per discord_id in the window
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECS  = int(os.getenv("LOGIN_WINDOW_SECS",  "600"))  # 10 minutes

# ════════════════════════════════════════════════════════════
#  DATABASE
# ════════════════════════════════════════════════════════════
mc               = pymongo.MongoClient(MONGO_URI)
db               = mc["ava_services"]
services_coll    = db["services"]
roblox_coll      = db["roblox_accounts"]
config_coll      = db["guild_configs"]
notes_coll       = db["service_notes"]
sessions_coll    = db["panel_sessions"]
credentials_coll = db["panel_credentials"]
rate_coll        = db["login_rate_limits"]

try:
    sessions_coll.create_index("expires_at",  expireAfterSeconds=0)
    rate_coll.create_index("expires_at",       expireAfterSeconds=0)
    credentials_coll.create_index("discord_id", unique=True)
    roblox_coll.create_index([("discord_id", 1), ("guild_id", 1)], unique=True)
    services_coll.create_index([("assigned_id", 1), ("guild_id", 1)])
    services_coll.create_index([("roblox_username", 1), ("guild_id", 1)])
    services_coll.create_index("otp", unique=True)
except Exception:
    pass

# ════════════════════════════════════════════════════════════
#  APP
# ════════════════════════════════════════════════════════════
app = FastAPI(title="AVA API", version="5.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
)

# ════════════════════════════════════════════════════════════
#  PASSWORD HASHING  (bcrypt — work factor 12)
# ════════════════════════════════════════════════════════════
def _hash_password(password: str) -> str:
    """Hash a plain-text password with bcrypt. Returns the stored hash string."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plain-text password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except Exception:
        return False

# ════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ════════════════════════════════════════════════════════════
def _make_token() -> str:
    return secrets.token_urlsafe(40)

def verify_bot_key(x_api_key: str = Header(...)):
    """Full-access key — bot only."""
    if x_api_key != BOT_API_KEY:
        raise HTTPException(403, "Invalid bot API key.")

def verify_panel_key(x_api_key: str = Header(...)):
    """
    Panel key — used by Lua. Only allows login & session endpoints.
    Accepts either PANEL_API_KEY (Lua) or BOT_API_KEY (bot internal calls).
    """
    if x_api_key not in (PANEL_API_KEY, BOT_API_KEY):
        raise HTTPException(403, "Invalid API key.")

def require_session(x_session_token: str = Header(...)) -> dict:
    """Validates a panel session token. Returns the session doc."""
    now     = datetime.now(timezone.utc)
    session = sessions_coll.find_one({"token": x_session_token})
    if not session:
        raise HTTPException(401, "Invalid or expired session. Please log in again.")
    exp = session.get("expires_at")
    if exp and exp.replace(tzinfo=timezone.utc) < now:
        sessions_coll.delete_one({"token": x_session_token})
        raise HTTPException(401, "Session expired. Please log in again.")
    # Slide expiry on activity
    new_exp = now + timedelta(seconds=SESSION_TTL_SECONDS)
    sessions_coll.update_one(
        {"token": x_session_token},
        {"$set": {"expires_at": new_exp, "last_active": now}}
    )
    return session

# ════════════════════════════════════════════════════════════
#  LOGIN RATE LIMITER
# ════════════════════════════════════════════════════════════
def _check_rate_limit(discord_id: int):
    """
    Allows LOGIN_MAX_ATTEMPTS per LOGIN_WINDOW_SECS per discord_id.
    Raises 429 if exceeded. Uses MongoDB TTL collection so it auto-clears.
    """
    now        = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=LOGIN_WINDOW_SECS)
    doc_id     = str(discord_id)

    doc = rate_coll.find_one({"_id": doc_id})
    if doc:
        attempts = [t for t in doc.get("attempts", [])
                    if t.replace(tzinfo=timezone.utc) > window_start]
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            retry_after = int(
                (attempts[0].replace(tzinfo=timezone.utc) + timedelta(seconds=LOGIN_WINDOW_SECS)
                 - now).total_seconds()
            )
            raise HTTPException(
                429,
                f"Too many login attempts. Try again in {retry_after}s."
            )
        attempts.append(now)
        rate_coll.update_one(
            {"_id": doc_id},
            {"$set": {"attempts": attempts, "expires_at": now + timedelta(seconds=LOGIN_WINDOW_SECS)}}
        )
    else:
        rate_coll.insert_one({
            "_id":        doc_id,
            "attempts":   [now],
            "expires_at": now + timedelta(seconds=LOGIN_WINDOW_SECS)
        })

def _clear_rate_limit(discord_id: int):
    """Clear rate limit on successful login."""
    rate_coll.delete_one({"_id": str(discord_id)})

# ════════════════════════════════════════════════════════════
#  MODELS
# ════════════════════════════════════════════════════════════
class LoginBody(BaseModel):
    discord_id: int
    password:   str

    @field_validator("password")
    @classmethod
    def pw_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("Password cannot be empty.")
        return v

class SetPasswordBody(BaseModel):
    discord_id: int
    password:   str
    guild_id:   int

    @field_validator("password")
    @classmethod
    def pw_length(cls, v):
        if len(v) < 4:  raise ValueError("Password too short (min 4).")
        if len(v) > 32: raise ValueError("Password too long (max 32).")
        if " " in v:    raise ValueError("Password cannot contain spaces.")
        return v

class OTPBody(BaseModel):
    otp: str

class AssignBody(BaseModel):
    otp:              str
    target_discord_id: int   # staff member to assign to
    target_guild_id:  int    # their home guild

class NoteBody(BaseModel):
    otp:  str
    note: str

class RegisterBody(BaseModel):
    discord_id:      int
    guild_id:        int
    guild_name:      str  = ""
    roblox_username: str
    roblox_id:       int  = 0
    display_name:    str  = ""
    designation:     str  = "Staff"
    server_name:     str  = ""

# ════════════════════════════════════════════════════════════
#  SERIALISERS
# ════════════════════════════════════════════════════════════
def _svc(s: dict, include_notes: bool = False) -> dict:
    """Serialise a service document. Optionally includes notes from notes_coll."""
    out = {
        "otp":              s.get("otp", ""),
        "name":             s.get("name", ""),
        "value":            s.get("value", ""),
        "status":           s.get("status", "pending"),
        "priority":         s.get("priority", "normal"),
        "roblox_username":  s.get("roblox_username", ""),
        "assigned_id":      s.get("assigned_id"),
        "guild_id":         s.get("guild_id"),
        "tags":             s.get("tags", []),
        "due_date":         s["due_date"].isoformat() if s.get("due_date") else None,
        "created_at":       s["created_at"].isoformat() if s.get("created_at") else None,
        "updated_at":       s["updated_at"].isoformat() if s.get("updated_at") else None,
        # Cross-guild: source server name stored at creation time
        "source_guild_name": s.get("source_guild_name", ""),
        "source_guild_id":   s.get("source_guild_id"),
    }
    if include_notes:
        raw_notes = list(notes_coll.find(
            {"otp": s.get("otp", "")},
            {"_id": 0}
        ).sort("created_at", 1))
        out["notes"] = [
            {
                "author_id":  n.get("author_id"),
                "note":       n.get("note", ""),
                "created_at": n["created_at"].isoformat() if n.get("created_at") else None,
            }
            for n in raw_notes
        ]
    return out

def _profile(a: dict) -> dict:
    return {
        "discord_id":      a.get("discord_id"),
        "roblox_username": a.get("roblox_username", ""),
        "roblox_id":       a.get("roblox_id", 0),
        "display_name":    a.get("display_name") or a.get("roblox_username", ""),
        "designation":     a.get("designation", "Client"),
        "server_name":     a.get("server_name", "AVA Services"),
        "guild_id":        a.get("guild_id"),
        "guild_name":      a.get("guild_name", ""),
    }

DESIG_RANK = {
    "Developer & Owner": 5,
    "Server Owner":      4,
    "AVA Admin":         3,
    "Staff":             2,
    "Client":            1,
}

# ════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════
def _now() -> datetime:
    return datetime.now(timezone.utc)

def _ts(dt: datetime) -> datetime:
    """Ensure datetime is UTC-aware."""
    if dt is None:
        return _now()
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

def _history_entry(status: str, by: int, source: str = "roblox_panel_v5") -> dict:
    return {"status": status, "by": by, "at": _now(), "source": source}

# ════════════════════════════════════════════════════════════
#  ROUTES — Health
# ════════════════════════════════════════════════════════════
@app.get("/")
def root():
    return {"status": "AVA API online", "version": "5.0.0"}

@app.get("/health")
def health():
    """Uptime check used by Railway / monitoring."""
    return {"ok": True, "ts": _now().isoformat()}

# ════════════════════════════════════════════════════════════
#  ROUTES — Auth (PANEL_KEY gated)
# ════════════════════════════════════════════════════════════

@app.post("/auth/login", dependencies=[Depends(verify_panel_key)])
def login(body: LoginBody):
    """
    Login with Discord ID + password.
    Rate-limited: 5 attempts / 10 min per discord_id.
    Returns session token + full guild list.
    """
    # Rate limit check BEFORE DB lookup (prevents enumeration)
    _check_rate_limit(body.discord_id)

    cred = credentials_coll.find_one({"discord_id": body.discord_id})
    if not cred:
        raise HTTPException(
            404,
            "Discord ID not found. Use >setpanelpass in your Discord server first."
        )

    stored = cred.get("password_hash", "")
    # Support legacy SHA-256 hashes during migration period
    if stored.startswith("$2b$") or stored.startswith("$2a$"):
        valid = _verify_password(body.password, stored)
    else:
        # Legacy — force re-hash on success, treat as invalid for now
        raise HTTPException(
            401,
            "Your password hash is outdated. Please run >setpanelpass again in Discord."
        )

    if not valid:
        raise HTTPException(401, "Incorrect password.")

    # Successful login — clear rate limit
    _clear_rate_limit(body.discord_id)

    records = list(roblox_coll.find({"discord_id": body.discord_id}))
    if not records:
        raise HTTPException(
            404,
            "No registered servers found. Ask your admin to run >sregister for you."
        )

    guilds = [
        {
            "guild_id":    r.get("guild_id"),
            "guild_name":  r.get("guild_name", "Unknown Server"),
            "server_name": r.get("server_name", "AVA Services"),
            "designation": r.get("designation", "Client"),
            "display_name": r.get("display_name", ""),
        }
        for r in records
    ]

    primary = max(records, key=lambda r: DESIG_RANK.get(r.get("designation", "Client"), 0))

    # Kill old sessions
    sessions_coll.delete_many({"discord_id": body.discord_id})

    token = _make_token()
    now   = _now()
    sessions_coll.insert_one({
        "token":       token,
        "discord_id":  body.discord_id,
        "guild_ids":   [r.get("guild_id") for r in records],
        "created_at":  now,
        "expires_at":  now + timedelta(seconds=SESSION_TTL_SECONDS),
        "last_active": now,
    })

    return {
        "success":         True,
        "token":           token,
        "primary_profile": _profile(primary),
        "guilds":          guilds,
        "message":         f"Welcome back, {primary.get('display_name') or 'user'}!",
    }


@app.post("/auth/logout")
def logout(session: dict = Depends(require_session)):
    sessions_coll.delete_one({"token": session["token"]})
    return {"success": True, "message": "Logged out."}


@app.get("/auth/me")
def me(session: dict = Depends(require_session)):
    """Quick session check — returns current profile."""
    discord_id = session["discord_id"]
    records    = list(roblox_coll.find({"discord_id": discord_id}))
    if not records:
        raise HTTPException(404, "No records found.")
    primary = max(records, key=lambda r: DESIG_RANK.get(r.get("designation", "Client"), 0))
    guilds  = [
        {
            "guild_id":   r.get("guild_id"),
            "guild_name": r.get("guild_name", ""),
            "server_name": r.get("server_name", ""),
            "designation": r.get("designation", ""),
        }
        for r in records
    ]
    return {
        "discord_id":      discord_id,
        "primary_profile": _profile(primary),
        "guilds":          guilds,
    }

# ════════════════════════════════════════════════════════════
#  ROUTES — Panel (session gated)
# ════════════════════════════════════════════════════════════

def _get_account_or_403(discord_id: int, guild_id: int, session: dict):
    """Validate guild membership and return account doc."""
    if guild_id not in session.get("guild_ids", []):
        raise HTTPException(403, "You are not registered in this server.")
    account = roblox_coll.find_one({"discord_id": discord_id, "guild_id": guild_id})
    if not account:
        raise HTTPException(404, "Profile not found for this server.")
    return account

def _require_staff(account: dict):
    if account.get("designation", "Client") == "Client":
        raise HTTPException(403, "Staff access required.")

def _is_staff(account: dict) -> bool:
    return account.get("designation", "Client") != "Client"


# ── Full panel data ───────────────────────────────────────────
@app.get("/panel/{guild_id}")
def panel(guild_id: int, session: dict = Depends(require_session)):
    """
    Returns everything the panel needs for one guild.
    Staff: assigned tasks (with notes + due dates).
    Client: their own active orders.
    """
    discord_id = session["discord_id"]
    account    = _get_account_or_403(discord_id, guild_id, session)
    designation = account.get("designation", "Client")
    cfg         = config_coll.find_one({"guild_id": guild_id}) or {}

    if designation == "Client":
        rblx = account.get("roblox_username", "")
        svcs = list(services_coll.find({
            "roblox_username": rblx,
            "guild_id":        guild_id,
            "status":          {"$in": ["pending", "started"]},
        }).sort("created_at", -1).limit(20))
        fin = services_coll.count_documents({
            "roblox_username": rblx,
            "guild_id":        guild_id,
            "status":          "finished",
        })
        return {
            "view":    "client",
            "profile": _profile(account),
            "orders": {
                "active":         [_svc(s) for s in svcs],
                "total_active":   len(svcs),
                "total_finished": fin,
            },
        }

    # Staff — pull tasks assigned to this user across ALL guilds they belong to
    # (cross-server: assigned_id matches, regardless of guild_id)
    all_t = list(
        services_coll.find({"assigned_id": discord_id})
        .sort("created_at", -1)
        .limit(80)
    )

    # Enrich each task with source guild name
    guild_name_cache = {}
    for t in all_t:
        gid = t.get("guild_id")
        if gid and gid not in guild_name_cache:
            cfg_doc = config_coll.find_one({"guild_id": gid}) or {}
            guild_name_cache[gid] = cfg_doc.get("server_name") or t.get("source_guild_name", str(gid))
        t["source_guild_name"] = guild_name_cache.get(gid, "")

    pend = [t for t in all_t if t.get("status") == "pending"]
    start = [t for t in all_t if t.get("status") == "started"]
    fin   = [t for t in all_t if t.get("status") == "finished"]
    canc  = [t for t in all_t if t.get("status") == "cancelled"]

    return {
        "view":    "staff",
        "profile": _profile(account),
        "config": {
            "server_name": cfg.get("server_name") or account.get("server_name", "AVA Services"),
            "guild_name":  account.get("guild_name", ""),
        },
        "summary": {
            "total":     len(all_t),
            "pending":   len(pend),
            "started":   len(start),
            "finished":  len(fin),
            "cancelled": len(canc),
            "remaining": len(pend) + len(start),
            "completed": len(fin),
        },
        "tasks": {
            # Include notes + due dates inline for panel display
            "pending":  [_svc(t, include_notes=True) for t in pend],
            "started":  [_svc(t, include_notes=True) for t in start],
            "finished": [_svc(t) for t in fin[:5]],
        },
    }


# ── Single task detail ────────────────────────────────────────
@app.get("/panel/{guild_id}/task/{otp}")
def task_detail(guild_id: int, otp: str, session: dict = Depends(require_session)):
    """Full task detail including all notes, tags, history."""
    discord_id = session["discord_id"]
    account    = _get_account_or_403(discord_id, guild_id, session)
    _require_staff(account)

    svc = services_coll.find_one({"otp": otp.upper()})
    if not svc:
        raise HTTPException(404, f"OTP {otp.upper()} not found.")

    # Allow if task belongs to this guild OR is cross-assigned to this user
    if svc.get("guild_id") != guild_id and svc.get("assigned_id") != discord_id:
        raise HTTPException(403, "Access denied to this task.")

    return _svc(svc, include_notes=True)


# ── Start task ────────────────────────────────────────────────
@app.post("/panel/{guild_id}/start")
def start_task(guild_id: int, body: OTPBody, session: dict = Depends(require_session)):
    """Mark a task as started. Only the assigned staff member can do this."""
    discord_id = session["discord_id"]
    account    = _get_account_or_403(discord_id, guild_id, session)
    _require_staff(account)

    svc = services_coll.find_one({"otp": body.otp.upper()})
    if not svc:
        raise HTTPException(404, f"OTP {body.otp.upper()} not found.")

    # Cross-guild: allow if assigned to this user even if from another guild
    if svc.get("assigned_id") != discord_id:
        raise HTTPException(403, "This task is not assigned to you.")
    if svc.get("status") == "started":
        return {"success": False, "message": "Already started."}
    if svc.get("status") in ("finished", "cancelled"):
        return {"success": False, "message": f"Cannot start a {svc['status']} task."}

    services_coll.update_one(
        {"otp": body.otp.upper()},
        {
            "$set":  {"status": "started", "updated_at": _now()},
            "$push": {"history": _history_entry("started", discord_id)},
        }
    )
    return {"success": True, "message": f"{body.otp.upper()} marked as started.", "otp": body.otp.upper()}


# ── Complete task ─────────────────────────────────────────────
@app.post("/panel/{guild_id}/complete")
def complete_task(guild_id: int, body: OTPBody, session: dict = Depends(require_session)):
    """Mark a task as finished."""
    discord_id = session["discord_id"]
    account    = _get_account_or_403(discord_id, guild_id, session)
    _require_staff(account)

    svc = services_coll.find_one({"otp": body.otp.upper()})
    if not svc:
        raise HTTPException(404, f"OTP {body.otp.upper()} not found.")
    if svc.get("assigned_id") != discord_id:
        raise HTTPException(403, "This task is not assigned to you.")
    if svc.get("status") == "finished":
        return {"success": False, "message": "Already finished."}
    if svc.get("status") == "cancelled":
        return {"success": False, "message": "Cannot complete a cancelled task."}

    services_coll.update_one(
        {"otp": body.otp.upper()},
        {
            "$set":  {"status": "finished", "updated_at": _now()},
            "$push": {"history": _history_entry("finished", discord_id)},
        }
    )
    return {"success": True, "message": f"{body.otp.upper()} completed.", "otp": body.otp.upper()}


# ── Cancel task ───────────────────────────────────────────────
@app.post("/panel/{guild_id}/cancel")
def cancel_task(guild_id: int, body: OTPBody, session: dict = Depends(require_session)):
    """Cancel a task. Staff can cancel their own; Admins can cancel any in their guild."""
    discord_id  = session["discord_id"]
    account     = _get_account_or_403(discord_id, guild_id, session)
    _require_staff(account)
    is_admin    = account.get("designation") in ("AVA Admin", "Server Owner", "Developer & Owner")

    svc = services_coll.find_one({"otp": body.otp.upper()})
    if not svc:
        raise HTTPException(404, f"OTP {body.otp.upper()} not found.")

    # Admins can cancel any task in their guild; staff only their own
    if not is_admin and svc.get("assigned_id") != discord_id:
        raise HTTPException(403, "You can only cancel tasks assigned to you.")
    if not is_admin and svc.get("guild_id") != guild_id:
        raise HTTPException(403, "Task belongs to a different server.")
    if svc.get("status") == "cancelled":
        return {"success": False, "message": "Already cancelled."}
    if svc.get("status") == "finished":
        return {"success": False, "message": "Cannot cancel a finished task."}

    services_coll.update_one(
        {"otp": body.otp.upper()},
        {
            "$set":  {"status": "cancelled", "updated_at": _now()},
            "$push": {"history": _history_entry("cancelled", discord_id)},
        }
    )
    return {"success": True, "message": f"{body.otp.upper()} cancelled.", "otp": body.otp.upper()}


# ── Add note ──────────────────────────────────────────────────
@app.post("/panel/{guild_id}/note")
def add_note(guild_id: int, body: NoteBody, session: dict = Depends(require_session)):
    """Add a staff note to a task."""
    discord_id = session["discord_id"]
    account    = _get_account_or_403(discord_id, guild_id, session)
    _require_staff(account)

    svc = services_coll.find_one({"otp": body.otp.upper()})
    if not svc:
        raise HTTPException(404, f"OTP {body.otp.upper()} not found.")
    if svc.get("assigned_id") != discord_id:
        raise HTTPException(403, "You can only add notes to tasks assigned to you.")

    note_text = body.note.strip()[:500]
    if not note_text:
        raise HTTPException(400, "Note cannot be empty.")

    notes_coll.insert_one({
        "otp":        body.otp.upper(),
        "guild_id":   guild_id,
        "author_id":  discord_id,
        "note":       note_text,
        "created_at": _now(),
    })
    return {"success": True, "message": "Note added."}


# ── Cross-server staff list ───────────────────────────────────
@app.get("/panel/{guild_id}/crossstaff")
def cross_staff(guild_id: int, session: dict = Depends(require_session)):
    """
    Returns all staff registered across ALL guilds.
    Used by the Lua panel assignment selector.
    Groups by guild, includes designation + display name.
    """
    discord_id = session["discord_id"]
    account    = _get_account_or_403(discord_id, guild_id, session)
    _require_staff(account)

    # Get all non-Client records from the entire DB
    all_staff = list(roblox_coll.find(
        {"designation": {"$ne": "Client"}},
        {"_id": 0, "discord_id": 1, "guild_id": 1, "guild_name": 1,
         "server_name": 1, "display_name": 1, "roblox_username": 1, "designation": 1}
    ))

    # Group by guild
    by_guild: dict[int, dict] = {}
    for s in all_staff:
        gid = s.get("guild_id")
        if gid not in by_guild:
            cfg_doc = config_coll.find_one({"guild_id": gid}) or {}
            by_guild[gid] = {
                "guild_id":   gid,
                "guild_name": s.get("guild_name", ""),
                "server_name": cfg_doc.get("server_name") or s.get("server_name", "AVA Services"),
                "staff":      [],
            }
        by_guild[gid]["staff"].append({
            "discord_id":      s.get("discord_id"),
            "display_name":    s.get("display_name") or s.get("roblox_username", ""),
            "roblox_username": s.get("roblox_username", ""),
            "designation":     s.get("designation", "Staff"),
        })

    # Sort each group by designation rank
    for g in by_guild.values():
        g["staff"].sort(key=lambda x: DESIG_RANK.get(x["designation"], 0), reverse=True)

    return {
        "guilds": sorted(by_guild.values(), key=lambda g: g["server_name"].lower()),
        "total_staff": len(all_staff),
    }


# ── Cross-server assign ───────────────────────────────────────
@app.post("/panel/{guild_id}/assign")
def cross_assign(guild_id: int, body: AssignBody, session: dict = Depends(require_session)):
    """
    Assign a task to any registered staff member from any guild.
    Requires Admin designation or higher.
    """
    discord_id = session["discord_id"]
    account    = _get_account_or_403(discord_id, guild_id, session)

    if account.get("designation") not in ("AVA Admin", "Server Owner", "Developer & Owner"):
        raise HTTPException(403, "Admin access required to assign tasks.")

    svc = services_coll.find_one({"otp": body.otp.upper()})
    if not svc:
        raise HTTPException(404, f"OTP {body.otp.upper()} not found.")
    if svc.get("guild_id") != guild_id:
        raise HTTPException(403, "Task belongs to a different server.")
    if svc.get("status") in ("finished", "cancelled"):
        raise HTTPException(400, f"Cannot assign a {svc['status']} task.")

    # Verify the target staff member is registered
    target = roblox_coll.find_one({
        "discord_id": body.target_discord_id,
        "guild_id":   body.target_guild_id,
    })
    if not target:
        raise HTTPException(404, "Target staff member not found in AVA.")
    if target.get("designation") == "Client":
        raise HTTPException(400, "Cannot assign tasks to a Client.")

    services_coll.update_one(
        {"otp": body.otp.upper()},
        {
            "$set":  {
                "assigned_id":  body.target_discord_id,
                "updated_at":   _now(),
                # Store which guild the assignee belongs to for cross-guild reference
                "assigned_guild_id": body.target_guild_id,
            },
            "$push": {"history": _history_entry(
                f"assigned_to_{body.target_discord_id}", discord_id
            )},
        }
    )
    return {
        "success":      True,
        "message":      f"{body.otp.upper()} assigned to {target.get('display_name', 'staff')}.",
        "assigned_to":  {
            "discord_id":   body.target_discord_id,
            "display_name": target.get("display_name", ""),
            "guild_name":   target.get("guild_name", ""),
            "server_name":  target.get("server_name", ""),
            "designation":  target.get("designation", "Staff"),
        },
    }

# ════════════════════════════════════════════════════════════
#  ROUTES — Bot-internal (BOT_KEY only)
# ════════════════════════════════════════════════════════════

@app.post("/credentials/set", dependencies=[Depends(verify_bot_key)])
def set_password(body: SetPasswordBody):
    """Called by >setpanelpass. Stores bcrypt hash."""
    hashed = _hash_password(body.password)
    credentials_coll.update_one(
        {"discord_id": body.discord_id},
        {"$set": {
            "discord_id":    body.discord_id,
            "guild_id":      body.guild_id,
            "password_hash": hashed,
            "updated_at":    _now(),
        }},
        upsert=True
    )
    return {"success": True, "message": "Panel password set."}


@app.post("/register", dependencies=[Depends(verify_bot_key)])
def register(body: RegisterBody):
    """Called by bot >sregister."""
    roblox_coll.update_one(
        {"discord_id": body.discord_id, "guild_id": body.guild_id},
        {"$set": {
            "discord_id":      body.discord_id,
            "guild_id":        body.guild_id,
            "guild_name":      body.guild_name.strip(),
            "roblox_username": body.roblox_username.lower().strip(),
            "roblox_id":       body.roblox_id,
            "display_name":    body.display_name.strip() or body.roblox_username,
            "designation":     body.designation.strip() or "Client",
            "server_name":     body.server_name.strip() or "AVA Services",
            "registered_at":   _now(),
        }},
        upsert=True
    )
    # Update session guild_ids if user has an active session
    sessions_coll.update_many(
        {"discord_id": body.discord_id},
        {"$addToSet": {"guild_ids": body.guild_id}}
    )
    return {"success": True}


@app.post("/admin/force-logout/{discord_id}", dependencies=[Depends(verify_bot_key)])
def force_logout(discord_id: int):
    deleted = sessions_coll.delete_many({"discord_id": discord_id})
    return {"success": True, "sessions_removed": deleted.deleted_count}


@app.delete("/admin/delete-account/{discord_id}/{guild_id}", dependencies=[Depends(verify_bot_key)])
def delete_account(discord_id: int, guild_id: int):
    """Called by bot >resetacc — full wipe for one guild."""
    roblox_coll.delete_one({"discord_id": discord_id, "guild_id": guild_id})
    credentials_coll.delete_one({"discord_id": discord_id})
    sessions_coll.delete_many({"discord_id": discord_id})
    rate_coll.delete_one({"_id": str(discord_id)})
    return {"success": True}
@app.get("/", methods=["GET", "HEAD"])
def root():
    # UptimeRobot will receive the 200 OK status 
    # without downloading a large JSON body if it sends a HEAD request.
    return {"status": "AVA API online", "version": "5.0.0"}
