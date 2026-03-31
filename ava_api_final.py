"""
AVA API v3 — FastAPI backend for Roblox in-game panel
Fully multi-guild aware (guild_id is mandatory in all relevant operations)
Deploy: Railway / Render / any VPS with Python 3.11+
Run: uvicorn ava_api:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pymongo
from datetime import datetime, timezone
import os

# ========================= CONFIG =========================
MONGO_URI = os.getenv("MONGO_URI", "YOUR_MONGO_URI_HERE")
API_SECRET = os.getenv("API_SECRET", "ava_super_secret_key_change_this")

mc = pymongo.MongoClient(MONGO_URI)
db = mc["ava_services"]

services_coll = db["services"]
roblox_coll = db["roblox_accounts"]   # One doc per (discord_id + guild_id)
config_coll = db["guild_configs"]

app = FastAPI(title="AVA API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ====================== AUTH ======================
def verify(x_api_key: str = Header(..., alias="X-API-Key")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key


# ====================== MODELS ======================
class RegisterBody(BaseModel):
    discord_id: int
    guild_id: int
    roblox_username: str
    roblox_id: int = 0
    display_name: str = ""
    designation: str = "Staff"
    server_name: str = ""


class CompleteBody(BaseModel):
    otp: str
    discord_id: int
    guild_id: int


# ====================== HELPERS ======================
def _svc(s: dict) -> dict:
    return {
        "otp": s.get("otp", ""),
        "name": s.get("name", ""),
        "value": s.get("value", ""),
        "status": s.get("status", "pending"),
        "priority": s.get("priority", "normal"),
        "roblox_username": s.get("roblox_username", ""),
        "assigned_id": s.get("assigned_id"),
        "due_date": s["due_date"].isoformat() if s.get("due_date") else None,
        "created_at": s["created_at"].isoformat() if s.get("created_at") else None,
    }


def _profile(a: dict) -> dict:
    return {
        "roblox_username": a.get("roblox_username", ""),
        "roblox_id": a.get("roblox_id", 0),
        "display_name": a.get("display_name") or a.get("roblox_username", ""),
        "designation": a.get("designation", "Staff"),
        "server_name": a.get("server_name", "AVA Services"),
        "guild_id": a.get("guild_id"),
        "guild_name": a.get("guild_name", ""),
    }


# ====================== ROUTES ======================

@app.get("/")
def root():
    return {"status": "AVA API online", "version": "3.0.0"}


# ── Register Roblox Account ──────────────────────────────────────
@app.post("/register", dependencies=[Depends(verify)])
def register(body: RegisterBody):
    roblox_coll.update_one(
        {
            "discord_id": body.discord_id,
            "guild_id": body.guild_id
        },
        {
            "$set": {
                "discord_id": body.discord_id,
                "guild_id": body.guild_id,
                "roblox_username": body.roblox_username.lower().strip(),
                "roblox_id": body.roblox_id,
                "display_name": body.display_name.strip() or body.roblox_username,
                "designation": body.designation.strip() or "Staff",
                "server_name": body.server_name.strip() or "AVA Services",
                "registered_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
        },
        upsert=True
    )
    return {"success": True, "message": "Account registered/updated successfully"}


# ── Client Order Panel (Roblox side) ─────────────────────────────
@app.get("/order/{guild_id}/{roblox_username}", dependencies=[Depends(verify)])
def order(guild_id: int, roblox_username: str):
    u = roblox_username.lower().strip()

    a = roblox_coll.find_one({"roblox_username": u, "guild_id": guild_id})

    if not a:
        return {
            "registered": False,
            "message": "This Roblox account is not registered in AVA for this server.",
            "profile": None,
            "active_services": [],
            "total_active": 0,
            "total_finished": 0
        }

    # Active services
    svcs = list(
        services_coll.find({
            "roblox_username": u,
            "guild_id": guild_id,
            "status": {"$in": ["pending", "started"]}
        })
        .sort("created_at", -1)
        .limit(10)
    )

    total_finished = services_coll.count_documents({
        "roblox_username": u,
        "guild_id": guild_id,
        "status": "finished"
    })

    return {
        "registered": True,
        "message": "Account found.",
        "profile": _profile(a),
        "active_services": [_svc(s) for s in svcs],
        "total_active": len(svcs),
        "total_finished": total_finished
    }


# ── Staff Panel ──────────────────────────────────────────────────
@app.get("/staff/{guild_id}/{discord_id}", dependencies=[Depends(verify)])
def staff_panel(guild_id: int, discord_id: int):
    a = roblox_coll.find_one({"discord_id": discord_id, "guild_id": guild_id})

    if not a:
        return {
            "registered": False,
            "message": "Your account is not registered. Use >sregister <roblox_username> in Discord.",
            "profile": None,
            "summary": {},
            "tasks": {}
        }

    # Get all tasks for this staff in this guild
    all_tasks = list(
        services_coll.find({
            "assigned_id": discord_id,
            "guild_id": guild_id
        })
        .sort("created_at", -1)
        .limit(50)
    )

    pending = [s for s in all_tasks if s.get("status") == "pending"]
    started = [s for s in all_tasks if s.get("status") == "started"]
    finished = [s for s in all_tasks if s.get("status") == "finished"]
    cancelled = [s for s in all_tasks if s.get("status") == "cancelled"]

    return {
        "registered": True,
        "message": "Staff panel loaded.",
        "profile": _profile(a),
        "summary": {
            "total": len(all_tasks),
            "pending": len(pending),
            "started": len(started),
            "finished": len(finished),
            "cancelled": len(cancelled),
            "remaining": len(pending) + len(started),
            "completed": len(finished)
        },
        "tasks": {
            "pending": [_svc(s) for s in pending],
            "started": [_svc(s) for s in started],
            "finished": [_svc(s) for s in finished[:5]],
        }
    }


# ── Complete Service (from Roblox panel) ─────────────────────────
@app.post("/complete", dependencies=[Depends(verify)])
def complete(body: CompleteBody):
    otp = body.otp.upper().strip()

    svc = services_coll.find_one({"otp": otp})

    if not svc:
        raise HTTPException(404, f"Service with OTP {otp} not found.")

    # Critical multi-guild safety checks
    if svc.get("guild_id") != body.guild_id:
        raise HTTPException(403, "This service belongs to a different Discord server.")

    if svc.get("assigned_id") != body.discord_id:
        raise HTTPException(403, "This service is not assigned to you.")

    if svc.get("status") == "finished":
        return {"success": False, "message": "Service is already finished."}

    if svc.get("status") == "cancelled":
        return {"success": False, "message": "Cannot complete a cancelled service."}

    services_coll.update_one(
        {"otp": otp},
        {
            "$set": {
                "status": "finished",
                "updated_at": datetime.now(timezone.utc)
            },
            "$push": {
                "history": {
                    "status": "finished",
                    "by": body.discord_id,
                    "at": datetime.now(timezone.utc),
                    "source": "roblox_panel"
                }
            }
        }
    )

    return {
        "success": True,
        "message": f"Service {otp} marked as finished.",
        "otp": otp
    }


# ── Lookup Helpers ───────────────────────────────────────────────
@app.get("/lookup/discord/{guild_id}/{discord_id}", dependencies=[Depends(verify)])
def lookup_discord(guild_id: int, discord_id: int):
    a = roblox_coll.find_one({"discord_id": discord_id, "guild_id": guild_id})
    if not a:
        return {"found": False}
    return {"found": True, "discord_id": discord_id, **_profile(a)}


@app.get("/lookup/roblox/{guild_id}/{roblox_username}", dependencies=[Depends(verify)])
def lookup_roblox(guild_id: int, roblox_username: str):
    a = roblox_coll.find_one({
        "roblox_username": roblox_username.lower().strip(),
        "guild_id": guild_id
    })
    if not a:
        return {"found": False}
    return {"found": True, "discord_id": a.get("discord_id"), **_profile(a)}
