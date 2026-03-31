"""
AVA API v3  —  FastAPI backend for Roblox in-game panel
All queries are guild-aware (guild_id included in every record).
Deploy: Railway / Render / any VPS with Python 3.11+
Run:    uvicorn ava_api:app --host 0.0.0.0 --port 8000
"""
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pymongo
from datetime import datetime, timezone
import os

MONGO_URI  = os.getenv("MONGO_URI",  "YOUR_MONGO_URI_HERE")
API_SECRET = os.getenv("API_SECRET", "ava_super_secret_key_change_this")

mc            = pymongo.MongoClient(MONGO_URI)
db            = mc["ava_services"]
services_coll = db["services"]
roblox_coll   = db["roblox_accounts"]   # one doc per discord_id + guild_id
config_coll   = db["guild_configs"]

app = FastAPI(title="AVA API", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def verify(x_api_key: str = Header(...)):
    if x_api_key != API_SECRET:
        raise HTTPException(403, "Invalid API key")

class RegisterBody(BaseModel):
    discord_id:      int
    guild_id:        int
    roblox_username: str
    roblox_id:       int    = 0
    display_name:    str    = ""
    designation:     str    = "Staff"
    server_name:     str    = ""

class CompleteBody(BaseModel):
    otp:        str
    discord_id: int
    guild_id:   int

def _svc(s: dict) -> dict:
    return {
        "otp":             s.get("otp",""),
        "name":            s.get("name",""),
        "value":           s.get("value",""),
        "status":          s.get("status","pending"),
        "priority":        s.get("priority","normal"),
        "roblox_username": s.get("roblox_username",""),
        "assigned_id":     s.get("assigned_id"),
        "due_date":        s["due_date"].isoformat() if s.get("due_date") else None,
        "created_at":      s["created_at"].isoformat() if s.get("created_at") else None,
    }

def _profile(a: dict) -> dict:
    return {
        "roblox_username": a.get("roblox_username",""),
        "roblox_id":       a.get("roblox_id", 0),
        "display_name":    a.get("display_name") or a.get("roblox_username",""),
        "designation":     a.get("designation","Staff"),
        "server_name":     a.get("server_name","AVA Services"),
        "guild_id":        a.get("guild_id"),
        "guild_name":      a.get("guild_name",""),
    }

# ── Health ────────────────────────────────────────────────
@app.get("/")
def root(): return {"status": "AVA API online", "version": "3.0.0"}

# ── Register account ──────────────────────────────────────
@app.post("/register", dependencies=[Depends(verify)])
def register(body: RegisterBody):
    roblox_coll.update_one(
        {"discord_id": body.discord_id, "guild_id": body.guild_id},
        {"$set": {
            "discord_id":      body.discord_id,
            "guild_id":        body.guild_id,
            "roblox_username": body.roblox_username.lower().strip(),
            "roblox_id":       body.roblox_id,
            "display_name":    body.display_name.strip() or body.roblox_username,
            "designation":     body.designation.strip() or "Staff",
            "server_name":     body.server_name.strip() or "AVA Services",
            "registered_at":   datetime.now(timezone.utc)
        }},
        upsert=True
    )
    return {"success": True}

# ── Client order panel ────────────────────────────────────
@app.get("/order/{guild_id}/{roblox_username}", dependencies=[Depends(verify)])
def order(guild_id: int, roblox_username: str):
    u = roblox_username.lower().strip()
    a = roblox_coll.find_one({"roblox_username": u, "guild_id": guild_id})
    if not a:
        return {
            "registered": False,
            "message": "This account isn't in AVA's database for this server. Ask your staff member to add your username when creating the service.",
            "profile": None, "active_services": [], "total_active": 0, "total_finished": 0
        }
    svcs = list(services_coll.find({"roblox_username": u, "guild_id": guild_id,
                                     "status": {"$in":["pending","started"]}})
                              .sort("created_at",-1).limit(10))
    fin  = services_coll.count_documents({"roblox_username": u, "guild_id": guild_id, "status": "finished"})
    return {
        "registered": True, "message": "Account found.", "profile": _profile(a),
        "active_services": [_svc(s) for s in svcs],
        "total_active": len(svcs), "total_finished": fin
    }

# ── Staff panel ───────────────────────────────────────────
@app.get("/staff/{guild_id}/{discord_id}", dependencies=[Depends(verify)])
def staff_panel(guild_id: int, discord_id: int):
    a = roblox_coll.find_one({"discord_id": discord_id, "guild_id": guild_id})
    if not a:
        return {
            "registered": False,
            "message": "Your account isn't registered in AVA for this server. Use >sregister <roblox_username> in Discord.",
            "profile": None, "summary": {}, "tasks": {}
        }
    all_t  = list(services_coll.find({"assigned_id": discord_id, "guild_id": guild_id})
                                 .sort("created_at",-1).limit(50))
    pend   = [s for s in all_t if s.get("status")=="pending"]
    start  = [s for s in all_t if s.get("status")=="started"]
    fin    = [s for s in all_t if s.get("status")=="finished"]
    canc   = [s for s in all_t if s.get("status")=="cancelled"]
    return {
        "registered": True, "message": "Panel loaded.", "profile": _profile(a),
        "summary": {
            "total": len(all_t), "pending": len(pend), "started": len(start),
            "finished": len(fin), "cancelled": len(canc),
            "remaining": len(pend)+len(start), "completed": len(fin)
        },
        "tasks": {
            "pending":  [_svc(s) for s in pend],
            "started":  [_svc(s) for s in start],
            "finished": [_svc(s) for s in fin[:5]],
        }
    }

# ── Complete task ─────────────────────────────────────────
@app.post("/complete", dependencies=[Depends(verify)])
def complete(body: CompleteBody):
    svc = services_coll.find_one({"otp": body.otp.upper()})
    if not svc:
        raise HTTPException(404, f"OTP {body.otp.upper()} not found.")
    if svc.get("guild_id") != body.guild_id:
        raise HTTPException(403, "This service belongs to a different server.")
    if svc.get("assigned_id") != body.discord_id:
        raise HTTPException(403, "This service is not assigned to you.")
    if svc.get("status") == "finished":
        return {"success": False, "message": "Service is already finished."}
    if svc.get("status") == "cancelled":
        return {"success": False, "message": "Cannot complete a cancelled service."}
    services_coll.update_one(
        {"otp": body.otp.upper()},
        {"$set":  {"status":"finished","updated_at":datetime.now(timezone.utc)},
         "$push": {"history":{"status":"finished","by":body.discord_id,
                               "at":datetime.now(timezone.utc),"source":"roblox_panel"}}}
    )
    return {"success": True, "message": f"{body.otp.upper()} marked as finished.", "otp": body.otp.upper()}

# ── Lookup helpers ────────────────────────────────────────
@app.get("/lookup/discord/{guild_id}/{discord_id}", dependencies=[Depends(verify)])
def lookup_discord(guild_id: int, discord_id: int):
    a = roblox_coll.find_one({"discord_id": discord_id, "guild_id": guild_id})
    if not a: return {"found": False}
    return {"found": True, "discord_id": discord_id, **_profile(a)}

@app.get("/lookup/roblox/{guild_id}/{roblox_username}", dependencies=[Depends(verify)])
def lookup_roblox(guild_id: int, roblox_username: str):
    a = roblox_coll.find_one({"roblox_username": roblox_username.lower().strip(), "guild_id": guild_id})
    if not a: return {"found": False}
    return {"found": True, "discord_id": a.get("discord_id"), **_profile(a)}
