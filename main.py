import os, jwt, bcrypt, json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import asyncpg
from typing import List
from datetime import datetime, timedelta

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@db:<portnumber>/<nome>")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
JWT_ALGORITHM = "HS256"

app = FastAPI(title="Tile MVP")

async def get_pool():
    return await asyncpg.create_pool(dsn=DATABASE_URL, min_size=1, max_size=5)

class RegisterIn(BaseModel):
    email: str
    password: str
    webhook_url: str = None

class LoginIn(BaseModel):
    email: str
    password: str

class SubscriptionIn(BaseModel):
    type: str
    value: str

def create_jwt(user_id: int):
    payload = {"sub": user_id, "exp": datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register")
async def register(data: RegisterIn):
    pw = data.password.encode()
    hashed = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()
    pool = await get_pool()
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow("INSERT INTO users (email, password_hash, webhook_url) VALUES ($1,$2,$3) RETURNING id", data.email, hashed, data.webhook_url)
            user_id = row["id"]
        except Exception:
            await pool.close()
            raise HTTPException(status_code=400, detail="Email already registered")
    await pool.close()
    token = create_jwt(user_id)
    return {"token": token}

@app.post("/login")
async def login(data: LoginIn):
    pool = await get_pool()
    async with pool.acquire() as conn:
        user = await conn.fetchrow("SELECT id, password_hash FROM users WHERE email=$1", data.email)
    await pool.close()
    if not user or not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_jwt(user["id"])
    return {"token": token}

@app.post("/subscriptions")
async def add_subscription(sub: SubscriptionIn, token: str):
    user_id = verify_jwt(token)
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("INSERT INTO subscriptions (user_id, type, value) VALUES ($1,$2,$3) RETURNING id", user_id, sub.type, sub.value.lower())
        sub_id = row["id"]
    await pool.close()
    return {"id": sub_id}

@app.get("/subscriptions")
async def list_subscriptions(token: str):
    user_id = verify_jwt(token)
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT id, type, value, created_at FROM subscriptions WHERE user_id=$1", user_id)
    await pool.close()
    return [dict(r) for r in rows]

@app.get("/vulns")
async def list_vulns(limit: int = 50):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT id, cve_id, source, published_at, summary, cvss_score FROM vulns ORDER BY published_at DESC NULLS LAST LIMIT $1", limit)
    await pool.close()
    return [dict(r) for r in rows]

@app.get("/vulns/{vuln_id}")
async def get_vuln(vuln_id: int):
    pool = await get_pool()
    async with pool.acquire() as conn:
        vuln = await conn.fetchrow("SELECT * FROM vulns WHERE id=$1", vuln_id)
        affected = await conn.fetch("SELECT vendor, product, version_range FROM vuln_affected WHERE vuln_id=$1", vuln_id)
    await pool.close()
    if not vuln:
        raise HTTPException(status_code=404)
    return {"vuln": dict(vuln), "affected": [dict(a) for a in affected]}
