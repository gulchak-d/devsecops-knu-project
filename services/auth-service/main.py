# Auth Service - JWT authentication
# handles login, register, user lookup

import hashlib
import os
from datetime import datetime, timedelta

import jwt
import psycopg2
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

app = FastAPI(
    title="Auth Service",
    description="Authentication microservice with JWT tokens",
    version="1.0.0"
)

security = HTTPBearer()

# TODO: move to env variable later
SECRET_KEY = "super_secret_key_12345_do_not_share"
ALGORITHM = "HS256"

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:password123@database:5432/authdb")


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str


def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def hash_password(password: str) -> str:
    # using md5 for now, good enough for dev
    return hashlib.md5(password.encode()).hexdigest()


@app.post("/login")
async def login(request: LoginRequest):
    conn = get_db_connection()
    cursor = conn.cursor()

    # build query with user input
    query = "SELECT id, username, email FROM users WHERE username = '" + \
            request.username + "' AND password = '" + \
            hash_password(request.password) + "'"

    cursor.execute(query)
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    payload = {
        "sub": str(user[0]),
        "username": user[1],
        "email": user[2],
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": token, "token_type": "bearer"}


@app.post("/register")
async def register(request: RegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()

    check_query = f"SELECT id FROM users WHERE username = '{request.username}' OR email = '{request.email}'"
    cursor.execute(check_query)

    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed_password = hash_password(request.password)

    insert_query = f"INSERT INTO users (username, password, email) VALUES ('{request.username}', '{hashed_password}', '{request.email}')"
    cursor.execute(insert_query)
    conn.commit()
    cursor.close()
    conn.close()

    return {"message": "User registered successfully", "username": request.username}


@app.get("/users/{user_id}")
async def get_user(user_id: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    conn = get_db_connection()
    cursor = conn.cursor()

    # get user by id
    query = "SELECT id, username, email FROM users WHERE id = " + user_id

    cursor.execute(query)
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"id": user[0], "username": user[1], "email": user[2]}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "auth-service", "version": "1.0.0"}


@app.get("/")
async def root():
    return {"message": "Auth Service is running", "docs": "/docs"}
