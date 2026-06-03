"""
Auth Service - JWT Authentication Microservice
==============================================
Дипломна робота: DevSecOps Pipeline з AI Vulnerability Detection
Сервіс навмисно містить вразливості для демонстрації роботи SAST-сканерів.

ВРАЗЛИВОСТІ (навмисні, для тестування):
  - CWE-89: SQL Injection у функціях login() та get_user()
  - CWE-798: Hardcoded Secret Key для JWT
  - CWE-327: Слабкий алгоритм хешування (MD5)
"""

import hashlib
import os
import sqlite3
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

# ========================================================
# ВРАЗЛИВІСТЬ #1: CWE-798 — Hardcoded credentials
# Секретний ключ захардкоджений прямо у коді
# Semgrep rule: python.jwt.hardcoded-jwt-secret
# ========================================================
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
    """Отримати підключення до PostgreSQL."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def hash_password_insecure(password: str) -> str:
    """
    ВРАЗЛИВІСТЬ #2: CWE-327 — Слабкий алгоритм хешування
    MD5 не є безпечним для хешування паролів.
    Semgrep rule: python.cryptography.insecure-hash-algorithms
    """
    # nosec: intentional vulnerability for thesis demonstration
    return hashlib.md5(password.encode()).hexdigest()


@app.post("/login")
async def login(request: LoginRequest):
    """
    ВРАЗЛИВІСТЬ #3: CWE-89 — SQL Injection
    Прямо конкатенуємо рядки без параметризації запиту.
    Semgrep rule: python.django.security.injection.tainted-sql-string

    Приклад атаки:
      username = "admin' OR '1'='1' --"
      password = "anything"
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # ❌ ВРАЗЛИВИЙ КОД — пряма конкатенація рядків у SQL-запиті
    query = "SELECT id, username, email FROM users WHERE username = '" + \
            request.username + "' AND password = '" + \
            hash_password_insecure(request.password) + "'"

    cursor.execute(query)  # SQL Injection тут
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Генеруємо JWT токен
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
    """Реєстрація нового користувача."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # ❌ ВРАЗЛИВІСТЬ: SQL Injection при реєстрації
    check_query = f"SELECT id FROM users WHERE username = '{request.username}' OR email = '{request.email}'"
    cursor.execute(check_query)

    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed_password = hash_password_insecure(request.password)

    # ❌ ВРАЗЛИВІСТЬ: SQL Injection при вставці даних
    insert_query = f"INSERT INTO users (username, password, email) VALUES ('{request.username}', '{hashed_password}', '{request.email}')"
    cursor.execute(insert_query)
    conn.commit()
    cursor.close()
    conn.close()

    return {"message": "User registered successfully", "username": request.username}


@app.get("/users/{user_id}")
async def get_user(user_id: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    ВРАЗЛИВІСТЬ #4: CWE-89 — SQL Injection через path parameter
    user_id передається напряму в запит без валідації.
    """
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    conn = get_db_connection()
    cursor = conn.cursor()

    # ❌ ВРАЗЛИВИЙ КОД — user_id не валідується та вставляється напряму
    # Приклад атаки: GET /users/1 UNION SELECT username,password,email FROM users--
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
    """Health check endpoint."""
    return {"status": "healthy", "service": "auth-service", "version": "1.0.0"}


@app.get("/")
async def root():
    return {"message": "Auth Service is running", "docs": "/docs"}
