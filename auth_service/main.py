from fastapi import FastAPI
import sqlite3

app = FastAPI()

@app.get("/login")
def login(username: str):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'" 
    cursor.execute(query)
    return {"status": "success", "data": cursor.fetchall()}