import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return "Login successful!", 200
        else:
            return "Invalid credentials", 401
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(port=5000)