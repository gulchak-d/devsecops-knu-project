import os
from fastapi import FastAPI

app = FastAPI()

@app.get("/ping")
def ping_ip(ip_address: str):
    result = os.popen(f"ping -c 1 {ip_address}").read() 
    return {"output": result}