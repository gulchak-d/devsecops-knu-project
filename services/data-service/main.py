"""
Data Service - File Upload & Processing Microservice
====================================================
Дипломна робота: DevSecOps Pipeline з AI Vulnerability Detection
Сервіс навмисно містить вразливості для демонстрації роботи SAST-сканерів.

ВРАЗЛИВОСТІ (навмисні, для тестування):
  - CWE-78:  Command Injection через os.system() та subprocess без валідації
  - CWE-22:  Path Traversal при зчитуванні файлів
  - CWE-502: Insecure Deserialization через pickle
  - CWE-918: SSRF через requests без валідації URL
"""

import os
import pickle
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import requests
import yaml
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="Data Service",
    description="File upload and processing microservice",
    version="1.0.0"
)

UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


class ProcessRequest(BaseModel):
    filename: str
    operation: str


class FetchRequest(BaseModel):
    url: str
    output_file: str


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Завантаження файлу на сервер."""
    file_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    return {"message": "File uploaded", "filename": file.filename, "path": file_path}


@app.post("/process")
async def process_file(request: ProcessRequest):
    """
    ВРАЗЛИВІСТЬ #1: CWE-78 — Command Injection
    filename та operation передаються напряму в os.system() без валідації.
    Semgrep rule: python.lang.security.audit.subprocess-shell-true

    Приклад атаки:
      filename = "test.txt; rm -rf /tmp/uploads; echo 'pwned'"
      operation = "wc -l"
    Або:
      operation = "cat /etc/passwd"
    """
    file_path = os.path.join(UPLOAD_DIR, request.filename)

    # ❌ ВРАЗЛИВИЙ КОД — пряма підстановка змінної у shell-команду
    command = f"{request.operation} {file_path}"
    result = os.system(command)  # Command Injection тут

    # ❌ ВРАЗЛИВИЙ КОД — subprocess з shell=True та невалідованими даними
    output = subprocess.check_output(
        f"file {file_path} && wc -c {file_path}",
        shell=True  # Критична вразливість: shell=True з user input
    )

    return {
        "status": "processed",
        "command": command,
        "exit_code": result,
        "output": output.decode("utf-8", errors="replace")
    }


@app.get("/read")
async def read_file(filename: str):
    """
    ВРАЗЛИВІСТЬ #2: CWE-22 — Path Traversal
    filename не санітується, що дозволяє вихід за межі UPLOAD_DIR.
    Semgrep rule: python.flask.security.audit.path-traversal

    Приклад атаки:
      GET /read?filename=../../etc/passwd
      GET /read?filename=../../../etc/shadow
    """
    # ❌ ВРАЗЛИВИЙ КОД — немає перевірки на "../" у шляху
    file_path = UPLOAD_DIR + "/" + filename  # Path Traversal тут

    try:
        with open(file_path, "r") as f:
            content = f.read()
        return {"filename": filename, "content": content}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")


@app.post("/deserialize")
async def deserialize_data(file: UploadFile = File(...)):
    """
    ВРАЗЛИВІСТЬ #3: CWE-502 — Insecure Deserialization
    pickle.loads() виконує довільний Python-код з даних користувача.
    Semgrep rule: python.lang.security.audit.pickle

    Приклад атаки: створити payload з pickle.dumps(os.system('id'))
    """
    content = await file.read()

    # ❌ ВРАЗЛИВИЙ КОД — десеріалізація довільних даних через pickle
    try:
        data = pickle.loads(content)  # Insecure Deserialization тут
        return {"deserialized": str(data)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Deserialization error: {str(e)}")


@app.post("/fetch")
async def fetch_url(request: FetchRequest):
    """
    ВРАЗЛИВІСТЬ #4: CWE-918 — Server-Side Request Forgery (SSRF)
    URL від користувача використовується без валідації,
    що дозволяє доступ до внутрішніх сервісів.
    Semgrep rule: python.requests.security.ssrf

    Приклад атаки:
      url = "http://169.254.169.254/latest/meta-data/"  (AWS metadata)
      url = "http://database:5432/"                      (внутрішня БД)
      url = "file:///etc/passwd"                         (локальні файли)
    """
    # ❌ ВРАЗЛИВИЙ КОД — немає whitelist дозволених хостів
    try:
        response = requests.get(request.url, timeout=10)  # SSRF тут
        output_path = os.path.join(UPLOAD_DIR, request.output_file)

        with open(output_path, "wb") as f:
            f.write(response.content)

        return {
            "status": "fetched",
            "url": request.url,
            "status_code": response.status_code,
            "saved_to": output_path
        }
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Fetch error: {str(e)}")


@app.post("/parse-yaml")
async def parse_yaml(file: UploadFile = File(...)):
    """
    ВРАЗЛИВІСТЬ #5: CWE-502 — YAML Deserialization (yaml.load без Loader)
    yaml.load() без безпечного Loader виконує довільний Python-код.
    Semgrep rule: python.lang.security.audit.yaml-load

    Приклад атаки: YAML з !!python/object/apply:os.system ['id']
    """
    content = await file.read()

    # ❌ ВРАЗЛИВИЙ КОД — yaml.load без safe Loader
    try:
        data = yaml.load(content, Loader=yaml.Loader)  # Unsafe YAML deserialization
        return {"parsed": data}
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"YAML parse error: {str(e)}")


@app.get("/convert")
async def convert_file(filename: str, format: str):
    """
    ВРАЗЛИВІСТЬ #6: CWE-78 — Command Injection через конвертацію файлів
    Обидва параметри підставляються в shell-команду без санітації.
    """
    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{UPLOAD_DIR}/{filename}.{format}"

    # ❌ ВРАЗЛИВИЙ КОД — f-string з user input у shell-команді
    cmd = f"convert {input_path} {output_path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    return {
        "input": input_path,
        "output": output_path,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "data-service", "version": "1.0.0"}


@app.get("/")
async def root():
    return {"message": "Data Service is running", "docs": "/docs"}
