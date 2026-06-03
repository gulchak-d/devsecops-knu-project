# Data Service - file upload and processing
# handles file uploads, reading, conversion

import os
import pickle
import subprocess
import urllib.request
from pathlib import Path

import requests
import yaml
from fastapi import FastAPI, File, UploadFile, HTTPException
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
    file_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    return {"message": "File uploaded", "filename": file.filename, "path": file_path}


@app.post("/process")
async def process_file(request: ProcessRequest):
    file_path = os.path.join(UPLOAD_DIR, request.filename)

    # run the requested operation on the file
    command = f"{request.operation} {file_path}"
    result = os.system(command)

    output = subprocess.check_output(
        f"file {file_path} && wc -c {file_path}",
        shell=True
    )

    return {
        "status": "processed",
        "command": command,
        "exit_code": result,
        "output": output.decode("utf-8", errors="replace")
    }


@app.get("/read")
async def read_file(filename: str):
    # read file from uploads dir
    file_path = UPLOAD_DIR + "/" + filename

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
    # deserialize uploaded data
    content = await file.read()

    try:
        data = pickle.loads(content)
        return {"deserialized": str(data)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Deserialization error: {str(e)}")


@app.post("/fetch")
async def fetch_url(request: FetchRequest):
    # fetch content from url and save locally
    try:
        response = requests.get(request.url, timeout=10)
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
    content = await file.read()

    try:
        data = yaml.load(content, Loader=yaml.Loader)
        return {"parsed": data}
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"YAML parse error: {str(e)}")


@app.get("/convert")
async def convert_file(filename: str, format: str):
    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{UPLOAD_DIR}/{filename}.{format}"

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
    return {"status": "healthy", "service": "data-service", "version": "1.0.0"}


@app.get("/")
async def root():
    return {"message": "Data Service is running", "docs": "/docs"}
