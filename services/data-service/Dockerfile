# Data Service Dockerfile
# =======================

FROM python:3.11-slim

LABEL maintainer="devsecops-thesis"
LABEL service="data-service"
LABEL description="File processing service with intentional vulnerabilities"

# Встановлення системних залежностей (включно з imagemagick для convert)
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    file \
    imagemagick \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Директорія для завантажень
RUN mkdir -p /tmp/uploads && chmod 777 /tmp/uploads

# Непривілейований користувач
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--reload"]
