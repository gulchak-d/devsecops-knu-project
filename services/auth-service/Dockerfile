# Auth Service Dockerfile
# ======================
# Базовий образ з Python 3.11 (slim для зменшення розміру)

FROM python:3.11-slim

# Метадані образу
LABEL maintainer="devsecops-thesis"
LABEL service="auth-service"
LABEL description="JWT Authentication Service with intentional vulnerabilities"

# Встановлення системних залежностей
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Встановлення робочої директорії
WORKDIR /app

# Копіювання та встановлення Python-залежностей
# (Копіюємо requirements окремо для кешування шарів Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Копіювання коду застосунку
COPY . .

# Створення непривілейованого користувача
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

# Відкриття порту
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Запуск застосунку
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
