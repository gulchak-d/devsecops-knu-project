```
devsecops-thesis/
├── services/
│   ├── auth-service/          # FastAPI: JWT Auth + SQL Injection
│   │   ├── main.py
│   │   ├── requirements.txt   # Вразливі залежності
│   │   └── Dockerfile
│   ├── data-service/          # Python: File Processing + Command Injection
│   │   ├── main.py
│   │   ├── requirements.txt   # Вразливі залежності (CVE)
│   │   └── Dockerfile
│   └── database/
│       └── init.sql           # PostgreSQL схема
├── ai-analyzer/               # AI Security Analyzer (Крок 2)
│   ├── analyzer.py
│   └── requirements.txt
├── .github/
│   └── workflows/
│       └── devsecops.yml      # CI/CD Pipeline (Крок 3)
├── docker-compose.yml
└── README.md
```

---

## Навмисні вразливості (для тестування)

### Auth Service (`services/auth-service/main.py`)

| Тип | CWE | Рядок | Опис |
|-----|-----|-------|------|
| SQL Injection | CWE-89 | ~55 | login() — конкатенація рядків у SQL |
| SQL Injection | CWE-89 | ~76 | register() — f-string у SQL |
| SQL Injection | CWE-89 | ~107 | get_user() — path param у SQL |
| Hardcoded Secret | CWE-798 | ~32 | JWT SECRET_KEY в коді |
| Weak Hash | CWE-327 | ~40 | MD5 для паролів |

### Data Service (`services/data-service/main.py`)

| Тип | CWE | Рядок | Опис |
|-----|-----|-------|------|
| Command Injection | CWE-78 | ~74 | os.system() з user input |
| Command Injection | CWE-78 | ~78 | subprocess з shell=True |
| Path Traversal | CWE-22 | ~100 | читання файлів без санітації |
| Insecure Deserialization | CWE-502 | ~118 | pickle.loads() |
| SSRF | CWE-918 | ~138 | requests.get() без валідації URL |
| Unsafe YAML | CWE-502 | ~160 | yaml.load() без Loader |

### Вразливі залежності (CVE)

| Пакет | Версія | CVE | Severity |
|-------|--------|-----|----------|
| PyJWT | 1.7.1 | CVE-2022-29217 | HIGH |
| cryptography | 3.3.2 | CVE-2023-23931 | MEDIUM |
| Pillow | 9.3.0 | CVE-2023-44271 | HIGH |
| requests | 2.28.0 | CVE-2023-32681 | MEDIUM |
| PyYAML | 5.4.1 | CVE-2022-1471 | CRITICAL |
| aiohttp | 3.8.1 | CVE-2023-37276 | HIGH |
| paramiko | 2.11.0 | CVE-2023-48795 | MEDIUM |

---

## Швидкий старт

```bash
# 1. Клонуємо репозиторій
git clone https://github.com/your-username/devsecops-thesis.git
cd devsecops-thesis

# 2. Запускаємо всі сервіси
docker-compose up --build

# 3. Перевіряємо доступність
curl http://localhost:8000/health   # Auth Service
curl http://localhost:8001/health   # Data Service

# 4. Документація API
open http://localhost:8000/docs     # Auth Service Swagger
open http://localhost:8001/docs     # Data Service Swagger
```

## Тестування вразливостей вручну

```bash
# SQL Injection — обхід аутентифікації
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "anything"}'

# Command Injection
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{"filename": "test.txt; id", "operation": "cat"}'

# Path Traversal
curl "http://localhost:8001/read?filename=../../etc/passwd"
```

---

## DevSecOps Pipeline

Після `git push` автоматично запускається:

1. **Semgrep SAST** — статичний аналіз коду
2. **Snyk** — сканування залежностей на CVE
3. **AI Analyzer** — фільтрація False Positives через Gemini API
4. **Quality Gate** — блокування при критичних True Positives
5. **Docker Build** — збірка образів (якщо все чисто)

---


