-- =============================================================
-- Database Initialization Script
-- Дипломна робота: DevSecOps Pipeline з AI Vulnerability Detection
-- =============================================================

-- Створення бази даних для Auth Service
\c authdb;

-- Таблиця користувачів
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50) UNIQUE NOT NULL,
    password    VARCHAR(255) NOT NULL,       -- MD5 hash (навмисно слабкий)
    email       VARCHAR(100) UNIQUE NOT NULL,
    role        VARCHAR(20) DEFAULT 'user',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login  TIMESTAMP
);

-- Таблиця сесій (для відстеження JWT)
CREATE TABLE IF NOT EXISTS sessions (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP NOT NULL,
    is_active   BOOLEAN DEFAULT TRUE
);

-- Таблиця аудит-логів
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER,
    action      VARCHAR(100) NOT NULL,
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details     JSONB
);

-- Тестові дані для демонстрації SQL Injection
-- Паролі: MD5("password123") та MD5("admin")
INSERT INTO users (username, password, email, role) VALUES
    ('admin',    '0192023a7bbd73250516f069df18b500', 'admin@example.com',  'admin'),
    ('testuser', '482c811da5d5b4bc6d497ffa98491e38', 'test@example.com',   'user'),
    ('victim',   '5f4dcc3b5aa765d61d8327deb882cf99', 'victim@example.com', 'user')
ON CONFLICT (username) DO NOTHING;

-- Індекси для продуктивності
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);

-- Таблиця конфіденційних даних (для демонстрації масштабу витоку при SQL Injection)
CREATE TABLE IF NOT EXISTS sensitive_data (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    data_type   VARCHAR(50),
    data_value  TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO sensitive_data (user_id, data_type, data_value) VALUES
    (1, 'credit_card', '4532-1234-5678-9012'),
    (1, 'ssn',         '123-45-6789'),
    (2, 'api_key',     'sk-prod-abc123def456ghi789'),
    (3, 'password_plain', 'password123')
ON CONFLICT DO NOTHING;

-- Виведення підсумку
DO $$
BEGIN
    RAISE NOTICE '=== Database initialized successfully ===';
    RAISE NOTICE 'Tables: users, sessions, audit_log, sensitive_data';
    RAISE NOTICE 'Test users: admin, testuser, victim';
END $$;
