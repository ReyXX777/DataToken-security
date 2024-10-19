CREATE DATABASE IF NOT EXISTS secure_token_db;

USE secure_token_db;

CREATE TABLE tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sensitive_data TEXT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
