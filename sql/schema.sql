-- Create database with proper character set
CREATE DATABASE IF NOT EXISTS secure_token_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE secure_token_db;

-- Tokens table with enhanced security and tracking
CREATE TABLE tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token CHAR(64) NOT NULL UNIQUE,
    sensitive_data VARBINARY(2048) NOT NULL,  -- Encrypted data storage
    hash_verification CHAR(64) NOT NULL,     -- Hash for data verification
    status ENUM('active', 'revoked', 'expired') NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL DEFAULT NULL,
    created_by VARCHAR(255) NOT NULL,
    last_accessed_at TIMESTAMP NULL DEFAULT NULL,
    access_count INT UNSIGNED DEFAULT 0,
    metadata JSON,
    INDEX idx_token (token),
    INDEX idx_status (status),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB;

-- Audit logs table for comprehensive tracking
CREATE TABLE audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_type ENUM('tokenize', 'detokenize', 'access', 'modify', 'revoke', 'error') NOT NULL,
    severity ENUM('debug', 'info', 'warning', 'error', 'critical') NOT NULL,
    message TEXT NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,  -- Supports IPv6
    user_agent TEXT,
    token_id BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    context JSON,
    INDEX idx_event_type (event_type),
    INDEX idx_severity (severity),
    INDEX idx_created_at (created_at),
    INDEX idx_user_id (user_id),
    FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Users table for authentication and authorization
CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    status ENUM('active', 'inactive', 'suspended') NOT NULL DEFAULT 'active',
    role ENUM('admin', 'operator', 'viewer') NOT NULL DEFAULT 'viewer',
    last_login TIMESTAMP NULL DEFAULT NULL,
    mfa_secret VARCHAR(32) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_status (status),
    INDEX idx_role (role)
) ENGINE=InnoDB;

-- Rate limiting table to prevent abuse
CREATE TABLE rate_limits (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    request_count INT UNSIGNED NOT NULL DEFAULT 1,
    first_request_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_request_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_endpoint (ip_address, endpoint),
    INDEX idx_last_request (last_request_at)
) ENGINE=InnoDB;

-- API keys for external integrations
CREATE TABLE api_keys (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    key_hash CHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    permissions JSON NOT NULL,
    last_used_at TIMESTAMP NULL DEFAULT NULL,
    expires_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'revoked') NOT NULL DEFAULT 'active',
    INDEX idx_key_hash (key_hash),
    INDEX idx_user_id (user_id),
    INDEX idx_status (status),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Create views for common queries
CREATE OR REPLACE VIEW active_tokens AS
SELECT id, token, created_at, expires_at, access_count
FROM tokens
WHERE status = 'active' AND (expires_at IS NULL OR expires_at > NOW());

CREATE OR REPLACE VIEW recent_errors AS
SELECT id, message, user_id, ip_address, created_at
FROM audit_logs
WHERE severity IN ('error', 'critical')
ORDER BY created_at DESC;

-- Create stored procedures for common operations
DELIMITER //

CREATE PROCEDURE cleanup_expired_tokens()
BEGIN
    UPDATE tokens 
    SET status = 'expired' 
    WHERE status = 'active' 
    AND expires_at IS NOT NULL 
    AND expires_at <= NOW();
END //

CREATE PROCEDURE rotate_logs(IN days_to_keep INT)
BEGIN
    DELETE FROM audit_logs 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL days_to_keep DAY)
    AND severity IN ('debug', 'info');
END //

CREATE PROCEDURE get_token_usage_stats(IN time_period VARCHAR(10))
BEGIN
    SELECT 
        DATE(created_at) as date,
        COUNT(*) as tokens_created,
        SUM(access_count) as total_accesses
    FROM tokens
    WHERE created_at >= CASE time_period
        WHEN 'day' THEN DATE_SUB(NOW(), INTERVAL 1 DAY)
        WHEN 'week' THEN DATE_SUB(NOW(), INTERVAL 1 WEEK)
        WHEN 'month' THEN DATE_SUB(NOW(), INTERVAL 1 MONTH)
        ELSE DATE_SUB(NOW(), INTERVAL 1 YEAR)
    END
    GROUP BY DATE(created_at)
    ORDER BY date DESC;
END //

DELIMITER ;

-- Create triggers for automatic logging
DELIMITER //

CREATE TRIGGER after_token_access
AFTER UPDATE ON tokens
FOR EACH ROW
BEGIN
    IF NEW.access_count > OLD.access_count THEN
        INSERT INTO audit_logs (event_type, severity, message, user_id, ip_address, token_id)
        VALUES ('access', 'info', 'Token accessed', USER(), '127.0.0.1', NEW.id);
    END IF;
END //

CREATE TRIGGER before_token_delete
BEFORE DELETE ON tokens
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (event_type, severity, message, user_id, ip_address, token_id)
    VALUES ('revoke', 'warning', 'Token deleted', USER(), '127.0.0.1', OLD.id);
END //

DELIMITER ;

-- New component: Token Metadata Table
CREATE TABLE token_metadata (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_id BIGINT UNSIGNED NOT NULL,
    metadata_key VARCHAR(255) NOT NULL,
    metadata_value TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_token_id (token_id),
    INDEX idx_metadata_key (metadata_key),
    FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- New component: Token Access Logs Table
CREATE TABLE token_access_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_id BIGINT UNSIGNED NOT NULL,
    accessed_by VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    accessed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_token_id (token_id),
    INDEX idx_accessed_at (accessed_at),
    FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- New component: Token Expiry Notifications Table
CREATE TABLE token_expiry_notifications (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_id BIGINT UNSIGNED NOT NULL,
    notified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notification_type ENUM('email', 'sms', 'internal') NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    status ENUM('sent', 'failed', 'pending') NOT NULL DEFAULT 'pending',
    INDEX idx_token_id (token_id),
    INDEX idx_notified_at (notified_at),
    FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- New component: Token Usage Analytics Table
CREATE TABLE token_usage_analytics (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_id BIGINT UNSIGNED NOT NULL,
    usage_date DATE NOT NULL,
    access_count INT UNSIGNED NOT NULL DEFAULT 0,
    unique_users INT UNSIGNED NOT NULL DEFAULT 0,
    INDEX idx_token_id (token_id),
    INDEX idx_usage_date (usage_date),
    FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE CASCADE
) ENGINE=InnoDB;
