<?php
// src/Token.php
namespace App;

class Token {
    private $db;
    private $logger;

    public function __construct(Database $db, Logger $logger) {
        $this->db = $db;
        $this->logger = $logger;
    }

    public function generateToken($sensitiveData) {
        // Generate a cryptographically secure token
        $token = bin2hex(random_bytes(16));
        
        // Hash the sensitive data before storage
        $hashedData = password_hash($sensitiveData, PASSWORD_ARGON2ID);
        
        // Store in database
        $stmt = $this->db->prepare(
            "INSERT INTO tokens (token, sensitive_data, created_at) 
             VALUES (?, ?, NOW())"
        );
        $stmt->execute([$token, $hashedData]);
        
        // Log the tokenization event
        $this->logger->log('Token generated', 'info', [
            'token' => $token,
            'ip' => $_SERVER['REMOTE_ADDR']
        ]);
        
        return $token;
    }

    public function getVault() {
        $stmt = $this->db->prepare(
            "SELECT token, created_at FROM tokens 
             ORDER BY created_at DESC LIMIT 100"
        );
        $stmt->execute();
        return $stmt->fetchAll();
    }

    // New component: Token validation
    public function validateToken($token, $sensitiveData) {
        $stmt = $this->db->prepare(
            "SELECT sensitive_data FROM tokens 
             WHERE token = ?"
        );
        $stmt->execute([$token]);
        $result = $stmt->fetch();

        if ($result && password_verify($sensitiveData, $result['sensitive_data'])) {
            return true;
        }
        return false;
    }

    // New component: Token expiration check
    public function isTokenExpired($token) {
        $stmt = $this->db->prepare(
            "SELECT created_at FROM tokens 
             WHERE token = ?"
        );
        $stmt->execute([$token]);
        $result = $stmt->fetch();

        if ($result) {
            $createdAt = new \DateTime($result['created_at']);
            $now = new \DateTime();
            $interval = $now->diff($createdAt);

            // Token expires after 1 hour
            return ($interval->h >= 1);
        }
        return true;
    }

    // New component: Token deletion
    public function deleteToken($token) {
        $stmt = $this->db->prepare(
            "DELETE FROM tokens WHERE token = ?"
        );
        $stmt->execute([$token]);
        return $stmt->rowCount() > 0;
    }

    // New component: Token usage tracking
    public function trackTokenUsage($token) {
        $stmt = $this->db->prepare(
            "UPDATE tokens SET usage_count = usage_count + 1 
             WHERE token = ?"
        );
        $stmt->execute([$token]);
    }

    // New component: Bulk token generation
    public function generateBulkTokens($sensitiveDataArray) {
        $tokens = [];
        foreach ($sensitiveDataArray as $data) {
            $tokens[] = $this->generateToken($data);
        }
        return $tokens;
    }
}

// src/Logger.php
namespace App;

class Logger {
    private $logFile;

    public function __construct($logFile = null) {
        $this->logFile = $logFile ?? __DIR__ . '/../logs/app.log';
    }

    public function log($message, $level = 'info', $context = []) {
        $timestamp = date('Y-m-d H:i:s');
        $contextJson = json_encode($context);
        $logEntry = "[$timestamp] [$level] $message $contextJson\n";
        
        file_put_contents($this->logFile, $logEntry, FILE_APPEND);
    }

    public function getLogs($limit = 100) {
        $logs = [];
        $lines = file($this->logFile);
        $lines = array_reverse(array_slice($lines, -$limit));
        
        foreach ($lines as $line) {
            $logs[] = ['message' => trim($line)];
        }
        
        return $logs;
    }

    // New component: Log level filtering
    public function getLogsByLevel($level, $limit = 100) {
        $logs = [];
        $lines = file($this->logFile);
        $lines = array_reverse(array_slice($lines, -$limit));

        foreach ($lines as $line) {
            if (strpos($line, "[$level]") !== false) {
                $logs[] = ['message' => trim($line)];
            }
        }

        return $logs;
    }

    // New component: Log search by keyword
    public function searchLogs($keyword, $limit = 100) {
        $logs = [];
        $lines = file($this->logFile);
        $lines = array_reverse(array_slice($lines, -$limit));

        foreach ($lines as $line) {
            if (strpos($line, $keyword) !== false) {
                $logs[] = ['message' => trim($line)];
            }
        }

        return $logs;
    }

    // New component: Log rotation
    public function rotateLogs($maxSize = 1048576) {
        if (filesize($this->logFile) >= $maxSize) {
            $backupFile = $this->logFile . '.' . date('Y-m-d_H-i-s');
            rename($this->logFile, $backupFile);
            file_put_contents($this->logFile, '');
        }
    }

    // New component: Log archiving
    public function archiveLogs($days = 30) {
        $files = glob($this->logFile . '.*');
        $now = time();

        foreach ($files as $file) {
            if (is_file($file) && ($now - filemtime($file)) >= $days * 86400) {
                unlink($file);
            }
        }
    }
}

// sql/schema.sql
CREATE TABLE tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token CHAR(32) NOT NULL UNIQUE,
    sensitive_data TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    usage_count INT DEFAULT 0,
    INDEX idx_token (token)
) ENGINE=InnoDB;

CREATE TABLE audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    message TEXT NOT NULL,
    level VARCHAR(20) NOT NULL,
    context JSON,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;
