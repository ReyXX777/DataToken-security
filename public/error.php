<?php
// src/Logger.php
namespace App;

use Exception;
use PDO;

class Logger {
    private string $logDir;
    private string $logFile;
    private ?PDO $db;
    private array $allowedLevels;

    public function __construct(?string $logDir = null, ?PDO $db = null, array $allowedLevels = null) {
        $this->logDir = $logDir ?? dirname(__DIR__) . '/logs';
        $this->logFile = $this->logDir . '/app.log';
        $this->db = $db;
        $this->allowedLevels = $allowedLevels ?? ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];

        $this->initializeLogDirectory();
        $this->validateDatabaseConnection();
    }

    private function initializeLogDirectory(): void {
        if (!is_dir($this->logDir)) {
            if (!mkdir($this->logDir, 0750, true)) {
                throw new Exception('Failed to create log directory at ' . $this->logDir);
            }
        }

        if (!is_writable($this->logDir)) {
            throw new Exception('Log directory is not writable: ' . $this->logDir);
        }

        $htaccess = $this->logDir . '/.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "Deny from all");
        }
    }

    private function validateDatabaseConnection(): void {
        if ($this->db !== null) {
            try {
                $this->db->query('SELECT 1');
            } catch (Exception $e) {
                throw new Exception('Invalid PDO database connection: ' . $e->getMessage());
            }
        }
    }

    public function log(string $message, string $level = 'INFO', array $context = []): void {
        $level = strtoupper($level);
        if (!in_array($level, $this->allowedLevels)) {
            throw new Exception('Invalid log level: ' . $level);
        }

        $message = $this->sanitizeMessage($message);
        $context = $this->sanitizeContext($context);
        $context = $this->addStandardContext($context);

        $logEntry = $this->formatLogEntry($level, $message, $context);
        $this->writeToFile($logEntry);

        if ($this->db) {
            $this->writeToDatabase($level, $message, $context);
        }

        if ($level === 'CRITICAL') {
            $this->alertAdministrator($message, $context);
        }
    }

    private function sanitizeMessage(string $message): string {
        return htmlspecialchars(trim($message), ENT_QUOTES, 'UTF-8');
    }

    private function sanitizeContext(array $context): array {
        array_walk_recursive($context, function (&$value) {
            if (is_string($value)) {
                $value = $this->sanitizeMessage($value);
            }
        });
        return $context;
    }

    private function addStandardContext(array $context): array {
        return array_merge($context, [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_id' => $this->generateRequestId(),
        ]);
    }

    private function formatLogEntry(string $level, string $message, array $context): string {
        $timestamp = $context['timestamp'];
        $requestId = $context['request_id'];
        unset($context['timestamp'], $context['request_id']);

        $contextJson = json_encode($context);
        return "[$timestamp][$requestId][$level] $message | $contextJson" . PHP_EOL;
    }

    private function writeToFile(string $entry): void {
        if (file_put_contents($this->logFile, $entry, FILE_APPEND | LOCK_EX) === false) {
            throw new Exception('Failed to write to log file at ' . $this->logFile);
        }
    }

    private function writeToDatabase(string $level, string $message, array $context): void {
        $stmt = $this->db->prepare(
            "INSERT INTO audit_logs (level, message, context, created_at) 
             VALUES (?, ?, ?, NOW())"
        );
        $stmt->execute([$level, $message, json_encode($context)]);
    }

    private function alertAdministrator(string $message, array $context): void {
        error_log("CRITICAL ERROR: $message | " . json_encode($context));
    }

    private function generateRequestId(): string {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    // New component: Log rotation
    public function rotateLogs(int $maxSize = 1048576, int $maxFiles = 5): void {
        if (file_exists($this->logFile) && filesize($this->logFile) >= $maxSize) {
            for ($i = $maxFiles - 1; $i >= 1; $i--) {
                $oldLog = $this->logDir . '/app.log.' . $i;
                $newLog = $this->logDir . '/app.log.' . ($i + 1);
                if (file_exists($oldLog)) {
                    rename($oldLog, $newLog);
                }
            }
            rename($this->logFile, $this->logDir . '/app.log.1');
        }
    }

    // New component: Log search
    public function searchLogs(string $query, int $limit = 100): array {
        $logs = [];
        $lines = file($this->logFile);
        $lines = array_reverse(array_slice($lines, -$limit));

        foreach ($lines as $line) {
            if (strpos($line, $query) !== false) {
                $logs[] = ['message' => trim($line)];
            }
        }

        return $logs;
    }
}
