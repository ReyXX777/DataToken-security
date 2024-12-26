<?php
// src/Logger.php
namespace App;

use Exception;
use PDO;

class Logger {
    private string $logDir;
    private string $logFile;
    private ?PDO $db;
    private array $allowedLevels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];
    
    /**
     * Constructor initializes logging configuration
     * 
     * @param string|null $logDir Custom log directory path
     * @param PDO|null $db Database connection for audit logs
     */
    public function __construct(?string $logDir = null, ?PDO $db = null) {
        $this->logDir = $logDir ?? dirname(__DIR__) . '/logs';
        $this->logFile = $this->logDir . '/app.log';
        $this->db = $db;
        
        $this->initializeLogDirectory();
    }
    
    /**
     * Initialize log directory with proper permissions
     */
    private function initializeLogDirectory(): void {
        if (!is_dir($this->logDir)) {
            if (!mkdir($this->logDir, 0750, true)) {
                throw new Exception('Failed to create log directory');
            }
        }
        
        // Ensure proper permissions on existing directory
        chmod($this->logDir, 0750);
        
        // Create .htaccess to prevent direct access
        $htaccess = $this->logDir . '/.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "Deny from all");
        }
    }
    
    /**
     * Log a message with specified level and context
     * 
     * @param string $message Log message
     * @param string $level Log level
     * @param array $context Additional context data
     * @throws Exception If invalid log level
     */
    public function log(string $message, string $level = 'INFO', array $context = []): void {
        $level = strtoupper($level);
        
        if (!in_array($level, $this->allowedLevels)) {
            throw new Exception('Invalid log level: ' . $level);
        }
        
        // Sanitize and validate input
        $message = $this->sanitizeMessage($message);
        $context = $this->sanitizeContext($context);
        
        // Add standard context information
        $context = array_merge($context, [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_id' => $this->generateRequestId()
        ]);
        
        // Format log entry
        $logEntry = $this->formatLogEntry($level, $message, $context);
        
        // Write to file
        $this->writeToFile($logEntry);
        
        // Store in database if available
        if ($this->db) {
            $this->writeToDatabase($level, $message, $context);
        }
        
        // Alert on critical errors
        if ($level === 'CRITICAL') {
            $this->alertAdministrator($message, $context);
        }
    }
    
    /**
     * Log user actions specifically
     * 
     * @param string $username Username
     * @param string $action Action performed
     * @param array $additional Additional context
     */
    public function logUserAction(string $username, string $action, array $additional = []): void {
        $context = array_merge($additional, [
            'username' => $username,
            'action' => $action,
            'session_id' => session_id() ?? 'no_session'
        ]);
        
        $level = $this->determineActionLevel($action);
        $message = "User '$username' performed action: $action";
        
        $this->log($message, $level, $context);
    }
    
    /**
     * Retrieve logs with filtering options
     * 
     * @param array $filters Filter criteria
     * @param int $limit Result limit
     * @return array Filtered logs
     */
    public function getLogs(array $filters = [], int $limit = 100): array {
        if ($this->db) {
            return $this->getLogsFromDatabase($filters, $limit);
        }
        
        return $this->getLogsFromFile($filters, $limit);
    }
    
    /**
     * Sanitize log message
     * 
     * @param string $message Raw message
     * @return string Sanitized message
     */
    private function sanitizeMessage(string $message): string {
        return htmlspecialchars(trim($message), ENT_QUOTES, 'UTF-8');
    }
    
    /**
     * Sanitize context data recursively
     * 
     * @param array $context Context data
     * @return array Sanitized context
     */
    private function sanitizeContext(array $context): array {
        array_walk_recursive($context, function(&$value) {
            if (is_string($value)) {
                $value = $this->sanitizeMessage($value);
            }
        });
        
        return $context;
    }
    
    /**
     * Format log entry for file storage
     * 
     * @param string $level Log level
     * @param string $message Log message
     * @param array $context Context data
     * @return string Formatted log entry
     */
    private function formatLogEntry(string $level, string $message, array $context): string {
        $timestamp = $context['timestamp'];
        $requestId = $context['request_id'];
        
        unset($context['timestamp'], $context['request_id']);
        $contextJson = json_encode($context);
        
        return "[$timestamp][$requestId][$level] $message | $contextJson" . PHP_EOL;
    }
    
    /**
     * Write log entry to database
     * 
     * @param string $level Log level
     * @param string $message Log message
     * @param array $context Context data
     */
    private function writeToDatabase(string $level, string $message, array $context): void {
        $stmt = $this->db->prepare(
            "INSERT INTO audit_logs (level, message, context, created_at) 
             VALUES (?, ?, ?, NOW())"
        );
        
        $stmt->execute([
            $level,
            $message,
            json_encode($context)
        ]);
    }
    
    /**
     * Write log entry to file
     * 
     * @param string $entry Formatted log entry
     */
    private function writeToFile(string $entry): void {
        if (file_put_contents($this->logFile, $entry, FILE_APPEND | LOCK_EX) === false) {
            throw new Exception('Failed to write to log file');
        }
    }
    
    /**
     * Generate unique request ID
     * 
     * @return string Request ID
     */
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
    
    /**
     * Determine appropriate log level for action
     * 
     * @param string $action User action
     * @return string Log level
     */
    private function determineActionLevel(string $action): string {
        $action = strtoupper($action);
        
        $criticalActions = ['DELETE', 'TRUNCATE', 'DROP'];
        $warningActions = ['UPDATE', 'MODIFY'];
        
        if (in_array($action, $criticalActions)) {
            return 'WARNING';
        } elseif (in_array($action, $warningActions)) {
            return 'INFO';
        }
        
        return 'DEBUG';
    }
    
    /**
     * Alert administrator about critical errors
     * 
     * @param string $message Error message
     * @param array $context Error context
     */
    private function alertAdministrator(string $message, array $context): void {
        // Implementation depends on your notification system
        // Example: Email, Slack, SMS, etc.
        // For now, we'll just log it
        error_log("CRITICAL ERROR: $message");
    }
}
