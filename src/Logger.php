<?php

class Logger {

    // Log levels
    const LEVEL_INFO = 'INFO';
    const LEVEL_ERROR = 'ERROR';
    const LEVEL_WARNING = 'WARNING';
    const LEVEL_DEBUG = 'DEBUG';

    // Log file location
    private static string $logFile;

    // Initialize the logger
    public static function init(string $logFile = '/../logs/app.log') {
        self::$logFile = __DIR__ . $logFile;
        self::ensureLogFileExists();
    }

    // Ensure the log file and directory exist
    private static function ensureLogFileExists(): void {
        $logDir = dirname(self::$logFile);
        
        // Create the logs directory if it doesn't exist
        if (!is_dir($logDir)) {
            if (!mkdir($logDir, 0777, true)) {
                throw new Exception("Failed to create log directory: " . $logDir);
            }
        }

        // Create the log file if it doesn't exist
        if (!file_exists(self::$logFile)) {
            if (!touch(self::$logFile)) {
                throw new Exception("Failed to create log file: " . self::$logFile);
            }
            chmod(self::$logFile, 0666); // Set writable permissions
        }

        // Ensure the file is writable
        if (!is_writable(self::$logFile)) {
            throw new Exception("Log file is not writable: " . self::$logFile);
        }
    }

    // Log a message with a specific level
    public static function log(string $level, string $message): void {
        $timestamp = date('Y-m-d H:i:s');  // Get the current timestamp
        $logMessage = "[$timestamp] $level: $message" . PHP_EOL;  // Format log entry
        
        // Write the log entry to the file
        if (error_log($logMessage, 3, self::$logFile) === false) {
            // If the write fails, log to a separate error log file
            self::log(self::LEVEL_ERROR, "Failed to write to log file: " . self::$logFile);
            throw new Exception("Failed to write to log file: " . self::$logFile);
        }
    }

    // Convenience methods for specific log levels
    public static function info(string $message): void {
        self::log(self::LEVEL_INFO, $message);
    }

    public static function error(string $message): void {
        self::log(self::LEVEL_ERROR, $message);
    }

    public static function warning(string $message): void {
        self::log(self::LEVEL_WARNING, $message);
    }

    public static function debug(string $message): void {
        self::log(self::LEVEL_DEBUG, $message);
    }

    // Optional log rotation (simple size-based rotation)
    public static function rotateLog(int $maxSize = 10485760): void { // 10MB default size
        if (filesize(self::$logFile) > $maxSize) {
            $backupFile = self::$logFile . '.' . date('YmdHis');
            if (!rename(self::$logFile, $backupFile)) {
                throw new Exception("Failed to rotate log file: " . self::$logFile);
            }
            self::ensureLogFileExists(); // Recreate a new empty log file
        }
    }

    // New component: Log filtering by level
    public static function getLogsByLevel(string $level, int $limit = 100): array {
        $logs = [];
        $lines = file(self::$logFile);
        $lines = array_reverse(array_slice($lines, -$limit));

        foreach ($lines as $line) {
            if (strpos($line, "[$level]") !== false) {
                $logs[] = ['message' => trim($line)];
            }
        }

        return $logs;
    }

    // New component: Log search functionality
    public static function searchLogs(string $query, int $limit = 100): array {
        $logs = [];
        $lines = file(self::$logFile);
        $lines = array_reverse(array_slice($lines, -$limit));

        foreach ($lines as $line) {
            if (strpos($line, $query) !== false) {
                $logs[] = ['message' => trim($line)];
            }
        }

        return $logs;
    }
}

// Initialize the logger with a custom log file location if necessary
Logger::init(); 

// Example of using the Logger
Logger::info('This is an informational message');
Logger::error('This is an error message');
Logger::warning('This is a warning message');
Logger::debug('This is a debug message');

// Example of using the new components
$infoLogs = Logger::getLogsByLevel(Logger::LEVEL_INFO);
$searchResults = Logger::searchLogs('error');
