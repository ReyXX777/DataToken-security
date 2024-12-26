<?php

class Logger {

    // Log levels
    const LEVEL_INFO = 'INFO';
    const LEVEL_ERROR = 'ERROR';
    const LEVEL_WARNING = 'WARNING';
    const LEVEL_DEBUG = 'DEBUG';

    // Log file location
    private static $logFile;

    // Initialize the logger
    public static function init() {
        self::$logFile = __DIR__ . '/../logs/app.log';
        self::ensureLogFileExists();
    }

    // Ensure the log file and directory exist
    private static function ensureLogFileExists() {
        $logDir = dirname(self::$logFile);
        
        // Create the logs directory if it doesn't exist
        if (!is_dir($logDir)) {
            mkdir($logDir, 0777, true); // Create with full permissions
        }

        // Create the log file if it doesn't exist
        if (!file_exists(self::$logFile)) {
            touch(self::$logFile); // Create an empty file
            chmod(self::$logFile, 0666); // Set writable permissions
        }

        // Ensure the file is writable
        if (!is_writable(self::$logFile)) {
            throw new Exception("Log file is not writable: " . self::$logFile);
        }
    }

    // Log a message with a specific level
    public static function log($level, $message) {
        $timestamp = date('Y-m-d H:i:s');  // Get the current timestamp
        $logMessage = "[$timestamp] $level: $message" . PHP_EOL;  // Format log entry
        
        // Write the log entry to the file
        if (error_log($logMessage, 3, self::$logFile) === false) {
            throw new Exception("Failed to write to log file: " . self::$logFile);
        }
    }

    // Convenience methods for specific log levels
    public static function info($message) {
        self::log(self::LEVEL_INFO, $message);
    }

    public static function error($message) {
        self::log(self::LEVEL_ERROR, $message);
    }

    public static function warning($message) {
        self::log(self::LEVEL_WARNING, $message);
    }

    public static function debug($message) {
        self::log(self::LEVEL_DEBUG, $message);
    }
}

// Initialize the logger
Logger::init();
