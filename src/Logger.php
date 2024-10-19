<?php

class Logger {

    // Log file location
    private static $logFile = __DIR__ . '/../logs/app.log';

    // Log a message with a specific level (INFO, ERROR, etc.)
    public static function log($level, $message) {
        $timestamp = date('Y-m-d H:i:s');  // Get the current timestamp
        $logMessage = "[$timestamp] $level: $message" . PHP_EOL;  // Format log entry
        
        // Write the log entry to the file
        error_log($logMessage, 3, self::$logFile);
    }
}
