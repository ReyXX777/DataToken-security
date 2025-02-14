<?php
/**
 * Configuration file for the Secure Token Project
 * This file contains the database connection settings and other global configurations.
 * 
 * Note: For sensitive data (e.g., database credentials), use environment variables
 * instead of hardcoding them in this file.
 */

// Load environment variables (if using a .env file)
require_once __DIR__ . '/../vendor/autoload.php'; // Ensure Composer's autoloader is loaded

if (file_exists(__DIR__ . '/../.env')) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
    $dotenv->load();
}

// Configuration array
$config = [
    // Database connection settings
    'db_host' => getenv('DB_HOST') ?: 'localhost',          // MySQL host (default: localhost)
    'db_name' => getenv('DB_NAME') ?: 'secure_token_db',    // Database name (default: secure_token_db)
    'db_user' => getenv('DB_USER') ?: 'your_username',      // MySQL username (default: your_username)
    'db_pass' => getenv('DB_PASSWORD') ?: 'your_password',  // MySQL password (default: your_password)

    // Other global settings
    'app_name' => getenv('APP_NAME') ?: 'Secure Token System',  // Application name
    'app_env'  => getenv('APP_ENV') ?: 'development',           // Environment: 'development' or 'production'
    'log_file' => __DIR__ . '/../logs/app.log',                 // Path to the log file

    // Encryption settings
    'encryption_key' => getenv('ENCRYPTION_KEY') ?: 'mysecretkey',  // Encryption key (use a secure key)

    // New components added
    'token_expiry' => getenv('TOKEN_EXPIRY') ?: 3600,              // Token expiry time in seconds (default: 1 hour)
    'max_login_attempts' => getenv('MAX_LOGIN_ATTEMPTS') ?: 5,     // Maximum login attempts before lockout (default: 5)
    'session_timeout' => getenv('SESSION_TIMEOUT') ?: 1800,        // Session timeout in seconds (default: 30 minutes)
    'api_rate_limit' => getenv('API_RATE_LIMIT') ?: 100,           // API rate limit per minute (default: 100 requests)
    'enable_two_factor_auth' => getenv('ENABLE_TWO_FACTOR_AUTH') ?: true, // Enable two-factor authentication (default: true)
    'password_reset_timeout' => getenv('PASSWORD_RESET_TIMEOUT') ?: 600,  // Password reset timeout in seconds (default: 10 minutes)
    'enable_csrf_protection' => getenv('ENABLE_CSRF_PROTECTION') ?: true, // Enable CSRF protection (default: true)
    'default_timezone' => getenv('DEFAULT_TIMEZONE') ?: 'UTC',            // Default timezone (default: UTC)
    'enable_maintenance_mode' => getenv('ENABLE_MAINTENANCE_MODE') ?: false, // Enable maintenance mode (default: false)
];

// Validate critical configuration values
if (empty($config['db_host']) || empty($config['db_name']) || empty($config['db_user'])) {
    throw new RuntimeException(
        "Database configuration is incomplete. Please check your .env file or configuration settings."
    );
}

if (empty($config['encryption_key']) || $config['encryption_key'] === 'mysecretkey') {
    throw new RuntimeException(
        "Encryption key is missing or insecure. Please set a secure key in your .env file."
    );
}

// Return the configuration array
return $config;
