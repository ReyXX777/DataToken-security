<?php
/**
 * Configuration file for the Secure Token Project
 * This file contains the database connection settings and other global configurations.
 * 
 * Note: For sensitive data (e.g., database credentials), use environment variables
 * instead of hardcoding them in this file.
 */

// Load environment variables (if using a .env file)
if (file_exists(__DIR__ . '/../.env')) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
    $dotenv->load();
}

// Configuration array
return [
    // Database connection settings
    'db_host' => getenv('DB_HOST') ?: 'localhost',          // MySQL host (usually localhost)
    'db_name' => getenv('DB_NAME') ?: 'secure_token_db',    // The name of the database
    'db_user' => getenv('DB_USER') ?: 'your_username',      // Your MySQL username
    'db_pass' => getenv('DB_PASSWORD') ?: 'your_password',  // Your MySQL password

    // Other global settings (you can add more here if needed)
    'app_name' => getenv('APP_NAME') ?: 'Secure Token System',  // Application name
    'app_env'  => getenv('APP_ENV') ?: 'development',           // Environment: 'development' or 'production'
    'log_file' => __DIR__ . '/../logs/app.log',                 // Path to the application log file

    // Encryption settings (for tokenization, etc.)
    'encryption_key' => getenv('ENCRYPTION_KEY') ?: 'mysecretkey',  // Encryption key for sensitive data
];

// Validate critical configuration values
if (empty($config['db_host']) || empty($config['db_name']) || empty($config['db_user'])) {
    throw new RuntimeException("Database configuration is incomplete. Please check your settings.");
}

if (empty($config['encryption_key'])) {
    throw new RuntimeException("Encryption key is missing. Please set it in your environment variables.");
}
