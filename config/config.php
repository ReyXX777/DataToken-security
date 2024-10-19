<?php
/**
 * Configuration file for the Secure Token Project
 * This file contains the database connection settings and other global configurations.
 */

return [
    // Database connection settings
    'db_host' => 'localhost',          // MySQL host (usually localhost)
    'db_name' => 'secure_token_db',    // The name of the database
    'db_user' => 'your_username',      // Your MySQL username
    'db_pass' => 'your_password',      // Your MySQL password

    // Other global settings (you can add more here if needed)
    'app_name' => 'Secure Token System',  // Application name
    'app_env'  => 'development',          // Environment: 'development' or 'production'
    'log_file' => __DIR__ . '/../logs/app.log',  // Path to the application log file
];
