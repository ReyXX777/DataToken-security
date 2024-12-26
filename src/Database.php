<?php
namespace App;

use PDO;
use PDOException;
use Exception;

class Database {
    private static ?PDO $connection = null;
    private static array $instances = [];
    private static array $connectionParams = [];
    
    /**
     * Get database connection with optional parameters
     *
     * @param string $name Connection name (default: 'default')
     * @return PDO Active database connection
     * @throws Exception If connection fails
     */
    public static function getConnection(string $name = 'default'): PDO {
        if (!isset(self::$instances[$name])) {
            self::$instances[$name] = self::createConnection($name);
        }
        
        return self::$instances[$name];
    }
    
    /**
     * Initialize database configuration
     *
     * @param array $config Database configuration
     * @param string $name Connection name
     * @throws Exception If config is invalid
     */
    public static function init(array $config, string $name = 'default'): void {
        self::validateConfig($config);
        self::$connectionParams[$name] = $config;
    }
    
    /**
     * Create new database connection
     *
     * @param string $name Connection name
     * @return PDO New database connection
     * @throws Exception If connection fails
     */
    private static function createConnection(string $name): PDO {
        try {
            if (!isset(self::$connectionParams[$name])) {
                // Load default config if not initialized
                $config = require(__DIR__ . '/../config/config.php');
                self::init($config, $name);
            }
            
            $params = self::$connectionParams[$name];
            
            // Build DSN
            $dsn = sprintf(
                "mysql:host=%s;dbname=%s;charset=utf8mb4",
                $params['db_host'],
                $params['db_name']
            );
            
            // Set PDO options for security and performance
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_PERSISTENT => $params['persistent'] ?? false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
                PDO::MYSQL_ATTR_SSL_CA => $params['ssl_ca'] ?? null,
                PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => $params['verify_server_cert'] ?? true
            ];
            
            $connection = new PDO(
                $dsn,
                $params['db_user'],
                $params['db_pass'],
                $options
            );
            
            // Set session variables if specified
            if (isset($params['session_vars']) && is_array($params['session_vars'])) {
                foreach ($params['session_vars'] as $var => $value) {
                    $connection->exec("SET SESSION $var = " . $connection->quote($value));
                }
            }
            
            return $connection;
            
        } catch (PDOException $e) {
            throw new Exception(
                "Database connection failed: " . self::sanitizeError($e->getMessage()),
                $e->getCode(),
                $e
            );
        }
    }
    
    /**
     * Validate database configuration
     *
     * @param array $config Configuration array
     * @throws Exception If configuration is invalid
     */
    private static function validateConfig(array $config): void {
        $required = ['db_host', 'db_name', 'db_user', 'db_pass'];
        
        foreach ($required as $field) {
            if (!isset($config[$field]) || empty($config[$field])) {
                throw new Exception("Missing required database configuration: $field");
            }
        }
    }
    
    /**
     * Close specific or all database connections
     *
     * @param string|null $name Connection name (null for all)
     */
    public static function closeConnection(?string $name = null): void {
        if ($name !== null) {
            unset(self::$instances[$name]);
        } else {
            self::$instances = [];
        }
    }
    
    /**
     * Begin a transaction
     *
     * @param string $name Connection name
     * @return bool Success status
     */
    public static function beginTransaction(string $name = 'default'): bool {
        $connection = self::getConnection($name);
        return $connection->beginTransaction();
    }
    
    /**
     * Commit a transaction
     *
     * @param string $name Connection name
     * @return bool Success status
     */
    public static function commit(string $name = 'default'): bool {
        $connection = self::getConnection($name);
        return $connection->commit();
    }
    
    /**
     * Rollback a transaction
     *
     * @param string $name Connection name
     * @return bool Success status
     */
    public static function rollback(string $name = 'default'): bool {
        $connection = self::getConnection($name);
        return $connection->rollBack();
    }
    
    /**
     * Check connection status
     *
     * @param string $name Connection name
     * @return bool Whether connection is active
     */
    public static function isConnected(string $name = 'default'): bool {
        return isset(self::$instances[$name]) && self::$instances[$name] instanceof PDO;
    }
    
    /**
     * Sanitize error message to prevent sensitive data exposure
     *
     * @param string $error Original error message
     * @return string Sanitized error message
     */
    private static function sanitizeError(string $error): string {
        // Remove potential sensitive information from error messages
        $patterns = [
            '/SQLSTATE\[\d+\]/',
            '/with message \'.*\'/',
            '/\[MySQL\].*/',
            '/\[MariaDB\].*/'
        ];
        
        return preg_replace($patterns, '', $error);
    }
    
    /**
     * Prevent cloning of instance
     */
    private function __clone() {}
    
    /**
     * Prevent unserialization of instance
     */
    public function __wakeup() {
        throw new Exception("Cannot unserialize database connection");
    }
}
