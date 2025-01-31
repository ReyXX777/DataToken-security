<?php
declare(strict_types=1);

namespace App;

use PDO;
use PDOException;
use Exception;

class Database {
    private static ?array $instances = [];
    private static array $connectionParams = [];

    /**
     * Get a database connection.
     *
     * @param string $name Connection name (default: 'default').
     * @return PDO Active database connection.
     * @throws Exception If connection fails.
     */
    public static function getConnection(string $name = 'default'): PDO {
        if (!isset(self::$instances[$name])) {
            self::$instances[$name] = self::createConnection($name);
        }

        return self::$instances[$name];
    }

    /**
     * Initialize database configuration.
     *
     * @param array $config Database configuration.
     * @param string $name Connection name.
     * @throws Exception If config is invalid.
     */
    public static function init(array $config, string $name = 'default'): void {
        self::validateConfig($config);
        self::$connectionParams[$name] = $config;
    }

    /**
     * Create a new database connection.
     *
     * @param string $name Connection name.
     * @return PDO New database connection.
     * @throws Exception If connection fails.
     */
    private static function createConnection(string $name): PDO {
        if (!isset(self::$connectionParams[$name])) {
            $defaultConfig = require(__DIR__ . '/../config/config.php');
            self::init($defaultConfig, $name);
        }

        $params = self::$connectionParams[$name];
        $dsn = sprintf("mysql:host=%s;dbname=%s;charset=utf8mb4", $params['db_host'], $params['db_name']);

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_PERSISTENT => $params['persistent'] ?? false,
        ];

        // Add SSL options if provided
        if (!empty($params['ssl_ca'])) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = $params['ssl_ca'];
        }

        if (isset($params['verify_server_cert'])) {
            $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = $params['verify_server_cert'];
        }

        try {
            $connection = new PDO($dsn, $params['db_user'], $params['db_pass'], $options);

            // Set session variables if specified
            if (isset($params['session_vars']) && is_array($params['session_vars'])) {
                foreach ($params['session_vars'] as $var => $value) {
                    $connection->exec("SET SESSION $var = " . $connection->quote((string)$value));
                }
            }

            return $connection;
        } catch (PDOException $e) {
            throw new Exception("Database connection failed: " . self::sanitizeError($e->getMessage()), $e->getCode(), $e);
        }
    }

    /**
     * Validate database configuration.
     *
     * @param array $config Configuration array.
     * @throws Exception If configuration is invalid.
     */
    private static function validateConfig(array $config): void {
        $required = ['db_host', 'db_name', 'db_user', 'db_pass'];

        foreach ($required as $field) {
            if (empty($config[$field])) {
                throw new Exception("Missing required database configuration: $field");
            }
        }
    }

    /**
     * Close specific or all database connections.
     *
     * @param string|null $name Connection name (null for all).
     */
    public static function closeConnection(?string $name = null): void {
        if ($name !== null) {
            unset(self::$instances[$name]);
        } else {
            self::$instances = [];
        }
    }

    /**
     * Begin a transaction.
     *
     * @param string $name Connection name.
     * @return bool Success status.
     */
    public static function beginTransaction(string $name = 'default'): bool {
        return self::getConnection($name)->beginTransaction();
    }

    /**
     * Commit a transaction.
     *
     * @param string $name Connection name.
     * @return bool Success status.
     */
    public static function commit(string $name = 'default'): bool {
        return self::getConnection($name)->commit();
    }

    /**
     * Rollback a transaction.
     *
     * @param string $name Connection name.
     * @return bool Success status.
     */
    public static function rollback(string $name = 'default'): bool {
        return self::getConnection($name)->rollBack();
    }

    /**
     * Check connection status.
     *
     * @param string $name Connection name.
     * @return bool Whether connection is active.
     */
    public static function isConnected(string $name = 'default'): bool {
        return isset(self::$instances[$name]) && self::$instances[$name] instanceof PDO;
    }

    /**
     * Sanitize error messages to prevent sensitive data exposure.
     *
     * @param string $error Original error message.
     * @return string Sanitized error message.
     */
    private static function sanitizeError(string $error): string {
        return preg_replace('/(SQLSTATE\[\d+\]|with message \'.*\')/', '', $error);
    }

    /**
     * Prevent cloning of instance.
     */
    private function __clone() {}

    /**
     * Prevent unserialization of instance.
     */
    public function __wakeup(): void {
        throw new Exception("Cannot unserialize database connection");
    }

    // New component: Connection Pooling
    public static function getConnectionPoolSize(): int {
        return count(self::$instances);
    }

    public static function clearConnectionPool(): void {
        self::$instances = [];
    }

    // New component: Query Logger
    public static function logQuery(string $query, array $params = [], string $name = 'default'): void {
        if (isset(self::$connectionParams[$name]['query_log'])) {
            $logEntry = [
                'timestamp' => date('Y-m-d H:i:s'),
                'query' => $query,
                'params' => $params,
                'connection' => $name,
            ];
            file_put_contents(
                self::$connectionParams[$name]['query_log'],
                json_encode($logEntry) . PHP_EOL,
                FILE_APPEND
            );
        }
    }

    // New component: Connection Health Check
    public static function checkConnectionHealth(string $name = 'default'): bool {
        try {
            $connection = self::getConnection($name);
            $connection->query('SELECT 1');
            return true;
        } catch (PDOException $e) {
            return false;
        }
    }

    // New component: Connection Statistics
    public static function getConnectionStatistics(string $name = 'default'): array {
        if (!self::isConnected($name)) {
            return [];
        }

        $connection = self::getConnection($name);
        return [
            'connection_name' => $name,
            'status' => $connection->getAttribute(PDO::ATTR_CONNECTION_STATUS),
            'server_version' => $connection->getAttribute(PDO::ATTR_SERVER_VERSION),
            'client_version' => $connection->getAttribute(PDO::ATTR_CLIENT_VERSION),
            'time_connected' => time() - $connection->getAttribute(PDO::ATTR_TIMEOUT),
        ];
    }
}
