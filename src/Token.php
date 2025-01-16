<?php
require_once('Database.php');  // Include the database connection

class Token {

    // Encryption key (should be securely stored, e.g., in environment variables)
    private static $encryptionKey;

    // Initialize the encryption key from environment variables
    public static function init() {
        self::$encryptionKey = getenv('ENCRYPTION_KEY');  // Fetch from environment variables
        if (empty(self::$encryptionKey)) {
            throw new Exception("Encryption key is not set.");
        }
    }

    // Tokenize sensitive data and store it in the database
    public static function tokenize($sensitiveData, $expiry = null) {
        try {
            // Validate sensitive data
            if (empty($sensitiveData)) {
                throw new InvalidArgumentException("Sensitive data cannot be empty.");
            }

            $db = Database::getConnection();  // Get database connection

            // Create a unique token (16-character hexadecimal)
            $token = bin2hex(random_bytes(16)); // Securely generated token

            // Encrypt sensitive data before storing
            $encryptedData = self::encryptData($sensitiveData);

            // Set default expiry to 30 days if not provided
            if (!$expiry) {
                $expiry = date('Y-m-d H:i:s', strtotime('+30 days'));
            }

            // Insert the token, encrypted sensitive data, and expiry into the database
            $query = $db->prepare("INSERT INTO tokens (sensitive_data, token, created_at, expires_at) VALUES (?, ?, NOW(), ?)");
            $query->execute([$encryptedData, $token, $expiry]);

            // Return the token
            return $token;
        } catch (Exception $e) {
            error_log("Error in tokenization: " . $e->getMessage());  // Log any errors
            return false;  // Return false on error
        }
    }

    // Detokenize and retrieve the original data using the token
    public static function detokenize($token) {
        try {
            // Validate token format
            if (!self::isValidToken($token)) {
                throw new InvalidArgumentException("Invalid token format.");
            }

            $db = Database::getConnection();  // Get database connection

            // Query the database for the token
            $query = $db->prepare("SELECT sensitive_data, expires_at FROM tokens WHERE token = ?");
            $query->execute([$token]);

            $result = $query->fetch();
            if ($result) {
                // Check if the token has expired
                if ($result['expires_at'] && strtotime($result['expires_at']) < time()) {
                    return 'Token has expired';  // Return error message if token is expired
                }

                // Decrypt the sensitive data
                $decryptedData = self::decryptData($result['sensitive_data']);
                return $decryptedData;  // Return the original sensitive data
            } else {
                return 'Token not found';  // Return error message if token is not found
            }
        } catch (Exception $e) {
            error_log("Error in detokenization: " . $e->getMessage());  // Log any errors
            return false;  // Return false on error
        }
    }

    // Encrypt sensitive data before storing it
    private static function encryptData($data) {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));  // Generate a random IV

        // Encrypt the data using AES-256-CBC encryption
        $encryptedData = openssl_encrypt($data, 'aes-256-cbc', self::$encryptionKey, 0, $iv);
        return base64_encode($encryptedData . '::' . $iv);  // Encode encrypted data and IV as base64
    }

    // Decrypt the sensitive data when retrieving it
    private static function decryptData($encryptedData) {
        list($encryptedData, $iv) = explode('::', base64_decode($encryptedData), 2);  // Split data and IV

        // Decrypt the data using AES-256-CBC
        return openssl_decrypt($encryptedData, 'aes-256-cbc', self::$encryptionKey, 0, $iv);
    }

    // Validate the token format (16-character hexadecimal)
    private static function isValidToken($token) {
        return preg_match('/^[a-f0-9]{32}$/', $token);
    }

    // New component: Token expiration check
    public static function isTokenExpired($token) {
        try {
            if (!self::isValidToken($token)) {
                throw new InvalidArgumentException("Invalid token format.");
            }

            $db = Database::getConnection();  // Get database connection

            // Query the database for the token's expiry
            $query = $db->prepare("SELECT expires_at FROM tokens WHERE token = ?");
            $query->execute([$token]);

            $result = $query->fetch();
            if ($result) {
                return $result['expires_at'] && strtotime($result['expires_at']) < time();
            } else {
                throw new Exception("Token not found.");
            }
        } catch (Exception $e) {
            error_log("Error checking token expiration: " . $e->getMessage());
            return false;
        }
    }

    // New component: Token revocation
    public static function revokeToken($token) {
        try {
            if (!self::isValidToken($token)) {
                throw new InvalidArgumentException("Invalid token format.");
            }

            $db = Database::getConnection();  // Get database connection

            // Mark the token as revoked in the database
            $query = $db->prepare("UPDATE tokens SET status = 'revoked' WHERE token = ?");
            $query->execute([$token]);

            return $query->rowCount() > 0;  // Return true if the token was revoked
        } catch (Exception $e) {
            error_log("Error revoking token: " . $e->getMessage());
            return false;
        }
    }
}

// Initialize the encryption key
Token::init();
