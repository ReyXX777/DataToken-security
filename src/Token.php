<?php
require_once('Database.php');  // Include the database connection

class Token {

    // Tokenize sensitive data and store it in the database
    public static function tokenize($sensitiveData) {
        try {
            $db = Database::getConnection();  // Get database connection

            // Create a unique token (16-character hexadecimal)
            $token = bin2hex(random_bytes(16)); // Securely generated token

            // Encrypt sensitive data before storing
            $encryptedData = self::encryptData($sensitiveData);

            // Insert the token and encrypted sensitive data into the database
            $query = $db->prepare("INSERT INTO tokens (sensitive_data, token, created_at) VALUES (?, ?, NOW())");
            $query->execute([$encryptedData, $token]);

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
            $db = Database::getConnection();  // Get database connection

            // Query the database for the token
            $query = $db->prepare("SELECT sensitive_data FROM tokens WHERE token = ?");
            $query->execute([$token]);

            $result = $query->fetch();
            if ($result) {
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
        $encryptionKey = 'mysecretkey';  // Replace with a secure encryption key
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));  // Generate a random IV

        // Encrypt the data using AES-256-CBC encryption
        $encryptedData = openssl_encrypt($data, 'aes-256-cbc', $encryptionKey, 0, $iv);
        return base64_encode($encryptedData . '::' . $iv);  // Encode encrypted data and IV as base64
    }

    // Decrypt the sensitive data when retrieving it
    private static function decryptData($encryptedData) {
        $encryptionKey = 'mysecretkey';  // Use the same key used for encryption
        list($encryptedData, $iv) = explode('::', base64_decode($encryptedData), 2);  // Split data and IV

        // Decrypt the data using AES-256-CBC
        return openssl_decrypt($encryptedData, 'aes-256-cbc', $encryptionKey, 0, $iv);
    }
}
