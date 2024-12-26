<?php

class MFA {

    // Length of the OTP (typically 6 digits)
    const OTP_LENGTH = 6;

    // Time step for TOTP (typically 30 seconds)
    const TIME_STEP = 30;

    // Generate a secure secret key for TOTP
    public static function generateSecretKey() {
        return bin2hex(random_bytes(16));  // 16 bytes = 128 bits
    }

    // Generate a TOTP using the secret key
    public static function generateTOTP($secretKey) {
        // Get the current time step
        $timeStep = floor(time() / self::TIME_STEP);

        // Pack the time step into a binary string
        $timeStepBinary = pack('J', $timeStep);

        // Generate the HMAC hash using SHA1
        $hmac = hash_hmac('sha1', $timeStepBinary, hex2bin($secretKey), true);

        // Get the offset from the last nibble of the HMAC
        $offset = ord($hmac[strlen($hmac) - 1]) & 0x0F;

        // Extract the 4-byte dynamic binary code
        $dynamicBinaryCode = substr($hmac, $offset, 4);

        // Unpack the binary code into an integer
        $dynamicCode = unpack('N', $dynamicBinaryCode)[1] & 0x7FFFFFFF;

        // Generate the OTP by taking the last OTP_LENGTH digits
        $otp = str_pad($dynamicCode % pow(10, self::OTP_LENGTH), self::OTP_LENGTH, '0', STR_PAD_LEFT);

        return $otp;
    }

    // Verify a user-provided OTP against the generated TOTP
    public static function verifyTOTP($secretKey, $userOTP) {
        // Generate the expected TOTP
        $expectedOTP = self::generateTOTP($secretKey);

        // Compare the user-provided OTP with the expected OTP
        return hash_equals($expectedOTP, $userOTP);
    }

    // Generate a QR code URL for adding the secret key to an authenticator app
    public static function getQRCodeUrl($secretKey, $issuer, $accountName) {
        $encodedIssuer = rawurlencode($issuer);
        $encodedAccountName = rawurlencode($accountName);
        return "otpauth://totp/$encodedIssuer:$encodedAccountName?secret=$secretKey&issuer=$encodedIssuer";
    }
}
