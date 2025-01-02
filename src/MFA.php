<?php

class MFA {

    // Length of the OTP (typically 6 digits)
    const OTP_LENGTH = 6;

    // Time step for TOTP (typically 30 seconds)
    const TIME_STEP = 30;

    // Allowed time drift for tolerance (e.g., 1 time step before and after the current time step)
    const TIME_DRIFT = 1;

    // Generate a secure secret key for TOTP
    public static function generateSecretKey(): string {
        return bin2hex(random_bytes(16));  // 16 bytes = 128 bits
    }

    // Generate a TOTP using the secret key
    public static function generateTOTP(string $secretKey): string {
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
    public static function verifyTOTP(string $secretKey, string $userOTP): bool {
        // Validate the user OTP
        if (!self::isValidOTP($userOTP)) {
            throw new InvalidArgumentException("Invalid OTP format.");
        }

        // Generate the expected TOTP
        $expectedOTP = self::generateTOTP($secretKey);

        // Compare the user-provided OTP with the expected OTP
        return hash_equals($expectedOTP, $userOTP);
    }

    // Validate the format of the OTP
    private static function isValidOTP(string $otp): bool {
        // OTP should be a numeric string with exactly OTP_LENGTH digits
        return preg_match('/^\d{' . self::OTP_LENGTH . '}$/', $otp);
    }

    // Generate a QR code URL for adding the secret key to an authenticator app
    public static function getQRCodeUrl(string $secretKey, string $issuer, string $accountName): string {
        $encodedIssuer = rawurlencode($issuer);
        $encodedAccountName = rawurlencode($accountName);
        return "otpauth://totp/$encodedIssuer:$encodedAccountName?secret=$secretKey&issuer=$encodedIssuer";
    }

    // Generate a QR code image (using an external library like PHP QR Code)
    public static function generateQRCode(string $url): string {
        // You need to install and use a library like "PHP QR Code" to generate an actual QR code image
        // For example, using `phpqrcode` library:
        // require_once 'phpqrcode/qrlib.php';
        // $qrFile = '/path/to/save/qrcode.png';
        // QRcode::png($url, $qrFile);
        // return $qrFile;
        
        // For the sake of this example, we'll return the URL to the QR code
        return $url;
    }

    // Verify OTP with time drift window (allow time drift before and after the current time)
    public static function verifyTOTPWithDrift(string $secretKey, string $userOTP): bool {
        $currentTOTP = self::generateTOTP($secretKey);

        // Check current OTP
        if (hash_equals($currentTOTP, $userOTP)) {
            return true;
        }

        // Check previous time step (time drift tolerance)
        $timeStepBefore = floor((time() - self::TIME_STEP) / self::TIME_STEP);
        $timeStepBinaryBefore = pack('J', $timeStepBefore);
        $hmacBefore = hash_hmac('sha1', $timeStepBinaryBefore, hex2bin($secretKey), true);
        $offsetBefore = ord($hmacBefore[strlen($hmacBefore) - 1]) & 0x0F;
        $dynamicBinaryCodeBefore = substr($hmacBefore, $offsetBefore, 4);
        $dynamicCodeBefore = unpack('N', $dynamicBinaryCodeBefore)[1] & 0x7FFFFFFF;
        $otpBefore = str_pad($dynamicCodeBefore % pow(10, self::OTP_LENGTH), self::OTP_LENGTH, '0', STR_PAD_LEFT);

        if (hash_equals($otpBefore, $userOTP)) {
            return true;
        }

        // Check next time step (time drift tolerance)
        $timeStepAfter = floor((time() + self::TIME_STEP) / self::TIME_STEP);
        $timeStepBinaryAfter = pack('J', $timeStepAfter);
        $hmacAfter = hash_hmac('sha1', $timeStepBinaryAfter, hex2bin($secretKey), true);
        $offsetAfter = ord($hmacAfter[strlen($hmacAfter) - 1]) & 0x0F;
        $dynamicBinaryCodeAfter = substr($hmacAfter, $offsetAfter, 4);
        $dynamicCodeAfter = unpack('N', $dynamicBinaryCodeAfter)[1] & 0x7FFFFFFF;
        $otpAfter = str_pad($dynamicCodeAfter % pow(10, self::OTP_LENGTH), self::OTP_LENGTH, '0', STR_PAD_LEFT);

        return hash_equals($otpAfter, $userOTP);
    }
}
