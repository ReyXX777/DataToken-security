<?php
// Define the path for the log file
$logDir = "../logs";
$logFile = "$logDir/app.log";

// Ensure the log directory exists
if (!is_dir($logDir)) {
    mkdir($logDir, 0777, true);
}

// Function to log errors
function logError($message, $level = 'ERROR') {
    global $logFile;

    // Create a timestamp
    $timestamp = date("Y-m-d H:i:s");

    // Format the log message
    $logMessage = "[$timestamp] - $level - $message" . PHP_EOL;

    // Write to log file
    file_put_contents($logFile, $logMessage, FILE_APPEND);
}

// Function to handle user actions
function logUserAction($username, $action) {
    global $logFile;
    $timestamp = date("Y-m-d H:i:s");

    if ($action === "DELETE") {
        $level = "WARNING";
        $logMessage = "[$timestamp] - $level - User '$username' attempted a DELETE action.";
    } else {
        $level = "INFO";
        $logMessage = "[$timestamp] - $level - User '$username' performed action: $action.";
    }

    file_put_contents($logFile, $logMessage . PHP_EOL, FILE_APPEND);
}

// Example usage
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? 'Guest';
    $action = $_POST['action'] ?? 'UNKNOWN';

    try {
        logUserAction($username, $action);

        if ($action === "DELETE") {
            // Simulate an error for DELETE action
            throw new Exception("Unauthorized DELETE action attempted.");
        }

        echo "Action logged successfully.";
    } catch (Exception $e) {
        logError("User '$username' encountered an error: " . $e->getMessage());
        echo "An error occurred. Please contact support.";
    }
}
?>
