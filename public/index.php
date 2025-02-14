<?php
namespace App;

require_once(__DIR__ . '/../vendor/autoload.php');

use Exception;
use PDO;

session_start();

// Secure session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1); // Use only in HTTPS environments
ini_set('session.use_strict_mode', 1);

// Initialize services
try {
    $config = require_once(__DIR__ . '/../config/config.php');
    
    $pdo = new PDO(
        "mysql:host={$config['db_host']};dbname={$config['db_name']};charset=utf8mb4",
        $config['db_user'],
        $config['db_pass'],
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
    
    $logger = new Logger($pdo);
    $token = new Token($pdo, $logger);
    
    // CSRF Protection
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception('CSRF token validation failed');
        }
    }
    
    $message = '';
    $error = '';
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['tokenize']) && !empty($_POST['sensitive_data'])) {
            $sensitiveData = filter_input(INPUT_POST, 'sensitive_data', FILTER_SANITIZE_STRING);
            if ($sensitiveData) {
                try {
                    $result = $token->generateToken($sensitiveData);
                    $message = "Token generated successfully";
                    $generatedToken = $result['token'];
                    
                    $logger->logUserAction(
                        $_SESSION['username'] ?? 'guest',
                        'TOKENIZE',
                        ['data_length' => strlen($sensitiveData)]
                    );
                } catch (Exception $e) {
                    $error = "Failed to tokenize data";
                    $logger->log($e->getMessage(), 'ERROR');
                }
            } else {
                $error = "Invalid sensitive data";
            }
        } elseif (isset($_POST['detokenize']) && !empty($_POST['token'])) {
            $inputToken = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_STRING);
            if ($inputToken) {
                try {
                    $result = $token->detokenize($inputToken);
                    
                    if ($result) {
                        $message = "Data retrieved successfully";
                        $retrievedData = $result['data'];
                        
                        $logger->logUserAction(
                            $_SESSION['username'] ?? 'guest',
                            'DETOKENIZE',
                            ['token' => $inputToken]
                        );
                    } else {
                        throw new Exception('Invalid token');
                    }
                } catch (Exception $e) {
                    $error = "Failed to retrieve data";
                    $logger->log($e->getMessage(), 'ERROR');
                }
            } else {
                $error = "Invalid token input";
            }
        }
    }
} catch (Exception $e) {
    $error = "System error occurred: " . htmlspecialchars($e->getMessage());
    error_log($e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
    <title>SecureToken - Enterprise Tokenization System</title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
    <header>
        <h1>SecureToken</h1>
        <p class="subtitle">Enterprise-Grade Data Security Solution</p>
    </header>

    <main>
        <?php if ($error): ?>
            <div id="error-message" class="alert alert-error">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <?php if ($message): ?>
            <div id="success-message" class="alert alert-success">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <section id="tokenize-section" class="card">
            <h2>Tokenize Sensitive Data</h2>
            <form method="POST" id="tokenize-form" class="secure-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                
                <div class="input-group">
                    <label for="sensitive-data">Sensitive Data</label>
                    <input 
                        type="text" 
                        id="sensitive-data" 
                        name="sensitive_data" 
                        placeholder="Enter sensitive data" 
                        required 
                        autocomplete="off"
                    >
                </div>

                <div class="button-group">
                    <button type="submit" name="tokenize" class="primary">
                        Tokenize Data
                    </button>
                </div>
            </form>
        </section>

        <section id="detokenize-section" class="card">
            <h2>Retrieve Data</h2>
            <form method="POST" id="detokenize-form" class="secure-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                
                <div class="input-group">
                    <label for="token-input">Token</label>
                    <input 
                        type="text" 
                        id="token-input" 
                        name="token" 
                        placeholder="Enter token" 
                        required 
                        pattern="[A-Za-z0-9\-]+"
                    >
                </div>

                <div class="button-group">
                    <button type="submit" name="detokenize" class="primary">
                        Retrieve Data
                    </button>
                </div>
            </form>
        </section>

        <!-- New component: Token Vault -->
        <section id="token-vault" class="card">
            <h2>Token Vault</h2>
            <div class="vault-content">
                <?php
                $tokens = $token->getVault();
                if (!empty($tokens)) {
                    echo '<ul>';
                    foreach ($tokens as $tokenEntry) {
                        echo '<li>' . htmlspecialchars($tokenEntry['token']) . ' - ' . htmlspecialchars($tokenEntry['created_at']) . '</li>';
                    }
                    echo '</ul>';
                } else {
                    echo '<p>No tokens found.</p>';
                }
                ?>
            </div>
        </section>

        <!-- New component: Activity Log -->
        <section id="activity-log" class="card">
            <h2>Activity Log</h2>
            <div class="log-content">
                <?php
                $logs = $logger->getLogs(10);
                if (!empty($logs)) {
                    echo '<ul>';
                    foreach ($logs as $log) {
                        echo '<li>' . htmlspecialchars($log['message']) . '</li>';
                    }
                    echo '</ul>';
                } else {
                    echo '<p>No activity logs found.</p>';
                }
                ?>
            </div>
        </section>

        <!-- New component: Token Statistics -->
        <section id="token-statistics" class="card">
            <h2>Token Statistics</h2>
            <div class="statistics-content">
                <?php
                $stats = $token->getTokenStatistics();
                if (!empty($stats)) {
                    echo '<ul>';
                    echo '<li>Total Tokens: ' . htmlspecialchars($stats['total_tokens']) . '</li>';
                    echo '<li>Active Tokens: ' . htmlspecialchars($stats['active_tokens']) . '</li>';
                    echo '<li>Expired Tokens: ' . htmlspecialchars($stats['expired_tokens']) . '</li>';
                    echo '</ul>';
                } else {
                    echo '<p>No statistics available.</p>';
                }
                ?>
            </div>
        </section>

        <!-- New component: User Activity Dashboard -->
        <section id="user-activity-dashboard" class="card">
            <h2>User Activity Dashboard</h2>
            <div class="dashboard-content">
                <?php
                $userActivities = $logger->getUserActivities(10);
                if (!empty($userActivities)) {
                    echo '<ul>';
                    foreach ($userActivities as $activity) {
                        echo '<li>' . htmlspecialchars($activity['username']) . ' - ' . htmlspecialchars($activity['action']) . ' - ' . htmlspecialchars($activity['timestamp']) . '</li>';
                    }
                    echo '</ul>';
                } else {
                    echo '<p>No user activities found.</p>';
                }
                ?>
            </div>
        </section>

        <!-- New component: Token Expiry Notifications -->
        <section id="token-expiry-notifications" class="card">
            <h2>Token Expiry Notifications</h2>
            <div class="notifications-content">
                <?php
                $expiringTokens = $token->getExpiringTokens();
                if (!empty($expiringTokens)) {
                    echo '<ul>';
                    foreach ($expiringTokens as $token) {
                        echo '<li>' . htmlspecialchars($token['token']) . ' - Expires on: ' . htmlspecialchars($token['expiry_date']) . '</li>';
                    }
                    echo '</ul>';
                } else {
                    echo '<p>No tokens expiring soon.</p>';
                }
                ?>
            </div>
        </section>

        <!-- New component: Token Usage Analytics -->
        <section id="token-usage-analytics" class="card">
            <h2>Token Usage Analytics</h2>
            <div class="analytics-content">
                <?php
                $usageAnalytics = $token->getTokenUsageAnalytics();
                if (!empty($usageAnalytics)) {
                    echo '<ul>';
                    foreach ($usageAnalytics as $analytic) {
                        echo '<li>' . htmlspecialchars($analytic['token']) . ' - Used: ' . htmlspecialchars($analytic['usage_count']) . ' times</li>';
                    }
                    echo '</ul>';
                } else {
                    echo '<p>No usage analytics available.</p>';
                }
                ?>
            </div>
        </section>
    </main>

    <footer>
        <p>&copy; <?php echo date('Y'); ?> SecureToken. All rights reserved.</p>
    </footer>
</body>
</html>
