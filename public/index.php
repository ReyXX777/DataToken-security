<?php
namespace App;

require_once(__DIR__ . '/../vendor/autoload.php');

use Exception;
use PDO;

session_start();

// Initialize services
try {
    $config = require_once(__DIR__ . '/../config/config.php');
    $pdo = new PDO(
        "mysql:host={$config['db_host']};dbname={$config['db_name']};charset=utf8mb4",
        $config['db_user'],
        $config['db_pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
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
            try {
                $sensitiveData = trim($_POST['sensitive_data']);
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
        } elseif (isset($_POST['detokenize']) && !empty($_POST['token'])) {
            try {
                $inputToken = trim($_POST['token']);
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
        }
    }
} catch (Exception $e) {
    $error = "System error occurred";
    error_log($e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?php echo $_SESSION['csrf_token']; ?>">
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
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                
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
                    <button type="button" id="view-vault-btn" class="secondary">
                        View Vault
                    </button>
                </div>
            </form>

            <?php if (isset($generatedToken)): ?>
                <div class="result-display">
                    <h3>Generated Token</h3>
                    <div id="token-value" class="code-display">
                        <?php echo htmlspecialchars($generatedToken); ?>
                    </div>
                    <button type="button" class="copy-btn" data-copy="<?php echo htmlspecialchars($generatedToken); ?>">
                        Copy Token
                    </button>
                </div>
            <?php endif; ?>
        </section>

        <section id="detokenize-section" class="card">
            <h2>Retrieve Data</h2>
            <form method="POST" id="detokenize-form" class="secure-form">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                
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
                    <button type="button" id="view-logs-btn" class="secondary">
                        View Logs
                    </button>
                </div>
            </form>

            <?php if (isset($retrievedData)): ?>
                <div class="result-display">
                    <h3>Retrieved Data</h3>
                    <div id="data-value" class="code-display">
                        <?php echo htmlspecialchars($retrievedData); ?>
                    </div>
                </div>
            <?php endif; ?>
        </section>
    </main>

    <!-- Vault Lightbox -->
    <div id="vault-lightbox" class="lightbox">
        <div class="lightbox-content">
            <h3>Token Vault</h3>
            <button class="close">&times;</button>
            <ul id="vault-list"></ul>
        </div>
    </div>

    <!-- Logs Lightbox -->
    <div id="logs-lightbox" class="lightbox">
        <div class="lightbox-content">
            <h3>Audit Logs</h3>
            <button class="close">&times;</button>
            <ul id="logs-list"></ul>
        </div>
    </div>

    <footer>
        <p>&copy; <?php echo date('Y'); ?> SecureToken. All rights reserved.</p>
    </footer>

    <script src="/js/script.js"></script>
</body>
</html>
