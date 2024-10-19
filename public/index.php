<?php
require_once('../config/config.php');
require_once('../src/Token.php');

// Tokenize input
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['tokenize'])) {
    $sensitiveData = $_POST['sensitive_data'];
    $token = Token::tokenize($sensitiveData);
    $message = "Tokenized value: " . $token;
}

// Detokenize input
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['detokenize'])) {
    $token = $_POST['token'];
    $originalData = Token::detokenize($token);
    $message = "Original data: " . $originalData;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureToken - Tokenization System</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <header>
        <h1>SecureToken: Data Security Solution</h1>
    </header>

    <section id="tokenize-section">
        <h2>Tokenize Data</h2>
        <form method="POST">
            <input type="text" name="sensitive_data" placeholder="Enter sensitive data" required>
            <button type="submit" name="tokenize">Tokenize</button>
        </form>
    </section>

    <section id="detokenize-section">
        <h2>Detokenize Data</h2>
        <form method="POST">
            <input type="text" name="token" placeholder="Enter token" required>
            <button type="submit" name="detokenize">Detokenize</button>
        </form>
    </section>

    <p><?php if (isset($message)) echo $message; ?></p>

    <script src="js/script.js"></script>
</body>
</html>
