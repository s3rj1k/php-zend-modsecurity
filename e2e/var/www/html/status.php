<?php
// Configurable HTTP status for response status inspection tests.
// /status.php?code=500 responds with that status, default 200.

$code = isset($_GET['code']) ? (int)$_GET['code'] : 200;
if ($code < 100 || $code > 599) {
    $code = 200;
}

http_response_code($code);
header('Content-Type: application/json');

echo json_encode([
    'status' => 'ok',
    'code' => $code,
    'time' => date('Y-m-d H:i:s'),
], JSON_PRETTY_PRINT);
