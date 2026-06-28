<?php
// Reflects request headers and auth info for header inspection tests.
header('Content-Type: application/json');

$headers = [];
foreach (getallheaders() as $name => $value) {
    $headers[$name] = $value;
}

echo json_encode([
    'status' => 'ok',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN',
    'uri' => $_SERVER['REQUEST_URI'] ?? '/',
    'headers' => $headers,
    'auth' => [
        'user' => $_SERVER['PHP_AUTH_USER'] ?? null,
        'pass' => $_SERVER['PHP_AUTH_PW'] ?? null,
    ],
    'time' => date('Y-m-d H:i:s'),
], JSON_PRETTY_PRINT);
