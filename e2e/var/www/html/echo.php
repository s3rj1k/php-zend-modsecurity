<?php
header('Content-Type: application/json');

// Echo back request metadata for assertion.
$response = [
    'status' => 'ok',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN',
    'uri' => $_SERVER['REQUEST_URI'] ?? '/',
    'time' => date('Y-m-d H:i:s'),
    'server' => [
        'host' => $_SERVER['HTTP_HOST'] ?? 'localhost',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
    ],
    'get' => $_GET,
    'post' => $_POST,
    'cookies' => $_COOKIE,
];

echo json_encode($response, JSON_PRETTY_PRINT);
