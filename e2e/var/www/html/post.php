<?php
header('Content-Type: application/json');

$input = file_get_contents('php://input');
$contentType = $_SERVER['CONTENT_TYPE'] ?? 'unknown';

$response = [
    'status' => 'received',
    'method' => $_SERVER['REQUEST_METHOD'],
    'content_type' => $contentType,
    'body_length' => strlen($input),
    'body_preview' => substr($input, 0, 500),
    'post_data' => $_POST,
    'time' => date('Y-m-d H:i:s'),
];

echo json_encode($response, JSON_PRETTY_PRINT);
