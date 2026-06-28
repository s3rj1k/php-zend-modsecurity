<?php
header('Content-Type: application/json');

$action = $_GET['action'] ?? 'normal';

$response = [
    'status' => 'ok',
    'action' => $action,
    'time' => date('Y-m-d H:i:s'),
];

// If action is 'blocked', include content that should be blocked by ModSecurity
if ($action === 'blocked') {
    $response['data'] = 'blocked_response_content';
}

echo json_encode($response, JSON_PRETTY_PRINT);
