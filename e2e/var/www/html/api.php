<?php
// JSON API endpoint for body inspection tests (GraphQL style + REST).
header('Content-Type: application/json');

$input = file_get_contents('php://input');
$parsed = json_decode($input, true);

$action = $_GET['action'] ?? 'query';

switch ($action) {
    case 'graphql':
        if ($parsed && isset($parsed['query'])) {
            echo json_encode(['data' => ['user' => ['id' => 1]]], JSON_PRETTY_PRINT);
        } else {
            echo json_encode(['errors' => [['message' => 'Invalid query']]]);
        }
        break;
    case 'leak_pan':
        // Fake PAN for response body leak tests
        echo json_encode(['card' => '4111-1111-1111-1111']);
        break;
    case 'leak_path':
        echo json_encode(['path' => '/var/www/html/config.php']);
        break;
    case 'leak_secret':
        echo json_encode(['config' => 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG']);
        break;
    default:
        echo json_encode(['status' => 'ok', 'input_length' => strlen($input)], JSON_PRETTY_PRINT);
}
