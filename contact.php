<?php

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

header('Access-Control-Allow-Origin: http://localhost:8080');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

session_start();
$current_time = time();
$rate_limit_window = 60;
$max_requests = 5;

if (!isset($_SESSION['last_requests'])) {
    $_SESSION['last_requests'] = [];
}

$_SESSION['last_requests'] = array_filter($_SESSION['last_requests'], function($timestamp) use ($current_time, $rate_limit_window) {
    return ($current_time - $timestamp) < $rate_limit_window;
});

if (count($_SESSION['last_requests']) >= $max_requests) {
    http_response_code(429);
    echo json_encode(['status' => 'error', 'message' => 'Too many requests. Please try again later.']);
    exit;
}

$_SESSION['last_requests'][] = $current_time;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed']);
    exit;
}

$name = isset($_POST['name']) ? trim(htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8')) : '';
$email = isset($_POST['email']) ? trim(filter_var($_POST['email'], FILTER_SANITIZE_EMAIL)) : '';
$message = isset($_POST['message']) ? trim(htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8')) : '';

if (empty($name) || empty($email) || empty($message)) {
    echo json_encode(['status' => 'error', 'message' => 'All fields are required']);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid email format']);
    exit;
}

if (strlen($name) > 100 || strlen($message) > 1000 || strlen($email) > 320) {
    echo json_encode(['status' => 'error', 'message' => 'Input too long']);
    exit;
}

if (preg_match('/[<>"\']/', $name) || preg_match('/[<>"\']/', $message)) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid characters detected']);
    exit;
}

$suspicious_patterns = ['/script/i', '/javascript/i', '/vbscript/i', '/onload/i', '/onerror/i'];
foreach ($suspicious_patterns as $pattern) {
    if (preg_match($pattern, $name . $email . $message)) {
        error_log("Suspicious content detected from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        echo json_encode(['status' => 'error', 'message' => 'Invalid content detected']);
        exit;
    }
}

date_default_timezone_set('Europe/Warsaw');

$datetime = new DateTime('now', new DateTimeZone('Europe/Warsaw'));

$submission = [
    'name' => $name,
    'email' => $email,
    'message' => $message,
    'submission_date' => $datetime->format('Y-m-d H:i:s')
];

$submissions = [];
$jsonFile = 'submissions.json';

if (file_exists($jsonFile)) {
    $jsonContent = file_get_contents($jsonFile);
    if ($jsonContent !== false) {
        $submissions = json_decode($jsonContent, true) ?: [];
    }
}

$submissions[] = $submission;

if (file_put_contents($jsonFile, json_encode($submissions, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE))) {
    echo json_encode(['status' => 'success', 'message' => 'Thank you for submitting the form! We will respond as soon as possible.']);
} else {
    echo json_encode(['status' => 'error', 'message' => 'Failed to save submission. Please try again.']);
}