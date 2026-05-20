<?php
// cspell:disable
$config = require __DIR__ . '/../api/config.php';
require __DIR__ . '/../api/utils.php';

$token = trim($_GET['token'] ?? '');

if ($token !== '' && consumeThankYouAccessToken($config, $token)) {
    header('Cache-Control: no-store, private');
    header('X-Robots-Tag: noindex, nofollow');
    header('Location: /thank-you/', true, 303);
    exit;
}

if (!hasValidThankYouAccessCookie($config)) {
    header('Cache-Control: no-store, private');
    header('X-Robots-Tag: noindex, nofollow');
    header('Location: /estimates/', true, 302);
    exit;
}

$html = __DIR__ . '/index.html';
if (!is_file($html)) {
    http_response_code(404);
    echo 'Confirmation page unavailable.';
    exit;
}

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Robots-Tag: noindex, nofollow');
readfile($html);
