<?php
// cspell:disable
$config = require __DIR__ . '/config.php';
require __DIR__ . '/utils.php';
setSecurityHeaders($config);
validateConfig($config);

/**
 * Contact Form API Endpoint
 * Handles contact form submissions with validation, reCAPTCHA, and SMTP2GO email
 */

// Handle CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'errors' => ['Method not allowed']]);
    exit;
}

// Rate limiting
$ip = getClientIp($config);

// CSRF: validate request origin
validateRequestOrigin($config);

if (!isAllowed($ip)) {
    http_response_code(429);
    echo json_encode(['success' => false, 'errors' => ['Too many requests. Please try again later.']]);
    exit;
}

// Parse form data (supports both FormData and JSON)
$data = readLeadRequestData();

// Honeypot check
if (!empty($data['website'])) {
    error_log("Honeypot triggered from IP: $ip");
    http_response_code(403);
    echo json_encode(['success' => false, 'errors' => ['Spam detected.']]);
    exit;
}

// Validation
$errors = [];
$name = inputString($data, 'name', 120);
$email = inputString($data, 'email', 254);
$phone = inputString($data, 'phone', 40);
$service = inputString($data, 'service', 120);
$address = normalizeLeadAddress($data);
$location = $address['location'];
$message = inputString($data, 'message', 2000);
$consent = inputString($data, 'consent', 16);
$recaptchaToken = inputString($data, 'recaptchaToken', 4096);

// Sanitize inputs
$name = sanitizeString($name);
$email = sanitizeEmail($email);
$phone = sanitizePhone($phone);
$service = sanitizeString($service);
$addressErrors = validateLeadAddress($address, false);
$address = sanitizeLeadAddress($address);
$location = $address['location'];
$message = sanitizeString($message);

if (empty($name)) $errors[] = 'Full name is required';
elseif (strlen($name) < 2) $errors[] = 'Name is too short';
if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'A valid email address is required';
if (empty($message)) $errors[] = 'Please provide details about your request';
if (strlen($message) < 5) $errors[] = 'Message is too short';
foreach ($addressErrors as $addressError) $errors[] = $addressError;
if ($consent !== 'yes') $errors[] = 'Please consent to be contacted about this request.';
if (empty($recaptchaToken)) $errors[] = 'Security verification failed. Please try again.';

if (!empty($errors)) {
    writeLeadEvent($config, $data, $ip, 'validation_failed', [
        'failureCode' => 'validation',
    ]);
    http_response_code(400);
    echo json_encode(['success' => false, 'errors' => $errors]);
    exit;
}

// Verify reCAPTCHA
$recaptcha = verifyRecaptchaToken($config, $recaptchaToken, $ip, 'contact_submit');
if (!$recaptcha['success']) {
    writeLeadEvent($config, $data, $ip, 'recaptcha_failed', [
        'failureCode' => 'recaptcha',
        'httpStatus' => $recaptcha['status'],
    ]);
    http_response_code($recaptcha['status']);
    echo json_encode(['success' => false, 'errors' => $recaptcha['errors']]);
    exit;
}

// Prepare email content using utility helper
$subject = "New Contact Message from $name";
$html = renderEmailTemplate('New Contact Message', [
    'Name'          => $name,
    'Email'         => $email,
    'Phone'         => $phone ?: 'Not provided',
    'Service'       => $service ?: 'Not sure yet',
    'Service Address' => $location ?: 'Not provided',
    'Apt/Suite'     => $address['apt_suite'] ?: 'Not provided',
    'Gate Code'     => $address['gate_code'] ?: 'Not provided',
    'Google Address' => $address['formatted_address'] ?: 'Not provided',
    'Google Place ID' => $address['place_id'] ?: 'Not provided',
    'Message'       => $message,
    'Consent'       => 'Yes',
    'Lead Source'   => sanitizeString($data['source'] ?? 'Contact Page'),
    'City Context'  => sanitizeString($data['city_context'] ?? 'Site-Wide')
] + collectLeadContext($data));

$redirectTo = issueThankYouAccessUrl($config, 'contact');
if (!$redirectTo) {
    http_response_code(500);
    echo json_encode(['success' => false, 'errors' => ['Confirmation service temporarily unavailable. Please call us directly.']]);
    exit;
}

$result = sendSmtp2goEmail($config, $config['notification_emails'], $subject, $html, $email, $config['notification_bcc_emails'] ?? []);

if ($result['success']) {
    writeLeadEvent($config, $data, $ip, 'delivered', [
        'messageId' => $result['messageId'] ?? '',
        'recaptchaScore' => $recaptcha['score'] ?? null,
    ]);
    // Send autoresponder to the client
    sendAutoresponder($config, $email, $name, 'contact');
    echo json_encode([
        'success' => true,
        'message' => 'Message sent successfully',
        'redirectTo' => $redirectTo,
    ]);
} else {
    writeLeadEvent($config, $data, $ip, 'delivery_failed', [
        'failureCode' => 'smtp2go',
    ]);
    revokeThankYouAccessUrl($config, $redirectTo);
    http_response_code(500);
    error_log('SMTP2GO contact delivery failed: ' . ($result['error'] ?? 'Unknown error'));
    echo json_encode(['success' => false, 'errors' => ['Message delivery unavailable. Please call us directly.']]);
}
