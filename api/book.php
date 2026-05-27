<?php
// cspell:disable
$config = require __DIR__ . '/config.php';
require __DIR__ . '/utils.php';
setSecurityHeaders($config);
validateConfig($config);

/**
 * Booking Form API Endpoint
 * Handles booking form submissions with validation, reCAPTCHA, and SMTP2GO email
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

// Parse form data
$data = readLeadRequestData();

// Honeypot check
if (!empty($data['website'])) {
    error_log("Booking Honeypot triggered from IP: $ip");
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
$businessType = inputString($data, 'business_type', 120);
$doorCount = inputString($data, 'door_count', 40);
$credentialInterest = inputString($data, 'credential_interest', 120);
$vehicle = inputString($data, 'vehicle', 160);
$urgency = inputString($data, 'urgency', 80);
$consent = inputString($data, 'consent', 16);
$recaptchaToken = inputString($data, 'recaptchaToken', 4096);

// Sanitize inputs
$name = sanitizeString($name);
$email = sanitizeEmail($email);
$phone = sanitizePhone($phone);
$service = sanitizeString($service);
$addressErrors = validateLeadAddress($address, true);
$address = sanitizeLeadAddress($address);
$location = $address['location'];
$message = sanitizeString($message);
$businessType = sanitizeString($businessType);
$doorCount = sanitizeString($doorCount);
$credentialInterest = sanitizeString($credentialInterest);
$vehicle = sanitizeString($vehicle);
$urgency = sanitizeString($urgency);

if (empty($name)) $errors[] = 'Full name is required';
elseif (strlen($name) < 2) $errors[] = 'Name is too short';
if (empty($phone)) $errors[] = 'A valid phone number is required';
if (empty($service)) $errors[] = 'Please select a service type';
foreach ($addressErrors as $addressError) $errors[] = $addressError;
if ($consent !== 'yes') $errors[] = 'Please consent to be contacted about this request.';
if (empty($recaptchaToken)) $errors[] = 'Security verification failed. Please try again.';
// Email is optional - many booking forms only collect phone
if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Please provide a valid email address';

if (!empty($errors)) {
    writeLeadEvent($config, $data, $ip, 'validation_failed', [
        'failureCode' => 'validation',
    ]);
    http_response_code(400);
    echo json_encode(['success' => false, 'errors' => $errors]);
    exit;
}

// Verify reCAPTCHA
$recaptcha = verifyRecaptchaToken($config, $recaptchaToken, $ip, 'booking_submit');
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
$subject = "New Booking Request: $service - $name";
$html = renderEmailTemplate('New Booking Request', [
    'Name'          => $name,
    'Email'         => $email,
    'Phone'         => $phone,
    'Service'       => $service,
    'Service Address' => $location,
    'Apt/Suite'     => $address['apt_suite'] ?: 'Not provided',
    'Gate Code'     => $address['gate_code'] ?: 'Not provided',
    'Google Address' => $address['formatted_address'] ?: 'Not provided',
    'Google Place ID' => $address['place_id'] ?: 'Not provided',
    'Message'       => $message,
    'Business Type' => $businessType ?: 'Not provided',
    'Door Count'    => $doorCount ?: 'Not provided',
    'Credential'    => $credentialInterest ?: 'Not provided',
    'Vehicle'       => $vehicle ?: 'Not provided',
    'Urgency'       => $urgency ?: 'Not provided',
    'Consent'       => 'Yes',
    'Lead Source'   => sanitizeString($data['source'] ?? 'Booking Form'),
    'City Context'  => sanitizeString($data['city_context'] ?? 'Site-Wide')
] + collectLeadContext($data));

$redirectTo = issueThankYouAccessUrl($config, 'booking');
if (!$redirectTo) {
    http_response_code(500);
    echo json_encode(['success' => false, 'errors' => ['Confirmation service temporarily unavailable. Please call us directly.']]);
    exit;
}

$replyTo = !empty($email) ? $email : '';
$result = sendSmtp2goEmail($config, $config['notification_emails'], $subject, $html, $replyTo, $config['notification_bcc_emails'] ?? []);

if ($result['success']) {
    writeLeadEvent($config, $data, $ip, 'delivered', [
        'messageId' => $result['messageId'] ?? '',
        'recaptchaScore' => $recaptcha['score'] ?? null,
    ]);
    // Send autoresponder only if client provided a valid email
    if (!empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        sendAutoresponder($config, $email, $name ?: 'Valued Customer', 'booking');
    }
    echo json_encode([
        'success' => true,
        'message' => 'Booking request sent successfully',
        'redirectTo' => $redirectTo,
    ]);
} else {
    writeLeadEvent($config, $data, $ip, 'delivery_failed', [
        'failureCode' => 'smtp2go',
    ]);
    revokeThankYouAccessUrl($config, $redirectTo);
    http_response_code(500);
    error_log('SMTP2GO booking delivery failed: ' . ($result['error'] ?? 'Unknown error'));
    echo json_encode(['success' => false, 'errors' => ['Message delivery unavailable. Please call us directly.']]);
}
