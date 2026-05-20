<?php
/**
 * Shared API Utilities
 * cspell:disable
 * file deepcode ignore TooPermissiveXFrameOptions: False positive.
 */

// ============================================================
// Brand Constants — Single source of truth for email templates
// ============================================================
define('BRAND_GREEN', '#137b14');
define('BRAND_ORANGE', '#ff6b00');
define('BRAND_CHARCOAL', '#070806');
define('BRAND_GREEN_ON_DARK', '#8ed08a');
define('BRAND_LIGHT_BG', '#ffffff');
define('BRAND_MUTED_TEXT', '#999999');
define('BRAND_BODY_TEXT', '#333333');
define('BRAND_HEADING_TEXT', '#1a1a1a');
define('BRAND_BORDER', '#e0e0e0');
define('BRAND_FOOTER_BG', '#f7f7f7');

define('COMPANY_NAME', 'Kwikey Locksmith');
define('COMPANY_PHONE', '(302) 551-2550');
define('COMPANY_PHONE_RAW', '+13025512550');
define('COMPANY_WEBSITE', 'https://www.kwikeylocksmith.com');
define('COMPANY_ADDRESS', '211 Maryland Ave, Wilmington, DE 19805');
define('COMPANY_LOGO_URL', 'https://www.kwikeylocksmith.com/logo.png');
define('COMPANY_EMAIL', 'kwikeylocksmithoffice@gmail.com');
define('COMPANY_ESTIMATES_URL', 'https://www.kwikeylocksmith.com/estimates/');

define('MOBILE_HOURS_DISPLAY', 'Mon\xe2\x80\x93Thu & Sun 7 AM\xe2\x80\x9310 PM, Fri 7 AM\xe2\x80\x934:30 PM');

define('SOCIAL_FACEBOOK', 'https://www.facebook.com/profile.php?id=61585926614213');
define('SOCIAL_INSTAGRAM', 'https://www.instagram.com/kwikeylocksmith');
define('SOCIAL_TIKTOK', 'https://www.tiktok.com/@kwikeylocksmith');
define('SOCIAL_TWITTER', 'https://x.com/kwikeylocksmth');
define('SOCIAL_YOUTUBE', 'https://www.youtube.com/@kwikeylocksmith');
define('SOCIAL_GOOGLE', 'https://maps.app.goo.gl/sp3bMYfiPH6bEife7');

define('EMAIL_ASSETS_BASE', 'https://www.kwikeylocksmith.com/email-assets');

require_once __DIR__ . '/email-templates.php';

/**
 * Basic IP-based rate limiting using flat files
 */
function isAllowed(string $ip, int $limit = 5, int $window = 3600): bool {
    $dir = __DIR__ . '/.rate_limit';
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0750, true)) return false; // Fail-closed: deny on error
    }

    // Probabilistic garbage collection (~1% of requests)
    if (mt_rand(1, 100) === 1) {
        cleanupRateLimitFiles($dir, $window * 2);
    }

    $file = $dir . '/' . basename(hash('sha256', $ip));
    $now = time();

    // Open for reading and writing (c+ creates if not exists)
    $fp = fopen($file, 'c+');
    if (!$fp) return false; // Fail-closed: deny on error

    // Acquire exclusive lock (blocking)
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        return false; // Fail-closed: deny on error
    }

    // Read current data
    $content = stream_get_contents($fp);
    $data = $content ? json_decode($content, true) : [];
    if (!is_array($data)) $data = [];

    // Filter old timestamps
    $data = array_filter($data, function($ts) use ($now, $window) {
        return ($now - $ts) < $window;
    });

    $allowed = count($data) < $limit;

    if ($allowed) {
        $data[] = $now;
        // Truncate file and write new data
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode(array_values($data)));
        fflush($fp);
    }

    // Release lock and close
    flock($fp, LOCK_UN);
    fclose($fp);

    return $allowed;
}

/**
 * Cleans up stale rate limit files older than $maxAge seconds
 */
function cleanupRateLimitFiles(string $dir, int $maxAge = 7200): void {
    $now = time();
    $files = glob($dir . '/*');
    if (!is_array($files)) return;

    foreach ($files as $file) {
        if (is_file($file) && ($now - filemtime($file)) > $maxAge) {
            @unlink($file);
        }
    }
}

/**
 * Sets standard security headers for API responses
 */
function setSecurityHeaders(array $config): void {
    // deepcode ignore TooPermissiveXFrameOptions: Value is DENY (most restrictive). CSP frame-ancestors 'none' set on the next line as the modern equivalent. False positive.
    header('X-Frame-Options: DENY'); // phpcs:ignore -- snyk:ignore TooPermissiveXFrameOptions
    header("Content-Security-Policy: frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: ' . $config['allowed_origin']);
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('X-XSS-Protection: 0');
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

const MAX_LEAD_REQUEST_BYTES = 32768;

function sendJsonError(int $status, array $errors): void {
    http_response_code($status);
    echo json_encode(['success' => false, 'errors' => $errors]);
    exit;
}

function readLeadRequestData(int $maxBytes = MAX_LEAD_REQUEST_BYTES): array {
    $contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($contentLength > $maxBytes) {
        sendJsonError(413, ['Request is too large. Please call us directly.']);
    }

    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (stripos($contentType, 'application/json') === false) {
        return $_POST;
    }

    $raw = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
    if ($raw === false || strlen($raw) > $maxBytes) {
        sendJsonError(413, ['Request is too large. Please call us directly.']);
    }

    $data = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
        sendJsonError(400, ['Invalid request format. Please try again.']);
    }

    return $data;
}

function inputString(array $data, string $key, int $maxLength = 500): string {
    return substr(trim((string) ($data[$key] ?? '')), 0, $maxLength);
}

/**
 * Validates that required config keys are present and non-empty.
 * Fails fast with a diagnostic JSON response instead of crashing with HTTP 500.
 */
function validateConfig(array $config): void {
    $required = ['smtp2go_api_key', 'recaptcha_secret_key'];
    $missing = [];

    foreach ($required as $key) {
        if (empty($config[$key])) {
            $missing[] = $key;
        }
    }

    if (!empty($missing)) {
        error_log('API config error: missing keys - ' . implode(', ', $missing));
        http_response_code(503);
        echo json_encode([
            'success' => false,
            'errors'  => ['Service temporarily unavailable. Please call us directly.'],
        ]);
        exit;
    }
}

/**
 * Gets the client IP address.
 * Proxy headers are opt-in because clients can spoof them unless a trusted proxy strips them.
 */
function getClientIp(array $config = []): string {
    if (!empty($config['trust_proxy_headers'])) {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
            $ip = $ips[0];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }

    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }
    return 'unknown';
}

/**
 * Sanitizes email to prevent header injection
 */
function sanitizeEmail(string $email): string {
    return filter_var($email, FILTER_SANITIZE_EMAIL);
}

/**
 * Validates and sanitizes phone numbers
 * Returns digits only or empty string if invalid length
 */
function sanitizePhone(string $phone): string {
    $digits = preg_replace('/\D/', '', $phone);
    if (strlen($digits) < 10 || strlen($digits) > 15) return '';
    return $digits;
}

/**
 * Robust string sanitization for general text inputs
 */
function sanitizeString(string $input): string {
    return htmlspecialchars(trim($input), ENT_COMPAT, 'UTF-8');
}

function validUsStateCodes(): array {
    return [
        'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA', 'HI', 'ID', 'IL', 'IN', 'IA',
        'KS', 'KY', 'LA', 'ME', 'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
        'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT', 'VT',
        'VA', 'WA', 'WV', 'WI', 'WY', 'DC',
    ];
}

function normalizeLeadAddress(array $data): array {
    $street = trim((string) ($data['street'] ?? ''));
    $city = trim((string) ($data['city'] ?? ''));
    $state = strtoupper(trim((string) ($data['state'] ?? '')));
    $zip = preg_replace('/\s+/', '', trim((string) ($data['zip'] ?? '')));
    $aptSuite = trim((string) ($data['apt_suite'] ?? ''));
    $gateCode = trim((string) ($data['gate_code'] ?? ''));
    $formattedAddress = trim((string) ($data['formatted_address'] ?? ''));
    $placeId = trim((string) ($data['place_id'] ?? ''));

    $parts = array_filter([$street, $aptSuite, $city, $state, $zip]);
    $composite = implode(', ', $parts);
    $fallbackLocation = trim((string) ($data['location'] ?? ''));

    return [
        'street' => $street,
        'city' => $city,
        'state' => $state,
        'zip' => $zip,
        'apt_suite' => $aptSuite,
        'gate_code' => $gateCode,
        'formatted_address' => $formattedAddress,
        'place_id' => $placeId,
        'location' => $composite !== '' ? $composite : $fallbackLocation,
    ];
}

function validateLeadAddress(array $address, bool $required = true): array {
    $errors = [];
    $hasAnyAddressValue = false;
    foreach (['street', 'city', 'state', 'zip'] as $field) {
        if (($address[$field] ?? '') !== '') {
            $hasAnyAddressValue = true;
            break;
        }
    }

    if (!$required && !$hasAnyAddressValue) {
        return $errors;
    }

    if (strlen($address['street'] ?? '') < 5) $errors[] = 'A valid street address is required';
    if (strlen($address['city'] ?? '') < 2) $errors[] = 'A valid city is required';
    if (!in_array($address['state'] ?? '', validUsStateCodes(), true)) $errors[] = 'A valid U.S. state is required';
    if (!preg_match('/^\d{5}(-\d{4})?$/', $address['zip'] ?? '')) $errors[] = 'A valid U.S. ZIP code is required';

    return $errors;
}

function sanitizeLeadAddress(array $address): array {
    foreach ($address as $key => $value) {
        $address[$key] = sanitizeString((string) $value);
    }
    return $address;
}

/**
 * Collects optional campaign and page context fields submitted by the browser.
 */
function collectLeadContext(array $data): array {
    $fieldLabels = [
        'page_url'     => 'Page URL',
        'page_path'    => 'Page Path',
        'referrer'     => 'Referrer',
        'gclid'        => 'GCLID',
        'gbraid'       => 'GBRAID',
        'wbraid'       => 'WBRAID',
        'msclkid'      => 'MSCLKID',
        'fbclid'       => 'FBCLID',
        'ttclid'       => 'TTCLID',
        'utm_source'   => 'UTM Source',
        'utm_medium'   => 'UTM Medium',
        'utm_campaign' => 'UTM Campaign',
        'utm_term'     => 'UTM Term',
        'utm_content'  => 'UTM Content',
        'first_landing_page' => 'First Landing Page',
        'last_landing_page'  => 'Last Landing Page',
        'conversion_page'    => 'Conversion Page',
        'first_referrer'     => 'First Referrer',
        'last_referrer'      => 'Last Referrer',
        'page_title'         => 'Page Title',
        'viewport_width'     => 'Viewport Width',
        'viewport_height'    => 'Viewport Height',
        'recaptchaAction'    => 'reCAPTCHA Action',
    ];

    $context = [];
    foreach ($fieldLabels as $field => $label) {
        $value = trim((string) ($data[$field] ?? ''));
        if ($value !== '') {
            $context[$label] = sanitizeString($value);
        }
    }

    return $context;
}

function leadEventsDir(): string {
    return __DIR__ . '/.lead_events';
}

function leadEventIpHash(array $config, string $ip): string {
    return hash_hmac('sha256', $ip, thankYouSecret($config));
}

function writeLeadEvent(array $config, array $data, string $ip, string $status, array $extra = []): void {
    if (($config['lead_event_logging'] ?? true) === false) return;

    $dir = leadEventsDir();
    if (!is_dir($dir) && !mkdir($dir, 0750, true)) {
        error_log('Lead event log error: unable to create event directory.');
        return;
    }

    $event = [
        'createdAt' => gmdate('c'),
        'status' => sanitizeString($status),
        'formType' => sanitizeString((string) ($data['formType'] ?? 'unknown')),
        'source' => sanitizeString((string) ($data['source'] ?? 'unknown')),
        'cityContext' => sanitizeString((string) ($data['city_context'] ?? 'Site-Wide')),
        'service' => sanitizeString((string) ($data['service'] ?? 'General')),
        'pagePath' => sanitizeString((string) ($data['page_path'] ?? '')),
        'recaptchaAction' => sanitizeString((string) ($data['recaptchaAction'] ?? '')),
        'ipHash' => leadEventIpHash($config, $ip),
    ] + $extra;

    $file = $dir . '/lead-events-' . gmdate('Y-m-d') . '.jsonl';
    @file_put_contents($file, json_encode($event) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

/**
 * Renders a branded HTML email template (backward-compatible signature).
 * Delegates to the new branded notification email system.
 */
function renderEmailTemplate(string $title, array $fields): string {
    $formType = (stripos($title, 'Booking') !== false) ? 'booking' : 'contact';
    $content = renderNotificationEmail($formType, $fields);
    return renderBaseLayout($content);
}

function isAllowedRequestHost(string $host, string $allowedHost): bool {
    return $host === $allowedHost
        || $host === str_replace('www.', '', $allowedHost)
        || 'www.' . $host === $allowedHost;
}

/**
 * Validates the request Origin/Referer header against the allowed origin.
 * Prevents cross-site form submissions (CSRF mitigation).
 */
function validateRequestOrigin(array $config): void {
    $allowedOrigin = $config['allowed_origin'] ?? '';
    if (!$allowedOrigin) return; // Skip if not configured

    $allowedHost = strtolower(parse_url($allowedOrigin, PHP_URL_HOST) ?: '');
    if (!$allowedHost) return;

    // Check Origin header first (most reliable)
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin) {
        $originHost = strtolower(parse_url($origin, PHP_URL_HOST) ?: '');
        if (!$originHost || !isAllowedRequestHost($originHost, $allowedHost)) {
            sendJsonError(403, ['Request origin not allowed.']);
        }
        return; // Origin matched
    }

    // Fall back to Referer header
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    if ($referer) {
        $refererHost = strtolower(parse_url($referer, PHP_URL_HOST) ?: '');
        if (!$refererHost || !isAllowedRequestHost($refererHost, $allowedHost)) {
            sendJsonError(403, ['Request origin not allowed.']);
        }
    }
    // If neither Origin nor Referer is present, allow (some browsers strip these)
}

/**
 * External API Endpoints
 */
const SMTP2GO_ENDPOINT = 'https://api.smtp2go.com/v3/email/send';
const RECAPTCHA_VERIFY_ENDPOINT = 'https://www.google.com/recaptcha/api/siteverify';
const THANK_YOU_TOKEN_TTL = 1200;
const THANK_YOU_COOKIE_NAME = 'kwikey_thank_you_access';

function allowedRecaptchaHostnames(array $config): array {
    $host = strtolower(parse_url($config['allowed_origin'] ?? '', PHP_URL_HOST) ?: '');
    if (!$host) return [];

    $hosts = [$host];
    if (strpos($host, 'www.') === 0) {
        $hosts[] = substr($host, 4);
    } else {
        $hosts[] = 'www.' . $host;
    }

    return array_values(array_unique(array_filter($hosts)));
}

function verifyRecaptchaToken(array $config, string $token, string $ip, string $expectedAction = 'submit'): array {
    if (empty($token)) {
        return [
            'success' => false,
            'status' => 400,
            'errors' => ['Security verification failed. Please try again.'],
        ];
    }

    $ch = curl_init(RECAPTCHA_VERIFY_ENDPOINT);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_POSTFIELDS     => [
            'secret'   => $config['recaptcha_secret_key'],
            'response' => $token,
            'remoteip' => $ip,
        ],
    ]);
    $response = curl_exec($ch);

    if ($response === false) {
        $curlError = curl_error($ch);
        curl_close($ch);
        error_log('reCAPTCHA curl error: ' . $curlError);
        return [
            'success' => false,
            'status' => 500,
            'errors' => ['Verification service unavailable. Please try again.'],
        ];
    }

    curl_close($ch);

    $result = json_decode($response, true);
    if (!is_array($result) || !($result['success'] ?? false)) {
        $errorCodes = $result['error-codes'] ?? [];
        error_log('reCAPTCHA verification failed. Error codes: ' . json_encode($errorCodes) . ' | Full response: ' . $response);
        // Provide actionable error for known issues
        if (in_array('timeout-or-duplicate', $errorCodes, true)) {
            return [
                'success' => false,
                'status' => 400,
                'errors' => ['Verification expired. Please submit the form again.'],
            ];
        }
        if (in_array('invalid-input-secret', $errorCodes, true)) {
            error_log('CRITICAL: reCAPTCHA secret key is invalid. Check config.php on the server.');
        }
        return [
            'success' => false,
            'status' => 400,
            'errors' => ['reCAPTCHA verification failed. Please try again.'],
        ];
    }

    $minScore = (float) ($config['recaptcha_min_score'] ?? 0.5);
    $score = (float) ($result['score'] ?? 0);
    if ($score < $minScore) {
        return [
            'success' => false,
            'status' => 400,
            'errors' => ['reCAPTCHA verification failed. Please try again.'],
        ];
    }

    $action = (string) ($result['action'] ?? '');
    if ($expectedAction && (!$action || !hash_equals($expectedAction, $action))) {
        error_log('reCAPTCHA action mismatch: expected ' . $expectedAction . ', got ' . ($action ?: 'none'));
        return [
            'success' => false,
            'status' => 400,
            'errors' => ['reCAPTCHA verification failed. Please try again.'],
        ];
    }

    $hostname = strtolower((string) ($result['hostname'] ?? ''));
    $allowedHosts = allowedRecaptchaHostnames($config);
    if ($allowedHosts && $hostname && !in_array($hostname, $allowedHosts, true)) {
        // Log but don't block — Google's console already restricts by domain.
        // This prevents false rejections from hostname format differences.
        error_log('reCAPTCHA hostname notice: got ' . $hostname . ', expected one of: ' . implode(', ', $allowedHosts));
    }

    return [
        'success' => true,
        'status' => 200,
        'score' => $score,
        'action' => $action,
        'hostname' => $hostname,
    ];
}

function thankYouTokenDir(): string {
    return __DIR__ . '/.thank_you_tokens';
}

function thankYouSecret(array $config): string {
    return $config['recaptcha_secret_key'] . '|' . $config['smtp2go_api_key'];
}

function isHttpsRequest(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

function cleanupThankYouTokens(string $dir): void {
    $files = glob($dir . '/*.json');
    if (!is_array($files)) return;

    $now = time();
    foreach ($files as $file) {
        $payload = json_decode((string) @file_get_contents($file), true);
        if (!is_array($payload) || ($payload['expires'] ?? 0) < $now) {
            @unlink($file);
        }
    }
}

function issueThankYouAccessUrl(array $config, string $formType): ?string {
    $dir = thankYouTokenDir();
    if (!is_dir($dir) && !mkdir($dir, 0750, true)) {
        error_log('Thank-you token error: unable to create token directory.');
        return null;
    }

    if (mt_rand(1, 100) === 1) {
        cleanupThankYouTokens($dir);
    }

    $token = bin2hex(random_bytes(32));
    $tokenHash = hash_hmac('sha256', $token, thankYouSecret($config));
    $payload = [
        'expires' => time() + THANK_YOU_TOKEN_TTL,
        'formType' => sanitizeString($formType),
    ];

    $written = file_put_contents(
        $dir . '/' . $tokenHash . '.json',
        json_encode($payload),
        LOCK_EX
    );

    if ($written === false) {
        error_log('Thank-you token error: unable to write token file.');
        return null;
    }

    return '/thank-you/?token=' . rawurlencode($token);
}

function revokeThankYouAccessUrl(array $config, string $url): void {
    $query = parse_url($url, PHP_URL_QUERY);
    if (!is_string($query)) return;

    parse_str($query, $params);
    $token = $params['token'] ?? '';
    if (!is_string($token) || !preg_match('/^[a-f0-9]{64}$/', $token)) return;

    $file = thankYouTokenDir() . '/' . hash_hmac('sha256', $token, thankYouSecret($config)) . '.json';
    if (is_file($file)) {
        @unlink($file);
    }
}

function consumeThankYouAccessToken(array $config, string $token): bool {
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) return false;

    $file = thankYouTokenDir() . '/' . hash_hmac('sha256', $token, thankYouSecret($config)) . '.json';
    if (!is_file($file)) return false;

    $payload = json_decode((string) file_get_contents($file), true);
    @unlink($file);

    if (!is_array($payload) || ($payload['expires'] ?? 0) < time()) {
        return false;
    }

    setThankYouAccessCookie($config);
    return true;
}

function thankYouCookieValue(array $config, int $expires, string $nonce): string {
    $signature = hash_hmac('sha256', $expires . '|' . $nonce, thankYouSecret($config));
    return $expires . '.' . $nonce . '.' . $signature;
}

function setThankYouAccessCookie(array $config): void {
    $expires = time() + THANK_YOU_TOKEN_TTL;
    $nonce = bin2hex(random_bytes(16));

    setcookie(THANK_YOU_COOKIE_NAME, thankYouCookieValue($config, $expires, $nonce), [
        'expires' => $expires,
        'path' => '/thank-you',
        'secure' => isHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function hasValidThankYouAccessCookie(array $config): bool {
    $value = $_COOKIE[THANK_YOU_COOKIE_NAME] ?? '';
    $parts = explode('.', $value);
    if (count($parts) !== 3) return false;

    [$expires, $nonce, $signature] = $parts;
    if (!ctype_digit($expires) || (int) $expires < time()) return false;
    if (!preg_match('/^[a-f0-9]{32}$/', $nonce)) return false;

    $expected = hash_hmac('sha256', $expires . '|' . $nonce, thankYouSecret($config));
    return hash_equals($expected, $signature);
}

/**
 * Sends email via SMTP2GO with retry on transient failures
 */
function sendSmtp2goEmail(array $config, $to, string $subject, string $html, string $replyTo = ''): array {
    $recipients = is_array($to) ? $to : [$to];
    $payload = [
        'api_key'   => $config['smtp2go_api_key'],
        'to'        => $recipients,
        'sender'    => $config['sender_name'] . ' <' . $config['sender_email'] . '>',
        'subject'   => $subject,
        'html_body' => $html,
        'text_body' => generatePlainText($html),
    ];

    if ($replyTo) {
        $payload['custom_headers'] = [['header' => 'Reply-To', 'value' => $replyTo]];
    }

    $maxAttempts = 2;
    $lastError = 'Unknown error';

    for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
        $ch = curl_init(SMTP2GO_ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
            CURLOPT_POSTFIELDS     => json_encode($payload),
            CURLOPT_TIMEOUT        => 15,
        ]);

        $response = curl_exec($ch);

        if ($response === false) {
            $lastError = 'Email service temporarily unavailable. Please try again.';
            error_log('SMTP2GO curl error (attempt ' . $attempt . '): ' . curl_error($ch));
            curl_close($ch);
            if ($attempt < $maxAttempts) { usleep(500000); continue; }
            return ['success' => false, 'error' => $lastError];
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $result = json_decode($response, true);

        if ($httpCode >= 200 && $httpCode < 300 && ($result['data']['succeeded'] ?? 0) > 0) {
            return ['success' => true, 'messageId' => $result['data']['email_id'] ?? ''];
        }

        // Retry on 5xx server errors
        if ($httpCode >= 500 && $attempt < $maxAttempts) {
            error_log('SMTP2GO server error (attempt ' . $attempt . '): HTTP ' . $httpCode);
            usleep(500000);
            continue;
        }

        $lastError = $result['data']['error'] ?? 'Failed to send email';
        break;
    }

    return ['success' => false, 'error' => $lastError];
}

/**
 * Sends a branded autoresponder confirmation email to the client.
 * Backward-compatible signature preserved.
 */
function sendAutoresponder(array $config, string $clientEmail, string $clientName, string $formType = 'contact'): array {
    $subject = "We've Received Your Request - " . COMPANY_NAME;
    $content = renderAutoresponderEmail($formType, $clientName);
    $html = renderBaseLayout($content);
    return sendSmtp2goEmail($config, $clientEmail, $subject, $html);
}
