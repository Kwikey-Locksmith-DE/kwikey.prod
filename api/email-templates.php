<?php
/**
 * Branded Email Template Engine
 * Kwikey Locksmith — Hybrid responsive HTML email templates
 *
 * This file provides the rendering functions for branded emails.
 * It is included by utils.php which defines the brand constants.
 * cspell:disable
 */

/**
 * Converts HTML email to plain-text for the text_body SMTP field.
 */
function generatePlainText(string $html): string {
    $text = preg_replace('/<\/(p|div|tr|h[1-6]|li)>/i', "\n\n", $html);
    $text = preg_replace('/<br\s*\/?>/i', "\n", $text);
    $text = strip_tags($text);
    $text = html_entity_decode($text, ENT_QUOTES, 'UTF-8');
    $text = preg_replace('/\n{3,}/', "\n\n", $text);
    $lines = array_map('trim', explode("\n", $text));
    $text = implode("\n", $lines);
    return trim($text);
}

/**
 * Returns current timestamp in Delaware (Eastern) timezone.
 */
function getEasternTimestamp(): string {
    $tz = new \DateTimeZone('America/New_York');
    $now = new \DateTime('now', $tz);
    return $now->format('M j, Y \a\t g:i A') . ' ET';
}

/**
 * Renders the brand header with logo on charcoal background.
 */
function renderBrandHeader(): string {
    $logoUrl = COMPANY_LOGO_URL;
    $siteUrl = COMPANY_WEBSITE;
    $bg = BRAND_CHARCOAL;
    $accent = BRAND_GREEN_ON_DARK;

    return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: ' . $bg . ';">
  <tr>
    <td align="center" style="padding: 28px 24px; background-color: ' . $bg . ';">
      <a href="' . $siteUrl . '" target="_blank" style="text-decoration: none;">
        <img src="' . $logoUrl . '" alt="Kwikey Locksmith" width="200" height="62" style="display: block; max-height: 64px; min-height: 48px; width: auto; border: 0; color: ' . $accent . '; font-size: 20px; font-weight: bold; font-family: Arial, Helvetica, sans-serif;" />
      </a>
    </td>
  </tr>
</table>';
}

/**
 * Renders social media icon links. Omits platforms with empty URLs.
 */
function renderSocialIcons(): string {
    $platforms = [
        ['name' => 'Facebook',  'url' => SOCIAL_FACEBOOK,  'icon' => 'icon-facebook.png'],
        ['name' => 'Instagram', 'url' => SOCIAL_INSTAGRAM, 'icon' => 'icon-instagram.png'],
        ['name' => 'TikTok',    'url' => SOCIAL_TIKTOK,    'icon' => 'icon-tiktok.png'],
        ['name' => 'X (Twitter)', 'url' => SOCIAL_TWITTER, 'icon' => 'icon-twitter.png'],
        ['name' => 'YouTube',   'url' => SOCIAL_YOUTUBE,   'icon' => 'icon-youtube.png'],
        ['name' => 'Google Business', 'url' => SOCIAL_GOOGLE, 'icon' => 'icon-google.png'],
    ];

    $base = EMAIL_ASSETS_BASE;
    $icons = '';
    foreach ($platforms as $p) {
        if (empty($p['url'])) continue;
        $alt = htmlspecialchars($p['name'], ENT_QUOTES, 'UTF-8');
        $icons .= '<a href="' . $p['url'] . '" target="_blank" style="display: inline-block; margin: 0 5px; text-decoration: none; line-height: 0;">';
        $icons .= '<img src="' . $base . '/' . $p['icon'] . '" alt="' . $alt . '" width="28" height="28" style="display: inline-block; border: 0; border-radius: 4px; width: 28px; height: 28px;" />';
        $icons .= '</a>';
    }

    if (!$icons) return '';
    return '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin: 0 auto;"><tr><td align="center" style="padding: 12px 0;">' . $icons . '</td></tr></table>';
}

/**
 * Renders the brand footer with contact info, social, hours, trust.
 */
function renderBrandFooter(): string {
    $orange = BRAND_ORANGE;
    $green = BRAND_GREEN;
    $muted = BRAND_MUTED_TEXT;
    $footerBg = BRAND_FOOTER_BG;
    $phone = COMPANY_PHONE;
    $phoneRaw = COMPANY_PHONE_RAW;
    $address = COMPANY_ADDRESS;
    $website = COMPANY_WEBSITE;
    $hours = MOBILE_HOURS_DISPLAY;
    $socialHtml = renderSocialIcons();

    return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: ' . $footerBg . '; border-top: 2px solid ' . BRAND_BORDER . ';">
  <tr>
    <td align="center" style="padding: 32px 24px 28px 24px; background-color: ' . $footerBg . '; font-family: Arial, Helvetica, sans-serif;">

      <!-- Need help now? -->
      <p style="margin: 0 0 8px 0; font-size: 12px; color: #888888; background-color: ' . $footerBg . '; text-transform: uppercase; letter-spacing: 0.5px;">Need help now?</p>

      <!-- Phone -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin: 0 auto 16px auto;">
        <tr>
          <td align="center" style="border-radius: 6px; background-color: ' . $orange . ';">
            <a href="tel:' . $phoneRaw . '" style="display: inline-block; padding: 12px 28px; font-size: 18px; font-weight: bold; color: #ffffff; background-color: ' . $orange . '; text-decoration: none; border-radius: 6px; font-family: Arial, Helvetica, sans-serif;">' . $phone . '</a>
          </td>
        </tr>
      </table>

      <!-- Divider -->
      <table role="presentation" width="80" cellpadding="0" cellspacing="0" border="0" style="margin: 0 auto 16px auto;">
        <tr><td style="border-top: 1px solid #dddddd; font-size: 0; line-height: 0;" height="1">&nbsp;</td></tr>
      </table>

      <!-- Social -->
      ' . $socialHtml . '

      <!-- Address + Website -->
      <p style="margin: 12px 0 4px 0; font-size: 13px; line-height: 1.6; color: #555555; background-color: ' . $footerBg . ';">' . $address . '</p>
      <p style="margin: 0 0 12px 0; font-size: 13px; line-height: 1.6;">
        <a href="' . $website . '" style="color: ' . $green . '; text-decoration: none; font-weight: bold; font-family: Arial, Helvetica, sans-serif;">www.kwikeylocksmith.com</a>
      </p>

      <!-- Hours -->
      <p style="margin: 12px 0 6px 0; font-size: 12px; line-height: 1.5; color: #666666; background-color: ' . $footerBg . ';">
        <strong style="color: #444444;">Mobile Service Hours:</strong> ' . $hours . '
      </p>
      <p style="margin: 0 0 0 0; font-size: 12px; line-height: 1.5; color: #666666; background-color: ' . $footerBg . ';">
        <strong style="color: #444444;">Store (by appt):</strong> Mon&ndash;Fri 9 AM&ndash;4 PM
      </p>

      <!-- Trust -->
      <p style="margin: 16px 0 0 0; font-size: 11px; color: ' . $muted . '; background-color: ' . $footerBg . ';">Professionally Insured &bull; Quote Before Work &bull; ' . SERVICE_AREA_EMAIL_FOOTER . '</p>
    </td>
  </tr>
</table>';
}

/**
 * Wraps content HTML in the full branded email document structure.
 */
function renderBaseLayout(string $contentHtml): string {
    $lightBg = BRAND_LIGHT_BG;
    $bodyText = BRAND_BODY_TEXT;
    $header = renderBrandHeader();
    $footer = renderBrandFooter();

    return '<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="color-scheme" content="light dark" />
<meta name="supported-color-schemes" content="light dark" />
<title>' . COMPANY_NAME . '</title>
<!--[if mso]>
<noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript>
<![endif]-->
<style>
:root { color-scheme: light dark; }
@media (prefers-color-scheme: dark) {
  .email-body { background-color: #1a1a1a !important; }
  .email-content { background-color: #222222 !important; color: #e0e0e0 !important; }
  .email-footer { background-color: #1a1a1a !important; }
}
@media only screen and (max-width: 600px) {
  .email-container { width: 100% !important; max-width: 100% !important; }
  .mobile-padding { padding-left: 16px !important; padding-right: 16px !important; }
  .mobile-full { width: 100% !important; display: block !important; }
  .mobile-center { text-align: center !important; }
  .mobile-hide { display: none !important; }
}
body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
img { -ms-interpolation-mode: bicubic; border: 0; outline: none; text-decoration: none; }
a { color: inherit; }
</style>
</head>
<body class="email-body" style="margin: 0; padding: 0; width: 100%; background-color: #eef0f2; color: ' . $bodyText . '; font-family: Arial, Helvetica, sans-serif; font-size: 15px; line-height: 1.6; -webkit-font-smoothing: antialiased;">

<!-- Outer spacer -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #eef0f2;">
<tr><td align="center" style="padding: 24px 12px;">

<!--[if mso]>
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" align="center" style="width: 600px;"><tr><td>
<![endif]-->

<table role="presentation" class="email-container" width="100%" cellpadding="0" cellspacing="0" border="0" align="center" style="max-width: 600px; margin: 0 auto; background-color: ' . $lightBg . '; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.06);">
  <tr><td>' . $header . '</td></tr>
  <tr><td class="email-content mobile-padding" style="padding: 32px 28px; background-color: ' . $lightBg . '; color: ' . $bodyText . ';">' . $contentHtml . '</td></tr>
  <tr><td class="email-footer">' . $footer . '</td></tr>
</table>

<!--[if mso]>
</td></tr></table>
<![endif]-->

</td></tr>
</table>
</body>
</html>';
}

/**
 * Renders the lead notification email body content.
 */
function renderNotificationEmail(string $formType, array $fields): string {
    $orange = BRAND_ORANGE;
    $green = BRAND_GREEN;
    $muted = BRAND_MUTED_TEXT;
    $bodyText = BRAND_BODY_TEXT;
    $headingText = BRAND_HEADING_TEXT;
    $border = BRAND_BORDER;

    // Extract key fields
    $customerName = $fields['Name'] ?? 'Unknown';
    $service = $fields['Service'] ?? 'General';
    $urgency = $fields['Urgency'] ?? '';
    $email = $fields['Email'] ?? '';
    $phone = $fields['Phone'] ?? '';
    $message = $fields['Message'] ?? '';

    // Preheader (max 100 chars)
    $preheaderParts = array_filter([$customerName, $service]);
    if ($urgency && strtolower($urgency) !== 'not provided') $preheaderParts[] = $urgency;
    $preheader = implode(' \xe2\x80\x94 ', $preheaderParts);
    if (strlen($preheader) > 100) $preheader = substr($preheader, 0, 97) . '...';

    // Urgency classification
    $isUrgent = in_array(strtolower($urgency), ['emergency', 'asap', 'urgent'], true);
    $bannerColor = $isUrgent ? $orange : $green;
    $bannerLabel = $isUrgent ? "\xeF\x80\x83 URGENT \xe2\x80\x94 Immediate Response Needed" : "\xe2\x9c\x93 New Lead Received";

    // Timestamp in Delaware timezone
    $timestamp = getEasternTimestamp();

    $html = '';

    // Preheader (hidden)
    $html .= '<div style="display: none; max-height: 0; overflow: hidden; font-size: 1px; line-height: 1px; color: #f4f4f4; opacity: 0;">' . htmlspecialchars($preheader, ENT_QUOTES, 'UTF-8') . str_repeat(' &zwnj; &nbsp;', 20) . '</div>';

    // Urgency banner
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin: -32px -28px 24px -28px; width: calc(100% + 56px);">';
    $html .= '<tr><td style="background-color: ' . $bannerColor . '; padding: 12px 20px; text-align: center;">';
    $html .= '<strong style="color: #ffffff; font-size: 13px; font-family: Arial, Helvetica, sans-serif; letter-spacing: 0.5px;">' . $bannerLabel . '</strong>';
    $html .= '</td></tr></table>';

    // Header row: title + timestamp
    $formLabel = ($formType === 'booking') ? 'Booking Request' : 'Contact Message';
    $html .= '<h1 style="margin: 0 0 4px 0; font-size: 22px; color: ' . $headingText . '; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">New ' . $formLabel . '</h1>';
    $html .= '<p style="margin: 0 0 24px 0; font-size: 12px; color: #888888; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">' . $timestamp . '</p>';

    // Quick summary card
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f8faf8; border: 1px solid #e8ece8; border-radius: 6px; margin-bottom: 24px;">';
    $html .= '<tr><td style="padding: 16px 20px; background-color: #f8faf8;">';
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">';
    // Customer name
    $html .= '<tr><td style="padding: 4px 0; font-size: 18px; font-weight: bold; color: ' . $headingText . '; background-color: #f8faf8; font-family: Arial, Helvetica, sans-serif;">' . htmlspecialchars($customerName, ENT_QUOTES, 'UTF-8') . '</td></tr>';
    // Service
    $html .= '<tr><td style="padding: 2px 0; font-size: 14px; color: ' . $bodyText . '; background-color: #f8faf8; font-family: Arial, Helvetica, sans-serif;">' . htmlspecialchars($service, ENT_QUOTES, 'UTF-8') . '</td></tr>';
    // Phone (tappable)
    if (!empty($phone) && $phone !== 'Not provided') {
        $phoneDigits = preg_replace('/\D/', '', $phone);
        $html .= '<tr><td style="padding: 4px 0 0 0; background-color: #f8faf8;"><a href="tel:' . $phoneDigits . '" style="font-size: 16px; font-weight: bold; color: ' . $orange . '; text-decoration: none; font-family: Arial, Helvetica, sans-serif;">' . htmlspecialchars($phone, ENT_QUOTES, 'UTF-8') . '</a></td></tr>';
    }
    $html .= '</table>';
    $html .= '</td></tr></table>';

    // Reply CTA (prominent, right after summary)
    if (!empty($email) && $email !== 'Not provided' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $html .= '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin: 0 0 28px 0;" width="100%">';
        $html .= '<tr><td align="center">';
        $html .= '<a href="mailto:' . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . '?subject=Re: Your ' . urlencode($service) . ' request" style="display: inline-block; background-color: ' . $green . '; color: #ffffff; font-size: 15px; font-weight: bold; text-decoration: none; padding: 14px 32px; border-radius: 6px; font-family: Arial, Helvetica, sans-serif;">Reply to ' . htmlspecialchars(explode(' ', $customerName)[0], ENT_QUOTES, 'UTF-8') . '</a>';
        $html .= '</td></tr></table>';
    }

    // Detailed sections
    $html .= renderNotifSection('Contact Details', [
        'Name' => $customerName,
        'Phone' => $phone,
        'Email' => $email,
    ], $phone, $email);

    $html .= renderNotifSection('Service &amp; Request', [
        'Service Type' => $service,
        'Urgency' => $urgency,
        'Message' => $message,
    ]);

    // Location
    $locationData = [];
    if (!empty($fields['Service Address'])) $locationData['Street Address'] = $fields['Service Address'];
    if (!empty($fields['Apt/Suite']) && $fields['Apt/Suite'] !== 'Not provided') $locationData['Apt / Suite'] = $fields['Apt/Suite'];
    if (!empty($fields['Gate Code']) && $fields['Gate Code'] !== 'Not provided') $locationData['Gate Code'] = $fields['Gate Code'];
    $cityContext = $fields['City Context'] ?? '';
    if (!empty($cityContext) && $cityContext !== 'Site-Wide') $locationData['City'] = $cityContext;
    if (!empty($fields['Google Address']) && $fields['Google Address'] !== 'Not provided') $locationData['Verified Address'] = $fields['Google Address'];
    if (!empty($locationData)) {
        $html .= renderNotifSection('Location', $locationData);
    }

    // Booking-specific fields
    if ($formType === 'booking') {
        $bookingData = [];
        if (!empty($fields['Vehicle']) && $fields['Vehicle'] !== 'Not provided') $bookingData['Vehicle'] = $fields['Vehicle'];
        if (!empty($fields['Business Type']) && $fields['Business Type'] !== 'Not provided') $bookingData['Business Type'] = $fields['Business Type'];
        if (!empty($fields['Door Count']) && $fields['Door Count'] !== 'Not provided') $bookingData['Door Count'] = $fields['Door Count'];
        if (!empty($fields['Credential']) && $fields['Credential'] !== 'Not provided') $bookingData['Credential Interest'] = $fields['Credential'];
        if (!empty($bookingData)) {
            $html .= renderNotifSection('Additional Details', $bookingData);
        }
    }

    // Attribution (smaller, less prominent)
    $attrData = [];
    $attrKeys = ['Lead Source', 'Page Path', 'Page URL', 'Referrer',
        'UTM Source', 'UTM Medium', 'UTM Campaign', 'GCLID', 'FBCLID'];
    foreach ($attrKeys as $k) {
        if (!empty($fields[$k]) && $fields[$k] !== 'Not provided') $attrData[$k] = $fields[$k];
    }
    if (!empty($attrData)) {
        $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top: 24px; border-top: 1px solid ' . $border . '; padding-top: 16px;">';
        $html .= '<tr><td>';
        $html .= '<p style="margin: 0 0 8px 0; font-size: 11px; color: #aaaaaa; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif; text-transform: uppercase; letter-spacing: 0.5px;">Attribution</p>';
        $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family: Arial, Helvetica, sans-serif;">';
        foreach ($attrData as $label => $val) {
            $html .= '<tr>';
            $html .= '<td style="padding: 2px 8px 2px 0; font-size: 11px; color: #aaaaaa; background-color: #ffffff; vertical-align: top; width: 100px;">' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . '</td>';
            $html .= '<td style="padding: 2px 0; font-size: 11px; color: #777777; background-color: #ffffff; vertical-align: top; word-break: break-all;">' . htmlspecialchars($val, ENT_QUOTES, 'UTF-8') . '</td>';
            $html .= '</tr>';
        }
        $html .= '</table></td></tr></table>';
    }

    return $html;
}

/**
 * Renders a labeled section in the notification email.
 */
function renderNotifSection(string $title, array $data, string $phoneRaw = '', string $emailRaw = ''): string {
    $muted = BRAND_MUTED_TEXT;
    $bodyText = BRAND_BODY_TEXT;
    $headingText = BRAND_HEADING_TEXT;
    $border = BRAND_BORDER;
    $orange = BRAND_ORANGE;

    $html = '<h2 style="margin: 20px 0 10px 0; font-size: 12px; color: #888888; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid ' . $border . '; padding-bottom: 8px;">' . $title . '</h2>';
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family: Arial, Helvetica, sans-serif;">';

    foreach ($data as $label => $value) {
        $safeLabel = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
        $isEmpty = empty($value) || $value === 'Not provided';

        if ($isEmpty) {
            $displayValue = '<span style="color: ' . $muted . '; font-style: italic; font-size: 13px;">Not provided</span>';
        } elseif ($label === 'Phone' && !empty($phoneRaw)) {
            $digits = preg_replace('/\D/', '', $phoneRaw);
            $displayValue = '<a href="tel:' . $digits . '" style="color: ' . $orange . '; text-decoration: none; font-weight: bold; font-size: 14px;">' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '</a>';
        } elseif ($label === 'Email' && !empty($emailRaw) && filter_var($emailRaw, FILTER_VALIDATE_EMAIL)) {
            $displayValue = '<a href="mailto:' . htmlspecialchars($emailRaw, ENT_QUOTES, 'UTF-8') . '" style="color: ' . $bodyText . '; text-decoration: underline; font-size: 14px;">' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '</a>';
        } elseif ($label === 'Message') {
            $displayValue = '<span style="color: ' . $bodyText . '; font-size: 14px; line-height: 1.5;">' . nl2br(htmlspecialchars($value, ENT_QUOTES, 'UTF-8')) . '</span>';
        } else {
            $displayValue = '<span style="color: ' . $bodyText . '; font-size: 14px;">' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '</span>';
        }

        $html .= '<tr>';
        $html .= '<td style="padding: 7px 12px 7px 0; vertical-align: top; width: 120px; font-size: 12px; color: #888888; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">' . $safeLabel . '</td>';
        $html .= '<td style="padding: 7px 0; vertical-align: top; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">' . $displayValue . '</td>';
        $html .= '</tr>';
    }

    $html .= '</table>';
    return $html;
}

/**
 * Renders the autoresponder email body content.
 */
function renderAutoresponderEmail(string $formType, string $customerName): string {
    $orange = BRAND_ORANGE;
    $green = BRAND_GREEN;
    $bodyText = BRAND_BODY_TEXT;
    $headingText = BRAND_HEADING_TEXT;
    $muted = BRAND_MUTED_TEXT;
    $border = BRAND_BORDER;
    $phone = COMPANY_PHONE;
    $phoneRaw = COMPANY_PHONE_RAW;
    $estimatesUrl = COMPANY_ESTIMATES_URL;
    $hours = MOBILE_HOURS_DISPLAY;

    // Extract first name
    $trimmed = trim($customerName);
    $firstName = '';
    if ($trimmed !== '') {
        $parts = preg_split('/\s+/', $trimmed);
        $firstName = htmlspecialchars($parts[0], ENT_QUOTES, 'UTF-8');
    }
    if ($firstName === '') $firstName = 'Valued Customer';

    // Form-type-specific content
    if ($formType === 'booking') {
        $preheader = 'We received your booking request. A team member will reach out shortly.';
        $heading = 'Booking Request Received';
        $step3 = 'Technician dispatched to your location';
        $openingLine = "We've received your booking request and a team member is reviewing it now.";
    } else {
        $preheader = 'We received your message. A team member will reach out shortly.';
        $heading = 'Message Received';
        $step3 = 'We follow up with the information you need';
        $openingLine = "We've received your message and a team member will get back to you shortly.";
    }

    $html = '';

    // Preheader (hidden + padding to prevent inbox preview from pulling footer text)
    $html .= '<div style="display: none; max-height: 0; overflow: hidden; font-size: 1px; line-height: 1px; color: #ffffff; opacity: 0;">' . htmlspecialchars($preheader, ENT_QUOTES, 'UTF-8') . str_repeat(' &zwnj; &nbsp;', 30) . '</div>';

    // Green accent bar at top
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin: -32px -28px 28px -28px; width: calc(100% + 56px);">';
    $html .= '<tr><td style="background-color: ' . $green . '; height: 4px; font-size: 0; line-height: 0;">&nbsp;</td></tr></table>';

    // Heading
    $html .= '<h1 style="margin: 0 0 20px 0; font-size: 24px; color: ' . $headingText . '; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">' . $heading . '</h1>';

    // Greeting + opening
    $html .= '<p style="margin: 0 0 8px 0; font-size: 16px; line-height: 1.6; color: ' . $bodyText . '; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">Hi ' . $firstName . ',</p>';
    $html .= '<p style="margin: 0 0 28px 0; font-size: 15px; line-height: 1.7; color: ' . $bodyText . '; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">' . $openingLine . '</p>';

    // What Happens Next — card style
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f8faf8; border: 1px solid #e4ece4; border-radius: 8px; margin-bottom: 28px;">';
    $html .= '<tr><td style="padding: 20px 24px; background-color: #f8faf8;">';
    $html .= '<h2 style="margin: 0 0 14px 0; font-size: 15px; color: ' . $headingText . '; background-color: #f8faf8; font-family: Arial, Helvetica, sans-serif;">What Happens Next</h2>';

    $steps = [
        ['num' => '1', 'text' => 'Our team reviews your request'],
        ['num' => '2', 'text' => 'We reach out to confirm details and provide a quote'],
        ['num' => '3', 'text' => $step3],
    ];
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family: Arial, Helvetica, sans-serif;">';
    foreach ($steps as $step) {
        $html .= '<tr>';
        $html .= '<td style="width: 28px; vertical-align: top; padding: 8px 0; background-color: #f8faf8;">';
        $html .= '<span style="display: inline-block; width: 22px; height: 22px; line-height: 22px; text-align: center; background-color: ' . $green . '; color: #ffffff; font-size: 12px; font-weight: bold; border-radius: 50%;">' . $step['num'] . '</span>';
        $html .= '</td>';
        $html .= '<td style="vertical-align: middle; padding: 8px 0 8px 10px; font-size: 14px; color: ' . $bodyText . '; background-color: #f8faf8;">' . htmlspecialchars($step['text'], ENT_QUOTES, 'UTF-8') . '</td>';
        $html .= '</tr>';
    }
    $html .= '</table>';
    $html .= '</td></tr></table>';

    // Reassurance
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 28px;">';
    $html .= '<tr><td style="padding: 14px 20px; background-color: #fff8f0; border-left: 3px solid ' . $orange . '; border-radius: 0 6px 6px 0;">';
    $html .= '<p style="margin: 0; font-size: 14px; color: ' . $bodyText . '; background-color: #fff8f0; font-family: Arial, Helvetica, sans-serif;"><strong style="color: ' . $headingText . ';">Our promise:</strong> Quote before work starts &mdash; no surprises, no hidden fees.</p>';
    $html .= '</td></tr></table>';

    // CTAs
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 8px;">';
    // Phone CTA (orange, full width)
    $html .= '<tr><td align="center" style="padding-bottom: 12px;">';
    $html .= '<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>';
    $html .= '<td align="center" style="border-radius: 6px; background-color: ' . $orange . ';">';
    $html .= '<a href="tel:' . $phoneRaw . '" style="display: inline-block; padding: 14px 36px; font-size: 16px; font-weight: bold; color: #ffffff; background-color: ' . $orange . '; text-decoration: none; border-radius: 6px; font-family: Arial, Helvetica, sans-serif;">Call Now: ' . $phone . '</a>';
    $html .= '</td></tr></table>';
    $html .= '</td></tr>';
    // Services CTA (green outline style)
    $html .= '<tr><td align="center" style="padding-bottom: 4px;">';
    $html .= '<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>';
    $html .= '<td align="center" style="border-radius: 6px; border: 2px solid ' . $green . ';">';
    $html .= '<a href="' . $estimatesUrl . '" style="display: inline-block; padding: 11px 28px; font-size: 14px; font-weight: bold; color: ' . $green . '; background-color: #ffffff; text-decoration: none; border-radius: 4px; font-family: Arial, Helvetica, sans-serif;">View Our Services</a>';
    $html .= '</td></tr></table>';
    $html .= '</td></tr>';
    $html .= '</table>';

    // Hours info
    $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top: 24px; border-top: 1px solid ' . $border . '; padding-top: 20px;">';
    $html .= '<tr><td style="background-color: #ffffff;">';
    $html .= '<p style="margin: 0 0 4px 0; font-size: 13px; color: #666666; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;"><strong style="color: ' . $headingText . ';">When to expect a response:</strong></p>';
    $html .= '<p style="margin: 0 0 4px 0; font-size: 13px; color: #666666; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">Mobile Service: ' . $hours . '</p>';
    $html .= '<p style="margin: 0; font-size: 13px; color: #888888; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif;">Most requests receive a callback within 15&ndash;30 minutes during service hours.</p>';
    $html .= '</td></tr></table>';

    // No-reply notice
    $html .= '<p style="margin: 28px 0 0 0; font-size: 11px; color: ' . $muted . '; background-color: #ffffff; font-family: Arial, Helvetica, sans-serif; text-align: center;">This is an automated confirmation. Please do not reply to this email.</p>';

    return $html;
}
