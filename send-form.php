<?php
declare(strict_types=1);

/**
 * send-form.php — generic form-to-email handler.
 *
 * Accepts a POST from the contact and Join Us forms, validates the fields
 * against the whitelist in $FORMS, and emails the result. Responds with JSON.
 *
 * Captcha: reCAPTCHA v2 or v3 (see verify_captcha()). Secret goes in form-secrets.php.
 *
 * To add a form: add an entry to $FORMS and give the HTML form a hidden
 * input named "form" whose value is that entry's key.
 */

/* ------------------------------------------------------------------ */
/* CONFIG                                                              */
/* ------------------------------------------------------------------ */

const MAIL_TO       = 'gabriel@bruze.com, caleb542@gmail.com';   // where submissions are delivered
const MAIL_FROM     = 'forms@bruze.com';       // must be an address on the hosting domain (IONOS rejects others)
const TIMEZONE      = 'America/Toronto';
const HONEYPOT      = 'hp_website';            // name of the hidden trap input
const RATE_LIMIT    = 5;                       // max submissions per IP ...
const RATE_WINDOW   = 600;                     // ... per this many seconds

$FORMS = [
    'contact' => [
        'subject' => 'Website contact form',
        'fields'  => [
            'FirstName'   => ['label' => 'First name', 'required' => true,  'max' => 100],
            'LastName'    => ['label' => 'Last name',  'required' => true,  'max' => 100],
            'PhoneNumber' => ['label' => 'Phone',      'required' => false, 'max' => 40, 'type' => 'phone'],
            'Email'       => ['label' => 'Email',      'required' => true,  'max' => 254, 'type' => 'email'],
            'Message'     => ['label' => 'Message',    'required' => true,  'max' => 5000],
        ],
    ],
    'join' => [
        'subject' => 'Website Join Us form',
        'fields'  => [
            'FirstName'   => ['label' => 'First name', 'required' => true,  'max' => 100],
            'LastName'    => ['label' => 'Last name',  'required' => true,  'max' => 100],
            'Email'       => ['label' => 'Email',      'required' => true,  'max' => 254, 'type' => 'email'],
            'PhoneNumber' => ['label' => 'Phone',      'required' => false, 'max' => 40, 'type' => 'phone'],
            'Position'    => ['label' => 'Position',   'required' => false, 'max' => 100],
            'CVLink'      => ['label' => 'CV link',    'required' => true,  'max' => 500],
        ],
    ],
];

// Secrets live outside version control. Create form-secrets.php next to this
// file (it is listed in .gitignore) containing:
//
//   <?php
//   const RECAPTCHA_SECRET = 'your-secret-key';
//
if (is_file(__DIR__ . '/form-secrets.php')) {
    require __DIR__ . '/form-secrets.php';
}

const RECAPTCHA_MIN_SCORE = 0.5;   // reCAPTCHA v3 only: 0.0 (bot) to 1.0 (human)

/**
 * Verifies the reCAPTCHA token posted as "g-recaptcha-response".
 * Handles v2 (checkbox / invisible) and v3 (score) with the same call:
 * both return "success"; v3 also returns "score" and "action".
 * Fails closed: any problem verifying counts as a failure.
 */
function verify_captcha(string $expectedAction): bool
{
    if (!defined('RECAPTCHA_SECRET') || RECAPTCHA_SECRET === '') {
        error_log('send-form.php: RECAPTCHA_SECRET is not configured');
        return false;
    }

    $token = $_POST['g-recaptcha-response'] ?? '';
    if (!is_string($token) || $token === '' || strlen($token) > 4096) {
        return false;
    }

    $post = http_build_query([
        'secret'   => RECAPTCHA_SECRET,
        'response' => $token,
        'remoteip' => client_ip(),
    ]);

    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $raw = false;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $post,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 8,
        ]);
        $raw = curl_exec($ch);
        curl_close($ch);
    } else {
        $raw = @file_get_contents($url, false, stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => 'Content-Type: application/x-www-form-urlencoded',
                'content' => $post,
                'timeout' => 8,
            ],
        ]));
    }

    if (!is_string($raw)) {
        error_log('send-form.php: reCAPTCHA verification request failed');
        return false;
    }

    $result = json_decode($raw, true);
    if (!is_array($result) || empty($result['success'])) {
        return false;
    }

    // v3 responses carry a score and the action the token was issued for.
    if (isset($result['score'])) {
        if ((float) $result['score'] < RECAPTCHA_MIN_SCORE) {
            return false;
        }
        if (($result['action'] ?? '') !== $expectedAction) {
            return false;
        }
    }

    return true;
}

/* ------------------------------------------------------------------ */
/* HELPERS                                                             */
/* ------------------------------------------------------------------ */

function respond(int $status, array $payload): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

/** Trim, normalise line endings, drop control characters (keeps \n and \t). */
function clean(mixed $value): string
{
    if (!is_string($value)) {
        return '';
    }
    $value = str_replace(["\r\n", "\r"], "\n", $value);
    $value = preg_replace('/[^\P{C}\n\t]+/u', '', $value) ?? '';
    return trim($value);
}

/** Single-line version for anything that ends up in a mail header. */
function header_safe(string $value): string
{
    return trim(preg_replace('/\s+/', ' ', $value) ?? '');
}

function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/** File-based per-IP throttle. Returns true when the request is allowed. */
function within_rate_limit(): bool
{
    $file = sys_get_temp_dir() . '/form_rate_' . md5(client_ip());
    $now  = time();
    $hits = [];

    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        return true; // fail open rather than block real users
    }
    flock($fh, LOCK_EX);
    $raw = stream_get_contents($fh);
    foreach (array_filter(explode("\n", (string) $raw)) as $t) {
        if ((int) $t > $now - RATE_WINDOW) {
            $hits[] = (int) $t;
        }
    }
    $allowed = count($hits) < RATE_LIMIT;
    if ($allowed) {
        $hits[] = $now;
    }
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, implode("\n", $hits));
    flock($fh, LOCK_UN);
    fclose($fh);

    return $allowed;
}

/* ------------------------------------------------------------------ */
/* REQUEST                                                             */
/* ------------------------------------------------------------------ */

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    respond(405, ['ok' => false, 'error' => 'Method not allowed.']);
}

// Honeypot: real users never fill this. Report success so bots learn nothing.
if (clean($_POST[HONEYPOT] ?? '') !== '') {
    respond(200, ['ok' => true]);
}

$formKey = clean($_POST['form'] ?? '');
if (!isset($FORMS[$formKey])) {
    respond(400, ['ok' => false, 'error' => 'Unknown form.']);
}
$form = $FORMS[$formKey];

if (!within_rate_limit()) {
    respond(429, ['ok' => false, 'error' => 'Too many submissions. Please try again later.']);
}

/* ------------------------------------------------------------------ */
/* VALIDATION                                                          */
/* ------------------------------------------------------------------ */

$values = [];
$errors = [];

foreach ($form['fields'] as $name => $rule) {
    $value = clean($_POST[$name] ?? '');

    if ($value === '') {
        if ($rule['required']) {
            $errors[$name] = $rule['label'] . ' is required.';
        }
        $values[$name] = '';
        continue;
    }

    if (mb_strlen($value) > $rule['max']) {
        $errors[$name] = $rule['label'] . ' is too long.';
        continue;
    }

    $type = $rule['type'] ?? 'text';
    if ($type === 'email' && filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
        $errors[$name] = 'Enter a valid email address.';
    } elseif ($type === 'phone' && !preg_match('/^[0-9+().\-\s]{7,40}$/', $value)) {
        $errors[$name] = 'Enter a valid phone number.';
    }

    $values[$name] = $value;
}

if ($errors) {
    respond(422, ['ok' => false, 'errors' => $errors]);
}

// Verified after field validation so a token is only spent on a complete submission.
if (!verify_captcha($formKey)) {
    respond(400, ['ok' => false, 'error' => 'Verification failed.']);
}

/* ------------------------------------------------------------------ */
/* EMAIL                                                               */
/* ------------------------------------------------------------------ */

date_default_timezone_set(TIMEZONE);

$lines = [];
foreach ($form['fields'] as $name => $rule) {
    $value = $values[$name];
    if (str_contains($value, "\n")) {
        $lines[] = $rule['label'] . ":\n" . $value . "\n";
    } else {
        $lines[] = $rule['label'] . ': ' . ($value === '' ? '-' : $value);
    }
}
$lines[] = '';
$lines[] = 'Sent: ' . date('Y-m-d H:i:s T');
$lines[] = 'IP: ' . client_ip();
$body = implode("\n", $lines) . "\n";

$senderName = header_safe(trim(($values['FirstName'] ?? '') . ' ' . ($values['LastName'] ?? '')));
$subject    = $form['subject'] . ($senderName !== '' ? ' - ' . $senderName : '');

$headers = [
    'From'                      => MAIL_FROM,
    'MIME-Version'              => '1.0',
    'Content-Type'              => 'text/plain; charset=UTF-8',
    'Content-Transfer-Encoding' => '8bit',
];
if (!empty($values['Email'])) {
    $headers['Reply-To'] = header_safe($values['Email']); // validated address, no display name
}

$sent = mail(
    MAIL_TO,
    mb_encode_mimeheader($subject, 'UTF-8'),
    str_replace("\n", "\r\n", $body),
    $headers
);

if (!$sent) {
    error_log('send-form.php: mail() failed for form "' . $formKey . '"');
    respond(500, ['ok' => false, 'error' => 'The message could not be sent.']);
}

respond(200, ['ok' => true]);