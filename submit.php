<?php
/**
 * Contact form handler
 * Reads SMTP config from /home/stanreeves/form.env
 * Validates, rate-limits, sends email, redirects
 */

// Debug log file
$debug_log = '/home/stanreeves/.form-debug.log';

// Load config
$config_file = '/home/stanreeves/form.env';
if (!file_exists($config_file)) {
    file_put_contents($debug_log, date('Y-m-d H:i:s') . " Config file not found\n", FILE_APPEND);
    http_response_code(500);
    die('Configuration file not found');
}

$config = parse_ini_file($config_file);
if (!$config) {
    file_put_contents($debug_log, date('Y-m-d H:i:s') . " Failed to parse config\n", FILE_APPEND);
    http_response_code(500);
    die('Failed to load configuration');
}

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die('Method not allowed');
}

// Rate limiting by IP (store in home directory instead of /tmp)
$rate_limit = (int)($config['RATE_LIMIT'] ?? 3);
$rate_window = (int)($config['RATE_WINDOW'] ?? 3600);
$rate_dir = '/home/stanreeves/.form-rate';

// Create rate limit directory if it doesn't exist
if (!is_dir($rate_dir)) {
    @mkdir($rate_dir, 0700, true);
}

$rate_file = $rate_dir . '/rate_' . md5($_SERVER['REMOTE_ADDR']);

if (file_exists($rate_file)) {
    $data = json_decode(file_get_contents($rate_file), true);
    $now = time();

    // Prune old entries
    $data['times'] = array_filter($data['times'], fn($t) => ($now - $t) < $rate_window);

    if (count($data['times']) >= $rate_limit) {
        http_response_code(429);
        header('Location: ' . $config['ERROR_URL']);
        exit;
    }

    $data['times'][] = $now;
} else {
    $data = ['times' => [time()]];
}

@file_put_contents($rate_file, json_encode($data));

// Validate required fields
$required = ['name', 'email', 'message'];
foreach ($required as $field) {
    if (empty($_POST[$field] ?? '')) {
        header('Location: ' . $config['ERROR_URL']);
        exit;
    }
}

// Honeypot check (if the field is filled, it's a bot)
if (!empty($_POST['website'] ?? '')) {
    header('Location: ' . $config['THANKS_URL']);
    exit; // Silently succeed to confuse bots
}

// Sanitize inputs
$name = trim($_POST['name']);
$email = trim($_POST['email']);
$message = trim($_POST['message']);
$subject = trim($_POST['subject'] ?? '');

// Basic email validation
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    header('Location: ' . $config['ERROR_URL']);
    exit;
}

// Build email
$to = $config['TO_ADDRESS'];
$email_subject = $subject ? "New contact from stanreeves.com: " . $subject : "New contact from stanreeves.com";
$body = "Name: $name\n";
$body .= "Email: $email\n";
$body .= "Subject: " . ($subject ?: "(no subject)") . "\n";
$body .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
$body .= "---\n\n";
$body .= $message;

$headers = "From: noreply@stanreeves.com\r\n";
$headers .= "Reply-To: $email\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();

// Send via SMTP (use the actual TO_ADDRESS as the from address so postfix accepts it)
file_put_contents($debug_log, date('Y-m-d H:i:s') . " Attempting SMTP send to " . $config['SMTP_HOST'] . ":" . $config['SMTP_PORT'] . "\n", FILE_APPEND);

$sent = smtp_send(
    $config['SMTP_HOST'],
    (int)$config['SMTP_PORT'],
    $config['SMTP_USER'],
    $config['SMTP_PASSWORD'],
    $to,  // Use the TO_ADDRESS (stan@stanreeves.com) as the sender
    $to,
    $email_subject,
    $body
);

file_put_contents($debug_log, date('Y-m-d H:i:s') . " SMTP result: " . ($sent ? "success" : "failed") . "\n", FILE_APPEND);

if ($sent) {
    header('Location: ' . $config['THANKS_URL']);
} else {
    header('Location: ' . $config['ERROR_URL']);
}
exit;

/**
 * Send email via SMTP (port 587 with STARTTLS)
 */
function smtp_send($host, $port, $user, $pass, $from, $to, $subject, $body) {
    global $debug_log;

    // Connect
    $socket = @fsockopen($host, $port, $errno, $errstr, 10);
    if (!$socket) {
        file_put_contents($debug_log, date('Y-m-d H:i:s') . " SMTP connect failed: $errstr ($errno)\n", FILE_APPEND);
        return false;
    }
    file_put_contents($debug_log, date('Y-m-d H:i:s') . " SMTP connected to $host:$port\n", FILE_APPEND);

    stream_set_timeout($socket, 10);

    // Helper to read SMTP responses
    $read_response = function() use ($socket) {
        $response = '';
        while ($line = fgets($socket, 1024)) {
            $response .= $line;
            // Check if this is the last line (3 digits followed by space or dash)
            if (preg_match('/^\d{3}[- ]/', $line)) {
                // If dash, keep reading. If space, this is the last line.
                if (substr($line, 3, 1) == ' ') break;
            }
        }
        return $response;
    };

    // Read initial 220 response
    $resp = $read_response();
    if (strpos($resp, '220') === false) {
        fclose($socket);
        return false;
    }

    // EHLO
    fputs($socket, "EHLO stanreeves.com\r\n");
    $resp = $read_response();

    // STARTTLS
    fputs($socket, "STARTTLS\r\n");
    $resp = $read_response();
    if (strpos($resp, '220') === false) {
        fclose($socket);
        return false;
    }

    // Upgrade to TLS
    $crypto_method = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
    if (!stream_socket_enable_crypto($socket, true, $crypto_method)) {
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
            if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT)) {
                fclose($socket);
                return false;
            }
        } else {
            fclose($socket);
            return false;
        }
    }

    // EHLO again after TLS
    fputs($socket, "EHLO stanreeves.com\r\n");
    $resp = $read_response();

    // AUTH LOGIN
    fputs($socket, "AUTH LOGIN\r\n");
    $resp = $read_response();

    fputs($socket, base64_encode($user) . "\r\n");
    $resp = $read_response();

    fputs($socket, base64_encode($pass) . "\r\n");
    $resp = $read_response();
    if (strpos($resp, '235') === false) {
        fclose($socket);
        return false;
    }

    // MAIL FROM
    fputs($socket, "MAIL FROM: <$from>\r\n");
    $resp = $read_response();
    if (strpos($resp, '250') === false) {
        fclose($socket);
        return false;
    }

    // RCPT TO
    fputs($socket, "RCPT TO: <$to>\r\n");
    $resp = $read_response();
    if (strpos($resp, '250') === false) {
        fclose($socket);
        return false;
    }

    // DATA
    fputs($socket, "DATA\r\n");
    $resp = $read_response();
    if (strpos($resp, '354') === false) {
        fclose($socket);
        return false;
    }

    // Message (CRLF line endings required)
    $message = "Subject: $subject\r\n";
    $message .= "From: $from\r\n";
    $message .= "To: $to\r\n";
    $message .= "\r\n";
    $message .= $body;

    // Send message and end with CRLF.CRLF
    fputs($socket, $message . "\r\n.\r\n");
    $resp = $read_response();

    // QUIT
    fputs($socket, "QUIT\r\n");
    fclose($socket);

    return strpos($resp, '250') !== false;
}
