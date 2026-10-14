<?php
// ============================================================
// MEDIVAULT — verify.php
// Purpose:  OTP verification after successful login credentials
//           Reads OTP from users table (never from session)
//           Sets full session variables on verified OTP only
//           Checks: first_login, IP change, unusual hours
//           Calls sendLoginNotif() on every successful login
// Layout:   No sidebar — centered auth card
// Includes: db.php, mailer.php
//           auth.php NOT included — this is a pre-login page
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/mailer.php';

// ============================================================
// SECURITY HEADERS
// Applied manually — auth.php is not included on pre-login pages
// ============================================================
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// ============================================================
// GATE — must have pending_user_id set by index.php
// If not set, user has not completed step 1 — send back to login
// ============================================================
if (!isset($_SESSION['pending_user_id'])) {
    header('Location: index.php');
    exit;
}

// ============================================================
// CSRF TOKEN
// Generated manually — verifyCsrf() from auth.php not available here
// ============================================================
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ============================================================
// HELPER — maskEmail()
// Masks most of the email for display: john@gmail.com → j***@g***.com
// Shows just enough for the user to confirm it's theirs
// ============================================================
function maskEmail($email) {
    $parts      = explode('@', $email);
    $user       = $parts[0]                      ?? '';
    $domain     = $parts[1]                      ?? '';
    $domainSplit = explode('.', $domain);
    $tld        = end($domainSplit);
    $domainName = $domainSplit[0]                ?? '';

    $maskedUser   = substr($user,       0, 1) . str_repeat('*', max(3, strlen($user)       - 1));
    $maskedDomain = substr($domainName, 0, 1) . str_repeat('*', max(3, strlen($domainName) - 1));

    return $maskedUser . '@' . $maskedDomain . '.' . $tld;
}

// ============================================================
// FETCH USER — always fetch fresh from DB
// Needed for: OTP value, expiry, rate limit state, display info
// ============================================================
$pendingId = (int)$_SESSION['pending_user_id'];

$stmt = $conn->prepare(
    "SELECT id, name, email, role, otp, otp_expiry,
            otp_attempts, otp_last_sent, first_login, last_login_ip
     FROM users WHERE id = ? LIMIT 1"
);
$stmt->bind_param("i", $pendingId);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

// If user row somehow missing — clear staging and redirect
if (!$user) {
    unset($_SESSION['pending_user_id']);
    header('Location: index.php');
    exit;
}

// ============================================================
// COMPUTE TIMER SECONDS
// How many seconds remain on the current OTP
// Passed to JS to start the countdown from the correct value
// ============================================================
$secondsRemaining = 0;
if (!empty($user['otp_expiry'])) {
    $secondsRemaining = max(0, strtotime($user['otp_expiry']) - time());
}

$maskedEmail = maskEmail($user['email']);
$ip          = getUserIP();
$error       = '';
$success     = '';

// ============================================================
// URL MESSAGE HANDLER
// ?resent=1 → OTP was just resent (PRG redirect from resend POST)
// ============================================================
if (isset($_GET['resent']) && $_GET['resent'] === '1') {
    $success = "A new OTP has been sent to your email. Please check your inbox.";
}

// ============================================================
// POST HANDLER
// Two actions:
//   action=verify  → user submitted OTP code
//   action=resend  → user clicked Resend OTP button
// ============================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // --------------------------------------------------------
    // CSRF Verification — manual (auth.php not included here)
    // --------------------------------------------------------
    if (
        !isset($_POST['csrf_token']) ||
        !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        http_response_code(403);
        die("
        <div style='font-family:Arial; text-align:center; padding:50px;'>
            <h2 style='color:#EF4444;'>Invalid Request</h2>
            <p style='color:#475569;'>CSRF token mismatch. Please go back and try again.</p>
            <a href='index.php' style='color:#2563EB;'>Back to Login</a>
        </div>
        ");
    }

    // Regenerate CSRF token after each POST
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    $action = $_POST['action'] ?? 'verify';

    // ============================================================
    // ACTION: RESEND OTP
    // ============================================================
    if ($action === 'resend') {

        $otpRateLimited = false;

        // Check rate limit — max 3 per 10-minute window
        if ($user['otp_last_sent'] !== null) {
            $lastSentTimestamp = strtotime($user['otp_last_sent']);
            $windowStart       = time() - 600;

            if ($lastSentTimestamp > $windowStart && $user['otp_attempts'] >= 3) {
                $otpRateLimited = true;
                $error = "Too many OTP requests. Please wait 10 minutes before requesting again.";
                logActivity($conn, $user['id'], "OTP resend rate limit hit on verify page", $ip);

            } elseif ($lastSentTimestamp <= $windowStart) {
                // 10-minute window expired — reset counter before new send
                $resetStmt = $conn->prepare("UPDATE users SET otp_attempts = 0 WHERE id = ?");
                $resetStmt->bind_param("i", $user['id']);
                $resetStmt->execute();
                $resetStmt->close();
                $user['otp_attempts'] = 0;
            }
        }

        if (!$otpRateLimited) {
            // Generate new OTP and update DB
            $newOtp         = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
            $newOtpExpiry   = date('Y-m-d H:i:s', time() + 300);
            $newOtpAttempts = $user['otp_attempts'] + 1;
            $nowStr         = date('Y-m-d H:i:s');

            $otpStmt = $conn->prepare(
                "UPDATE users
                 SET otp           = ?,
                     otp_expiry    = ?,
                     otp_attempts  = ?,
                     otp_last_sent = ?
                 WHERE id = ?"
            );
            $otpStmt->bind_param("ssisi", $newOtp, $newOtpExpiry, $newOtpAttempts, $nowStr, $user['id']);
            $otpStmt->execute();
            $otpStmt->close();

            // Send new OTP email (failure is silent — never breaks flow)
            sendOTP($user['email'], $newOtp, $user['name']);

            logActivity($conn, $user['id'], "OTP resent on verify page (attempt {$newOtpAttempts})", $ip);

            // PRG redirect to prevent form resubmission on reload
            header('Location: verify.php?resent=1');
            exit;
        }

    // ============================================================
    // ACTION: VERIFY OTP
    // ============================================================
    } else {

        $inputOtp = trim($_POST['otp'] ?? '');

        // --------------------------------------------------------
        // Check OTP expiry first
        // --------------------------------------------------------
        if (empty($user['otp_expiry']) || strtotime($user['otp_expiry']) < time()) {
            $error = "Your OTP has expired. Please request a new one.";
            logActivity($conn, $user['id'], "OTP verification failed — OTP expired", $ip);

        } elseif (empty($user['otp'])) {
            // No OTP stored — something went wrong, send back to login
            $error = "No OTP found. Please go back and login again.";

        } elseif (!hash_equals($user['otp'], $inputOtp)) {
            // --------------------------------------------------------
            // Wrong OTP — log and show error
            // hash_equals prevents timing attacks
            // --------------------------------------------------------
            $error = "Incorrect OTP. Please check your email and try again.";
            logActivity($conn, $user['id'], "OTP verification failed — wrong code entered", $ip);

        } else {
            // ============================================================
            // OTP VERIFIED — full login success flow
            // ============================================================

            // --------------------------------------------------------
            // 1. Set all session variables
            //    ONLY set here — never on index.php or anywhere earlier
            // --------------------------------------------------------
            $_SESSION['user_id']       = $user['id'];
            $_SESSION['user_name']     = $user['name'];
            $_SESSION['user_email']    = $user['email'];
            $_SESSION['user_role']     = $user['role'];
            $_SESSION['last_activity'] = time();
            $_SESSION['ip_address']    = $ip;
            $_SESSION['first_login']   = (bool)$user['first_login'];

            // --------------------------------------------------------
            // 2. Clear OTP from users table — one-time use enforced
            // --------------------------------------------------------
            $clearStmt = $conn->prepare(
                "UPDATE users SET otp = NULL, otp_expiry = NULL, otp_attempts = 0 WHERE id = ?"
            );
            $clearStmt->bind_param("i", $user['id']);
            $clearStmt->execute();
            $clearStmt->close();

            // --------------------------------------------------------
            // 3. IP change check — log suspicious if IP changed
            //    Compares current IP vs IP recorded on last successful login
            //    Flags possible session/account sharing or new device
            // --------------------------------------------------------
            if (!empty($user['last_login_ip']) && $user['last_login_ip'] !== $ip) {
                logSuspicious(
                    $conn,
                    $user['id'],
                    "Login from new IP address detected",
                    $ip,
                    "Previous IP: " . $user['last_login_ip'] . " | New IP: " . $ip
                );
            }

            // --------------------------------------------------------
            // 4. Unusual hours check — 10PM (22:00) to 5AM (05:00)
            //    Outside normal hospital working hours — flag suspicious
            // --------------------------------------------------------
            $loginHour = (int)date('H');
            if ($loginHour >= 22 || $loginHour < 5) {
                logSuspicious(
                    $conn,
                    $user['id'],
                    "Login during unusual hours",
                    $ip,
                    "Login at " . date('H:i:s') . " — outside normal hours (10PM–5AM flagged)"
                );
            }

            // --------------------------------------------------------
            // 5. Send login notification email to the user
            //    Includes: date/time, IP, browser/device info
            //    User can verify if it was them and alert admin if not
            // --------------------------------------------------------
            $browser   = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown Device';
            $loginTime = date('Y-m-d H:i:s');
            // try/catch — email failure must never break login flow or block redirect
            try {
                sendLoginNotif($user['email'], $user['name'], $ip, $browser, $loginTime);
            } catch (Exception $e) {
                // Silent — user is already logged in above; email is best-effort
            }

            // --------------------------------------------------------
            // 6. Update last_login_ip and last_login_time
            // --------------------------------------------------------
            $updateStmt = $conn->prepare(
                "UPDATE users SET last_login_ip = ?, last_login_time = NOW() WHERE id = ?"
            );
            $updateStmt->bind_param("si", $ip, $user['id']);
            $updateStmt->execute();
            $updateStmt->close();

            // --------------------------------------------------------
            // 7. Log successful login to activity_logs
            // --------------------------------------------------------
            logActivity($conn, $user['id'], "Login successful — OTP verified", $ip);

            // --------------------------------------------------------
            // 8. Clear staging session variable
            // --------------------------------------------------------
            unset($_SESSION['pending_user_id']);

            // --------------------------------------------------------
            // 9. Redirect — first_login check must come last
            //    If first_login = 1, user must change password immediately
            //    Cannot access any other page until done (enforced in auth.php)
            // --------------------------------------------------------
            if ($user['first_login']) {
                header('Location: change_password.php?msg=must_change_password');
            } else {
                header('Location: dashboard.php');
            }
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Verify OTP</title>
    <link rel="icon" href="assets/images/favicon.ico">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* ===================================================
           RESET & BASE
        =================================================== */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            color: #1E293B;
            min-height: 100vh;
            background: linear-gradient(135deg, #1E40AF 0%, #2563EB 50%, #38BDF8 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }

        /* ===================================================
           ANIMATED BACKGROUND SHAPES — matches index.php
        =================================================== */
        body::before,
        body::after {
            content: '';
            position: fixed;
            border-radius: 50%;
            opacity: 0.08;
            background: #ffffff;
            pointer-events: none;
        }

        body::before {
            width: 500px;
            height: 500px;
            top: -150px;
            right: -150px;
            animation: float1 8s ease-in-out infinite;
        }

        body::after {
            width: 350px;
            height: 350px;
            bottom: -100px;
            left: -100px;
            animation: float2 10s ease-in-out infinite;
        }

        @keyframes float1 {
            0%, 100% { transform: translate(0, 0) scale(1); }
            50%       { transform: translate(-20px, 20px) scale(1.05); }
        }

        @keyframes float2 {
            0%, 100% { transform: translate(0, 0) scale(1); }
            50%       { transform: translate(20px, -20px) scale(1.08); }
        }

        /* ===================================================
           VERIFY WRAPPER
        =================================================== */
        .verify-wrapper {
            width: 100%;
            max-width: 440px;
            position: relative;
            z-index: 10;
            animation: slideUp 0.5s ease-out both;
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        /* ===================================================
           AUTH CARD
        =================================================== */
        .auth-card {
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08),
                        0 20px 60px rgba(30, 64, 175, 0.25);
            overflow: hidden;
        }

        /* ===================================================
           CARD HEADER — gradient brand strip
        =================================================== */
        .card-header-brand {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            padding: 32px 40px 28px;
            text-align: center;
        }

        .brand-logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-bottom: 6px;
        }

        .brand-logo img {
            height: 36px;
            width: auto;
        }

        .brand-logo-icon {
            font-size: 28px;
            line-height: 1;
        }

        .brand-name {
            font-size: 26px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: 1.5px;
        }

        .brand-tagline {
            font-size: 11px;
            color: #BAE6FD;
            font-weight: 400;
            letter-spacing: 0.3px;
            margin-top: 2px;
        }

        /* ===================================================
           CARD BODY
        =================================================== */
        .card-body-form {
            padding: 36px 40px 32px;
        }

        .form-title {
            font-size: 20px;
            font-weight: 600;
            color: #1E293B;
            margin-bottom: 4px;
        }

        .form-subtitle {
            font-size: 13px;
            color: #94A3B8;
            margin-bottom: 6px;
        }

        .email-highlight {
            display: inline-block;
            background: #EFF6FF;
            color: #1E40AF;
            font-weight: 600;
            font-size: 13px;
            padding: 3px 10px;
            border-radius: 6px;
            margin-bottom: 24px;
            border: 1px solid #BFDBFE;
        }

        /* ===================================================
           COUNTDOWN TIMER WIDGET
        =================================================== */
        .timer-widget {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #F8FAFC;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 20px;
        }

        .timer-label {
            font-size: 12px;
            color: #94A3B8;
            font-weight: 500;
        }

        .timer-countdown {
            font-size: 22px;
            font-weight: 700;
            color: #22C55E;
            font-variant-numeric: tabular-nums;
            letter-spacing: 1px;
            transition: color 0.3s ease;
            min-width: 56px;
            text-align: right;
        }

        .timer-countdown.warning {
            color: #F59E0B;
        }

        .timer-countdown.danger {
            color: #EF4444;
        }

        /* ===================================================
           OTP INPUT
        =================================================== */
        .otp-label {
            font-size: 13px;
            font-weight: 500;
            color: #1E293B;
            margin-bottom: 8px;
            display: block;
        }

        .otp-input {
            font-family: 'Poppins', sans-serif;
            font-size: 30px;
            font-weight: 700;
            letter-spacing: 14px;
            text-align: center;
            border: 2px solid #E2E8F0;
            border-radius: 8px;
            padding: 14px 14px 14px 28px; /* offset for letter-spacing */
            width: 100%;
            color: #1E40AF;
            background: #F8FAFC;
            transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
            margin-bottom: 20px;
        }

        .otp-input:focus {
            border-color: #2563EB;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
            background: #ffffff;
            outline: none;
        }

        .otp-input::placeholder {
            color: #CBD5E1;
            font-size: 22px;
            letter-spacing: 10px;
        }

        .otp-input:disabled {
            background: #F1F5F9;
            color: #94A3B8;
            border-color: #E2E8F0;
            cursor: not-allowed;
        }

        /* ===================================================
           EXPIRED NOTICE (hidden by default, shown by JS)
        =================================================== */
        .expired-notice {
            display: none;
            background: #FEE2E2;
            border: 1px solid #FECACA;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 13px;
            color: #991B1B;
            margin-bottom: 20px;
            text-align: center;
        }

        /* ===================================================
           SUBMIT BUTTON
        =================================================== */
        .btn-verify {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            font-weight: 600;
            padding: 12px;
            width: 100%;
            cursor: pointer;
            transition: opacity 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease;
            letter-spacing: 0.3px;
            box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);
            margin-bottom: 16px;
        }

        .btn-verify:hover:not(:disabled) {
            opacity: 0.92;
            transform: translateY(-1px);
            box-shadow: 0 6px 18px rgba(37, 99, 235, 0.45);
        }

        .btn-verify:active:not(:disabled) {
            transform: translateY(0);
            opacity: 1;
        }

        .btn-verify:disabled {
            background: linear-gradient(135deg, #94A3B8, #CBD5E1);
            box-shadow: none;
            cursor: not-allowed;
            transform: none;
            opacity: 1;
        }

        /* ===================================================
           RESEND BUTTON
        =================================================== */
        .btn-resend {
            background: transparent;
            color: #2563EB;
            border: 1.5px solid #2563EB;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 13px;
            font-weight: 500;
            padding: 10px;
            width: 100%;
            cursor: pointer;
            transition: background 0.2s ease, color 0.2s ease, transform 0.15s ease;
        }

        .btn-resend:hover:not(:disabled) {
            background: #EFF6FF;
            transform: translateY(-1px);
        }

        .btn-resend:active:not(:disabled) {
            transform: translateY(0);
        }

        .btn-resend:disabled {
            color: #94A3B8;
            border-color: #E2E8F0;
            cursor: not-allowed;
            transform: none;
        }

        /* ===================================================
           ALERT MESSAGES
        =================================================== */
        .alert-custom {
            border-radius: 8px;
            font-size: 13px;
            padding: 12px 16px;
            margin-bottom: 20px;
            display: flex;
            align-items: flex-start;
            gap: 10px;
            border: none;
        }

        .alert-error {
            background: #FEE2E2;
            color: #991B1B;
        }

        .alert-success {
            background: #DCFCE7;
            color: #166534;
        }

        .alert-icon {
            font-size: 15px;
            flex-shrink: 0;
            margin-top: 1px;
        }

        /* ===================================================
           DIVIDER + BACK LINK
        =================================================== */
        .divider {
            border: none;
            border-top: 1px solid #E2E8F0;
            margin: 20px 0 16px;
        }

        .back-link {
            display: block;
            text-align: center;
            font-size: 12px;
            color: #94A3B8;
            text-decoration: none;
            transition: color 0.2s ease;
        }

        .back-link:hover {
            color: #2563EB;
        }

        /* ===================================================
           CARD FOOTER
        =================================================== */
        .card-footer-bar {
            background: #F8FAFC;
            border-top: 1px solid #E2E8F0;
            padding: 16px 40px;
            text-align: center;
        }

        .footer-text {
            font-size: 11px;
            color: #94A3B8;
        }

        /* ===================================================
           PAGE FOOTER NOTE
        =================================================== */
        .page-footer-note {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: rgba(255, 255, 255, 0.65);
        }

        /* ===================================================
           RESPONSIVE
        =================================================== */
        @media (max-width: 480px) {
            .card-header-brand { padding: 24px 24px 20px; }
            .card-body-form    { padding: 28px 24px 24px; }
            .card-footer-bar   { padding: 14px 24px; }
            .brand-name        { font-size: 22px; }
            .otp-input         { font-size: 24px; letter-spacing: 10px; padding-left: 20px; }
        }
    </style>
</head>
<body>

    <div class="verify-wrapper">

        <!-- ================================================
             AUTH CARD
        ================================================ -->
        <div class="auth-card">

            <!-- Card Header — Brand -->
            <div class="card-header-brand">
                <div class="brand-logo">
                    <?php if (file_exists('assets/images/logo.png')): ?>
                        <img src="assets/images/logo.png" alt="MediVault Logo">
                    <?php else: ?>
                        <span class="brand-logo-icon">🏥</span>
                    <?php endif; ?>
                    <span class="brand-name">MediVault</span>
                </div>
                <p class="brand-tagline">Securing Patient Records. Protecting Lives.</p>
            </div>

            <!-- Card Body -->
            <div class="card-body-form">

                <h1 class="form-title">Two-Factor Verification</h1>
                <p class="form-subtitle">A 6-digit OTP was sent to</p>
                <span class="email-highlight">✉️ &nbsp;<?= htmlspecialchars($maskedEmail, ENT_QUOTES, 'UTF-8') ?></span>

                <!-- ============================================
                     ERROR / SUCCESS ALERTS
                ============================================ -->
                <?php if ($error): ?>
                    <div class="alert-custom alert-error" role="alert">
                        <span class="alert-icon">⚠️</span>
                        <span><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></span>
                    </div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="alert-custom alert-success" role="alert">
                        <span class="alert-icon">✅</span>
                        <span><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></span>
                    </div>
                <?php endif; ?>

                <!-- ============================================
                     COUNTDOWN TIMER WIDGET
                ============================================ -->
                <div class="timer-widget">
                    <span class="timer-label">⏱ &nbsp;OTP expires in</span>
                    <span class="timer-countdown" id="countdown">
                        <?php
                            // Show initial MM:SS server-side before JS loads
                            $initMins = str_pad(floor($secondsRemaining / 60), 2, '0', STR_PAD_LEFT);
                            $initSecs = str_pad($secondsRemaining % 60, 2, '0', STR_PAD_LEFT);
                            echo "{$initMins}:{$initSecs}";
                        ?>
                    </span>
                </div>

                <!-- OTP EXPIRED NOTICE — shown by JS when timer hits 00:00 -->
                <div class="expired-notice" id="expiredNotice">
                    ⏰ &nbsp;Your OTP has expired. Please use the Resend button below.
                </div>

                <!-- ============================================
                     VERIFY OTP FORM
                ============================================ -->
                <form method="POST" action="verify.php" id="otpForm" autocomplete="off" novalidate>

                    <input type="hidden" name="csrf_token"
                           value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="action" value="verify">

                    <label for="otp" class="otp-label">Enter your 6-digit code</label>
                    <input
                        type="text"
                        id="otp"
                        name="otp"
                        class="otp-input"
                        placeholder="······"
                        maxlength="6"
                        inputmode="numeric"
                        pattern="[0-9]{6}"
                        autocomplete="one-time-code"
                        required
                        autofocus
                        <?= $secondsRemaining <= 0 ? 'disabled' : '' ?>
                    >

                    <button
                        type="submit"
                        class="btn-verify"
                        id="verifyBtn"
                        <?= $secondsRemaining <= 0 ? 'disabled' : '' ?>
                    >
                        ✅ &nbsp;Verify OTP
                    </button>

                </form>

                <!-- ============================================
                     RESEND OTP FORM
                     Separate form — POST action=resend
                     PRG redirect to verify.php?resent=1
                ============================================ -->
                <form method="POST" action="verify.php" id="resendForm">

                    <input type="hidden" name="csrf_token"
                           value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="action" value="resend">

                    <button
                        type="submit"
                        class="btn-resend"
                        id="resendBtn"
                    >
                        🔁 &nbsp;Resend OTP
                    </button>

                </form>

                <hr class="divider">

                <!-- Back to Login -->
                <a href="index.php" class="back-link">← Back to Login</a>

            </div>
            <!-- End Card Body -->

            <!-- Card Footer -->
            <div class="card-footer-bar">
                <p class="footer-text">
                    MediVault Hospital Patient Records Security System &copy; <?= date('Y') ?>
                </p>
            </div>

        </div>
        <!-- End Auth Card -->

        <p class="page-footer-note">
            🔒 &nbsp;Protected connection &nbsp;·&nbsp; All activity is monitored and logged
        </p>

    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ============================================================
        // COUNTDOWN TIMER
        // Starts from PHP-computed seconds remaining on the current OTP
        // Updates every second — changes color as time runs low
        // Disables the form and shows expired notice at 00:00
        // ============================================================
        let secondsLeft   = <?= (int)$secondsRemaining ?>;

        const countdownEl   = document.getElementById('countdown');
        const otpInput      = document.getElementById('otp');
        const verifyBtn     = document.getElementById('verifyBtn');
        const expiredNotice = document.getElementById('expiredNotice');

        function formatTime(secs) {
            const m = Math.floor(secs / 60);
            const s = secs % 60;
            return String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
        }

        function applyTimerColor(secs) {
            countdownEl.classList.remove('warning', 'danger');
            if (secs <= 60) {
                countdownEl.classList.add('danger');
            } else if (secs <= 120) {
                countdownEl.classList.add('warning');
            }
        }

        function onExpired() {
            countdownEl.textContent = '00:00';
            countdownEl.classList.remove('warning');
            countdownEl.classList.add('danger');

            // Disable the OTP input and verify button
            otpInput.disabled  = true;
            verifyBtn.disabled = true;
            verifyBtn.textContent = '⏰  OTP Expired';

            // Show the expired notice above the input
            if (expiredNotice) expiredNotice.style.display = 'block';
        }

        // Start timer only if there's time remaining
        if (secondsLeft <= 0) {
            onExpired();
        } else {
            applyTimerColor(secondsLeft);

            const timerInterval = setInterval(function () {
                secondsLeft--;

                if (secondsLeft <= 0) {
                    clearInterval(timerInterval);
                    onExpired();
                } else {
                    countdownEl.textContent = formatTime(secondsLeft);
                    applyTimerColor(secondsLeft);
                }
            }, 1000);
        }

        // ============================================================
        // OTP INPUT — digits only, auto-submit at 6 digits
        // ============================================================
        otpInput.addEventListener('input', function () {
            // Strip any non-digit characters as user types
            this.value = this.value.replace(/\D/g, '');

            // Auto-submit when exactly 6 digits are entered
            if (this.value.length === 6 && !this.disabled) {
                document.getElementById('otpForm').submit();
            }
        });

        // ============================================================
        // PREVENT DOUBLE SUBMIT — verify form
        // ============================================================
        document.getElementById('otpForm').addEventListener('submit', function () {
            if (verifyBtn.disabled) return;
            verifyBtn.disabled    = true;
            verifyBtn.textContent = '⏳  Verifying...';
        });

        // ============================================================
        // PREVENT DOUBLE SUBMIT — resend form
        // ============================================================
        const resendBtn = document.getElementById('resendBtn');
        document.getElementById('resendForm').addEventListener('submit', function () {
            resendBtn.disabled    = true;
            resendBtn.textContent = '⏳  Sending...';
        });

        // ============================================================
        // AUTO-DISMISS SUCCESS ALERTS AFTER 5 SECONDS
        // ============================================================
        const successAlert = document.querySelector('.alert-success');
        if (successAlert) {
            setTimeout(function () {
                successAlert.style.transition = 'opacity 0.4s ease';
                successAlert.style.opacity    = '0';
                setTimeout(() => successAlert.remove(), 400);
            }, 5000);
        }
    </script>

</body>
</html>
