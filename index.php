<?php
// ============================================================
// MEDIVAULT — index.php
// Purpose:  Login entry point — email + password authentication
//           Generates OTP on success, stores in users table
//           Rate limits OTP sends (max 3 per 10 mins)
//           Locks account after 5 consecutive failed attempts
// Layout:   No sidebar — centered auth card, full-page gradient
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
// REDIRECT IF ALREADY LOGGED IN
// ============================================================
if (isset($_SESSION['user_id'])) {
    if (isset($_GET['relogin'])) {
        // Came from an email button — destroy session inline and show login form clean
        // No redirect hop needed; session is gone before the form renders below
        session_unset();
        session_destroy();
        session_start();
    } else {
        header('Location: dashboard.php');
        exit;
    }
}

// ============================================================
// CSRF TOKEN
// Generated manually — verifyCsrf() from auth.php not available here
// ============================================================
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ============================================================
// VARIABLES
// ============================================================
$error   = '';
$success = '';

// ============================================================
// URL MESSAGE HANDLER
// Handles redirect messages from other pages
// ============================================================
if (isset($_GET['msg'])) {
    $msgMap = [
        'session_expired'  => ['type' => 'error',   'text' => 'Your session has expired. Please login again.'],
        'login_required'   => ['type' => 'error',   'text' => 'You must be logged in to access that page.'],
        'unauthorized'     => ['type' => 'error',   'text' => 'You are not authorized to access that page.'],
        'logout'           => ['type' => 'success',  'text' => 'You have been logged out successfully.'],
        'password_changed' => ['type' => 'success',  'text' => 'Password changed. Please login with your new credentials.'],
    ];

    $msgKey = clean($_GET['msg']);
    if (array_key_exists($msgKey, $msgMap)) {
        if ($msgMap[$msgKey]['type'] === 'error') {
            $error = $msgMap[$msgKey]['text'];
        } else {
            $success = $msgMap[$msgKey]['text'];
        }
    }
}

// ============================================================
// POST HANDLER — Login Form Submission
// ============================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // --------------------------------------------------------
    // Step 1 — CSRF Verification
    // Manual check — verifyCsrf() from auth.php not available here
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
            <a href='javascript:history.back()' style='color:#2563EB;'>Go Back</a>
        </div>
        ");
    }

    // Regenerate token after every POST
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    // --------------------------------------------------------
    // Step 2 — Sanitize Inputs
    // Note: password is NOT passed through clean() — htmlspecialchars
    //       mangles special chars like <, >, &, ', " in passwords
    //       email is cleaned for XSS safety before DB query
    // --------------------------------------------------------
    $email    = clean($_POST['email']    ?? '');
    $password = $_POST['password']       ?? '';
    $ip       = getUserIP();

    // --------------------------------------------------------
    // Step 3 — Look up user by email (prepared statement — SQL injection safe)
    // --------------------------------------------------------
    $stmt = $conn->prepare(
        "SELECT id, name, email, password, role, is_locked,
                failed_attempts, first_login, otp_attempts, otp_last_sent
         FROM users WHERE email = ? LIMIT 1"
    );
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user) {
        // Generic error — never reveal which field is wrong
        // Cannot log to activity_logs — no valid user_id for FK constraint
        $error = "Invalid email or password. Please try again.";

    } else {

        // --------------------------------------------------------
        // Step 4 — Check account lock BEFORE password verify
        // Checking lock first avoids leaking whether password is correct
        // --------------------------------------------------------
        if ($user['is_locked']) {
            $error = "Account is locked. Use Forgot Password or contact your administrator.";
            logActivity($conn, $user['id'], "Login attempt on locked account", $ip);

        } else {

            // --------------------------------------------------------
            // Step 5 — Verify password
            // --------------------------------------------------------
            if (!password_verify($password, $user['password'])) {

                $newAttempts = $user['failed_attempts'] + 1;

                if ($newAttempts >= 5) {
                    // -----------------------------------------
                    // Lock the account
                    // -----------------------------------------
                    $lockStmt = $conn->prepare(
                        "UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE id = ?"
                    );
                    $lockStmt->bind_param("ii", $newAttempts, $user['id']);
                    $lockStmt->execute();
                    $lockStmt->close();

                    // Send account locked notification to user
                    // try/catch — email failure must never break lockout logic
                    try {
                        sendAccountLocked($user['email'], $user['name'], $ip);
                    } catch (Exception $e) {
                        // Silent — account is already locked above; email is best-effort
                    }

                    // Log as suspicious — shows red in logs.php
                    logSuspicious(
                        $conn,
                        $user['id'],
                        "Account locked after 5 failed login attempts",
                        $ip,
                        "5 consecutive wrong password attempts from IP {$ip} — account auto-locked"
                    );

                    // Alert admin
                    $adminEmail = getAdminEmail($conn);
                    if ($adminEmail) {
                        sendSuspiciousAlert(
                            $adminEmail,
                            $user['name'],
                            "Account locked after 5 consecutive failed login attempts",
                            $ip,
                            date('Y-m-d H:i:s')
                        );
                    }

                    $error = "Account is locked. Use Forgot Password or contact your administrator.";

                } else {
                    // -----------------------------------------
                    // Increment failed_attempts only
                    // -----------------------------------------
                    $incrStmt = $conn->prepare(
                        "UPDATE users SET failed_attempts = ? WHERE id = ?"
                    );
                    $incrStmt->bind_param("ii", $newAttempts, $user['id']);
                    $incrStmt->execute();
                    $incrStmt->close();

                    // Generic error — never reveal which field is wrong
                    $error = "Invalid email or password. Please try again.";
                    logActivity(
                        $conn,
                        $user['id'],
                        "Failed login attempt — wrong password (attempt {$newAttempts} of 5)",
                        $ip
                    );
                }

            } else {
                // --------------------------------------------------------
                // Step 6 — Password correct — check OTP rate limit
                // Max 3 OTP sends per 10-minute window
                // --------------------------------------------------------
                $otpRateLimited = false;

                if ($user['otp_last_sent'] !== null) {
                    $lastSentTimestamp = strtotime($user['otp_last_sent']);
                    $windowStart       = time() - 600; // 10 minutes ago

                    if ($lastSentTimestamp > $windowStart && $user['otp_attempts'] >= 3) {
                        // Within window, limit reached
                        $otpRateLimited = true;
                        $error = "Too many OTP requests. Please wait 10 minutes.";
                        logActivity($conn, $user['id'], "OTP rate limit hit — max 3 per 10 mins", $ip);

                    } elseif ($lastSentTimestamp <= $windowStart) {
                        // Window expired — reset otp_attempts before counting new send
                        $resetStmt = $conn->prepare(
                            "UPDATE users SET otp_attempts = 0 WHERE id = ?"
                        );
                        $resetStmt->bind_param("i", $user['id']);
                        $resetStmt->execute();
                        $resetStmt->close();
                        $user['otp_attempts'] = 0;
                    }
                }

                if (!$otpRateLimited) {
                    // --------------------------------------------------------
                    // Step 7 — Generate OTP and store in users table
                    // --------------------------------------------------------
                    $otp            = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
                    $otpExpiry      = date('Y-m-d H:i:s', time() + 300); // 5 minutes
                    $newOtpAttempts = $user['otp_attempts'] + 1;
                    $nowStr         = date('Y-m-d H:i:s');

                    $otpStmt = $conn->prepare(
                        "UPDATE users
                         SET failed_attempts = 0,
                             otp             = ?,
                             otp_expiry      = ?,
                             otp_attempts    = ?,
                             otp_last_sent   = ?
                         WHERE id = ?"
                    );
                    $otpStmt->bind_param("ssisi", $otp, $otpExpiry, $newOtpAttempts, $nowStr, $user['id']);
                    $otpStmt->execute();
                    $otpStmt->close();

                    // --------------------------------------------------------
                    // Step 8 — Send OTP email (failure is silent — never breaks flow)
                    // --------------------------------------------------------
                    sendOTP($user['email'], $otp, $user['name']);

                    // --------------------------------------------------------
                    // Step 9 — Store pending user ID in session
                    // NOT a full login session — just a staging ID for verify.php
                    // Full session variables are only set after OTP verified
                    // --------------------------------------------------------
                    $_SESSION['pending_user_id'] = $user['id'];

                    // --------------------------------------------------------
                    // Step 10 — Log and redirect to OTP verification
                    // --------------------------------------------------------
                    logActivity(
                        $conn,
                        $user['id'],
                        "Login credentials verified — OTP sent to {$user['email']}",
                        $ip
                    );

                    header('Location: verify.php');
                    exit;
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Login</title>
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
           ANIMATED BACKGROUND SHAPES
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
           LOGIN WRAPPER
        =================================================== */
        .login-wrapper {
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
           CARD BODY — form area
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
            margin-bottom: 28px;
        }

        /* ===================================================
           FORM ELEMENTS
        =================================================== */
        .form-label {
            font-size: 13px;
            font-weight: 500;
            color: #1E293B;
            margin-bottom: 6px;
        }

        .form-control {
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            color: #1E293B;
            padding: 10px 14px;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
            background: #F8FAFC;
        }

        .form-control:focus {
            border-color: #2563EB;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
            background: #ffffff;
            outline: none;
        }

        .form-control::placeholder {
            color: #CBD5E1;
            font-size: 13px;
        }

        /* ===================================================
           PASSWORD TOGGLE WRAPPER
        =================================================== */
        .password-wrapper {
            position: relative;
        }

        .password-wrapper .form-control {
            padding-right: 44px;
        }

        .toggle-password {
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            padding: 0;
            cursor: pointer;
            color: #94A3B8;
            font-size: 16px;
            line-height: 1;
            transition: color 0.2s ease;
        }

        .toggle-password:hover {
            color: #2563EB;
        }

        /* ===================================================
           SUBMIT BUTTON
        =================================================== */
        .btn-login {
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
        }

        .btn-login:hover {
            opacity: 0.92;
            transform: translateY(-1px);
            box-shadow: 0 6px 18px rgba(37, 99, 235, 0.45);
        }

        .btn-login:active {
            transform: translateY(0);
            opacity: 1;
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
           FORGOT PASSWORD LINK
        =================================================== */
        .forgot-link {
            display: block;
            text-align: right;
            font-size: 12px;
            color: #2563EB;
            text-decoration: none;
            font-weight: 500;
            margin-top: -4px;
            margin-bottom: 22px;
            transition: color 0.2s ease;
        }

        .forgot-link:hover {
            color: #1E40AF;
            text-decoration: underline;
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
           FORM GROUP SPACING
        =================================================== */
        .form-group {
            margin-bottom: 18px;
        }

        /* ===================================================
           SHIELD DECORATION (bottom of page)
        =================================================== */
        .page-footer-note {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: rgba(255, 255, 255, 0.65);
        }

        /* ===================================================
           RESPONSIVE ADJUSTMENTS
        =================================================== */
        @media (max-width: 480px) {
            .card-header-brand { padding: 24px 24px 20px; }
            .card-body-form    { padding: 28px 24px 24px; }
            .card-footer-bar   { padding: 14px 24px; }
            .brand-name        { font-size: 22px; }
        }
    </style>
</head>
<body>

    <div class="login-wrapper">

        <!-- ================================================
             AUTH CARD
        ================================================ -->
        <div class="auth-card">

            <!-- Card Header — Brand -->
            <div class="card-header-brand">
                <div class="brand-logo">
                    <!-- Use logo.png if it exists, fallback to emoji -->
                    <?php if (file_exists('assets/images/logo.png')): ?>
                        <img src="assets/images/logo.png" alt="MediVault Logo">
                    <?php else: ?>
                        <span class="brand-logo-icon">🏥</span>
                    <?php endif; ?>
                    <span class="brand-name">MediVault</span>
                </div>
                <p class="brand-tagline">Securing Patient Records. Protecting Lives.</p>
            </div>

            <!-- Card Body — Login Form -->
            <div class="card-body-form">

                <h1 class="form-title">Welcome back</h1>
                <p class="form-subtitle">Sign in to your account to continue</p>

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
                     LOGIN FORM
                ============================================ -->
                <form method="POST" action="index.php" autocomplete="off" novalidate>

                    <!-- CSRF Token — required on every form submission -->
                    <input type="hidden" name="csrf_token"
                           value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                    <!-- Email Field -->
                    <div class="form-group">
                        <label for="email" class="form-label">Email Address</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            class="form-control"
                            placeholder="you@hospital.com"
                            value="<?= isset($_POST['email']) ? htmlspecialchars(clean($_POST['email']), ENT_QUOTES, 'UTF-8') : '' ?>"
                            required
                            autofocus
                            maxlength="100"
                        >
                    </div>

                    <!-- Password Field with Show/Hide Toggle -->
                    <div class="form-group">
                        <label for="password" class="form-label">Password</label>
                        <div class="password-wrapper">
                            <input
                                type="password"
                                id="password"
                                name="password"
                                class="form-control"
                                placeholder="Enter your password"
                                required
                                maxlength="255"
                            >
                            <button
                                type="button"
                                class="toggle-password"
                                id="togglePassword"
                                aria-label="Show or hide password"
                                title="Show/hide password"
                            >👁</button>
                        </div>
                    </div>

                    <!-- Forgot Password Link -->
                    <a href="forgot_password.php" class="forgot-link">Forgot your password?</a>

                    <!-- Submit Button -->
                    <button type="submit" class="btn-login">
                        🔐 &nbsp;Sign In
                    </button>

                </form>

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

        <!-- Below-card note -->
        <p class="page-footer-note">
            🔒 &nbsp;Protected connection &nbsp;·&nbsp; All activity is monitored and logged
        </p>

    </div>
    <!-- End Login Wrapper -->

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ============================================================
        // PASSWORD SHOW / HIDE TOGGLE
        // ============================================================
        const toggleBtn      = document.getElementById('togglePassword');
        const passwordInput  = document.getElementById('password');
        let   passwordVisible = false;

        toggleBtn.addEventListener('click', function () {
            passwordVisible = !passwordVisible;
            passwordInput.type  = passwordVisible ? 'text' : 'password';
            toggleBtn.textContent = passwordVisible ? '🙈' : '👁';
        });

        // ============================================================
        // PREVENT DOUBLE SUBMIT
        // Disables the login button immediately on submit
        // to prevent the user from clicking twice
        // ============================================================
        const loginForm = document.querySelector('form');
        const loginBtn  = document.querySelector('.btn-login');

        loginForm.addEventListener('submit', function () {
            const email    = document.getElementById('email').value.trim();
            const password = passwordInput.value;

            if (!email || !password) {
                return; // Let browser handle empty field validation
            }

            loginBtn.disabled    = true;
            loginBtn.textContent = '⏳  Signing in...';
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