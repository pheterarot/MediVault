<?php
// ============================================================
// MEDIVAULT — forgot_password.php
// Purpose:  Password reset request — accepts email input,
//           generates cryptographically secure token,
//           stores in password_resets table with 15-min expiry,
//           calls sendPasswordReset() with branded reset link
//           Rate limit: max 3 requests per hour per email
//           Security: always shows generic success message —
//           never reveals whether email exists in system
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
    header('Location: dashboard.php');
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
// VARIABLES
// ============================================================
$error   = '';
$success = '';

// ============================================================
// POST HANDLER — Forgot Password Form Submission
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
    // Step 2 — Sanitize Input
    // Note: email is cleaned through clean() for XSS safety
    // --------------------------------------------------------
    $email = clean($_POST['email'] ?? '');
    $ip    = getUserIP();

    // --------------------------------------------------------
    // Step 3 — Set generic success message immediately
    // Shown regardless of whether email exists in the system
    // This is intentional — never confirm email existence
    // --------------------------------------------------------
    $success = "If that email address is registered, a password reset link has been sent. Please check your inbox (and spam folder).";

    // --------------------------------------------------------
    // Step 4 — Look up user by email (prepared statement — SQL injection safe)
    // If not found, flow ends here — $success already set above
    // --------------------------------------------------------
    $stmt = $conn->prepare(
        "SELECT id, name, email FROM users WHERE email = ? LIMIT 1"
    );
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($user) {

        // --------------------------------------------------------
        // Step 5 — Rate limit check
        // Max 3 reset requests per hour per user
        // Count rows in password_resets created in last 60 minutes
        // If limit reached: silent — $success message already set
        // --------------------------------------------------------
        $rateStmt = $conn->prepare(
            "SELECT COUNT(*) AS request_count
             FROM password_resets
             WHERE user_id = ?
               AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)"
        );
        $rateStmt->bind_param("i", $user['id']);
        $rateStmt->execute();
        $rateRow = $rateStmt->get_result()->fetch_assoc();
        $rateStmt->close();

        if ((int)$rateRow['request_count'] < 3) {

            // --------------------------------------------------------
            // Step 6 — Generate cryptographically secure token
            // bin2hex(random_bytes(32)) = 64 hex chars, unguessable
            // --------------------------------------------------------
            $token  = bin2hex(random_bytes(32));
            $expiry = date('Y-m-d H:i:s', time() + 900); // 15 minutes from now

            // --------------------------------------------------------
            // Step 7 — Store token in password_resets table
            // is_used starts as 0 — marked 1 after successful reset
            // --------------------------------------------------------
            // AFTER — remove $expiry entirely, let MySQL handle it
            $insertStmt = $conn->prepare(
                "INSERT INTO password_resets (user_id, token, expiry, is_used)
                VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE), 0)"
            );
            $insertStmt->bind_param("is", $user['id'], $token);
            $insertStmt->execute();
            $insertStmt->close();

            // --------------------------------------------------------
            // Step 8 — Build reset link using SITE_URL from mailer.php
            // Token is URL-encoded for safe transmission
            // --------------------------------------------------------
            $resetLink = SITE_URL . 'reset_password.php?token=' . urlencode($token);

            // --------------------------------------------------------
            // Step 9 — Send branded reset email
            // On localhost Brevo rejects emails with localhost URLs.
            // Link is logged to PHP error log for manual copy during local testing.
            // On live, email sends normally with full clickable link.
            // try/catch — email failure must never break the flow
            // User still sees success message even if email fails
            // --------------------------------------------------------
            if (defined('IS_LOCALHOST') && IS_LOCALHOST) {
                error_log('[MediVault] Password reset link for ' . $user['name'] . ': ' . $resetLink);
            }

            try {
                sendPasswordReset($user['email'], $user['name'], $resetLink);
            } catch (Exception $e) {
                // Silent — $success still shown, token still stored
            }

            // --------------------------------------------------------
            // Step 10 — Log the request to activity_logs
            // Pre-login context — use $user['id'] directly (no session)
            // --------------------------------------------------------
            logActivity(
                $conn,
                $user['id'],
                "Password reset link requested from IP {$ip}",
                $ip
            );

        }
        // Rate limit hit — $success already set, nothing extra happens
    }
    // User not found — $success already set, nothing extra happens
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Forgot Password</title>
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
            margin-bottom: 20px;
        }

        /* ===================================================
           INFO BOX — security notice above form
        =================================================== */
        .info-box {
            background: #EFF6FF;
            border-left: 3px solid #2563EB;
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 24px;
            font-size: 12px;
            color: #1E40AF;
            line-height: 1.7;
        }

        /* ===================================================
           FORM ELEMENTS
        =================================================== */
        .form-group {
            margin-bottom: 18px;
        }

        .form-label {
            font-size: 13px;
            font-weight: 500;
            color: #1E293B;
            margin-bottom: 6px;
            display: block;
        }

        .form-control {
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            color: #1E293B;
            padding: 10px 14px;
            width: 100%;
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
           SUBMIT BUTTON
        =================================================== */
        .btn-submit {
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
            margin-top: 4px;
        }

        .btn-submit:hover {
            opacity: 0.92;
            transform: translateY(-1px);
            box-shadow: 0 6px 18px rgba(37, 99, 235, 0.45);
        }

        .btn-submit:active {
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
           BACK TO LOGIN LINK
        =================================================== */
        .back-link {
            display: block;
            text-align: center;
            font-size: 13px;
            color: #2563EB;
            text-decoration: none;
            font-weight: 500;
            margin-top: 22px;
            transition: color 0.2s ease;
        }

        .back-link:hover {
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
           PAGE FOOTER NOTE (below card)
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

            <!-- Card Body — Forgot Password Form -->
            <div class="card-body-form">

                <h1 class="form-title">Reset your password</h1>
                <p class="form-subtitle">Enter your email and we'll send you a secure reset link</p>

                <!-- Security notice -->
                <div class="info-box">
                    🔒 &nbsp;For your security, we will not confirm whether an email address
                    is registered. A reset link will be sent if the account exists.
                    Link expires in <strong>15 minutes</strong> and can only be used once.
                </div>

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
                     FORGOT PASSWORD FORM
                     Hidden after success — user can only submit once
                     then must use the link sent to their email
                ============================================ -->
                <?php if (!$success): ?>
                <form method="POST" action="forgot_password.php" autocomplete="off" novalidate id="forgotForm">

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

                    <!-- Submit Button -->
                    <button type="submit" class="btn-submit" id="submitBtn">
                        📧 &nbsp;Send Reset Link
                    </button>

                </form>
                <?php endif; ?>

                <!-- Back to Login — always visible -->
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

        <!-- Below-card note -->
        <p class="page-footer-note">
            🔒 &nbsp;Protected connection &nbsp;·&nbsp; All activity is monitored and logged
        </p>

    </div>
    <!-- End Login Wrapper -->

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ============================================================
        // PREVENT DOUBLE SUBMIT
        // Disables button immediately on submit — prevents resubmission
        // ============================================================
        const forgotForm = document.getElementById('forgotForm');
        const submitBtn  = document.getElementById('submitBtn');

        if (forgotForm && submitBtn) {
            forgotForm.addEventListener('submit', function () {
                const email = document.getElementById('email').value.trim();
                if (!email) return; // Let browser handle empty field validation
                submitBtn.disabled    = true;
                submitBtn.textContent = '⏳  Sending...';
            });
        }

        // ============================================================
        // AUTO-DISMISS SUCCESS ALERT AFTER 8 SECONDS
        // Longer than login (5s) — message is important, user needs time
        // ============================================================
        const successAlert = document.querySelector('.alert-success');
        if (successAlert) {
            setTimeout(function () {
                successAlert.style.transition = 'opacity 0.4s ease';
                successAlert.style.opacity    = '0';
                setTimeout(() => successAlert.remove(), 400);
            }, 8000);
        }
    </script>

</body>
</html>