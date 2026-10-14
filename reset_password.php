<?php
// ============================================================
// MEDIVAULT — reset_password.php
// Purpose:  Set new password via secure single-use reset link
//           Reads token from URL (?token=xxx), validates against
//           password_resets table (expiry > NOW, is_used = 0)
//           Shows new password + confirm form with live rules
//           On success: updates users table, marks token used,
//           unlocks account, resets attempts, calls sendPasswordChanged()
//           Logs to activity_logs, redirects to index.php
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
// PASSWORD POLICY VALIDATION — PHP server-side
// Must match the JS live rules exactly (same rules, same order)
// Returns array of error strings — empty array means valid
// ============================================================
function validatePassword($password) {
    $errors = [];
    if (strlen($password) < 8)
        $errors[] = "At least 8 characters";
    if (strlen($password) > 72)
        $errors[] = "Maximum 72 characters";
    if (!preg_match('/[A-Z]/', $password))
        $errors[] = "At least 1 uppercase letter";
    if (!preg_match('/[a-z]/', $password))
        $errors[] = "At least 1 lowercase letter";
    if (!preg_match('/[0-9]/', $password))
        $errors[] = "At least 1 number";
    if (!preg_match('/[!@#$%^&*]/', $password))
        $errors[] = "At least 1 special character (!@#$%^&*)";
    return $errors;
}

// ============================================================
// VARIABLES
// ============================================================
$error          = '';
$success        = '';
$tokenValid     = false;
$tokenRow       = null;
$tokenUser      = null;

// ============================================================
// READ AND SANITIZE TOKEN FROM URL
// Token comes from GET on page load, hidden field on POST
// clean() uses htmlspecialchars — safe for DB comparison
// ============================================================
$rawToken = $_GET['token'] ?? $_POST['token'] ?? '';
$token = trim($rawToken);

// ============================================================
// VALIDATE TOKEN — query password_resets JOIN users
// Checks: token exists, not expired, not already used
// JOIN users so we have name + email ready without a second query
// ============================================================
if (!empty($token)) {
    $valStmt = $conn->prepare(
        "SELECT pr.id      AS reset_id,
                pr.user_id,
                pr.expiry,
                pr.is_used,
                u.id       AS uid,
                u.name,
                u.email,
                u.password AS current_hash
         FROM password_resets pr
         JOIN users u ON u.id = pr.user_id
         WHERE pr.token   = ?
           AND pr.expiry  > NOW()
           AND pr.is_used = 0
         LIMIT 1"
    );
    $valStmt->bind_param("s", $token);
    $valStmt->execute();
    $row = $valStmt->get_result()->fetch_assoc();
    $valStmt->close();

    if ($row) {
        $tokenValid = true;
        $tokenRow   = $row;
    }
}

// ============================================================
// POST HANDLER — New Password Form Submission
// Only runs if token is valid (form is only shown when valid)
// ============================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tokenValid) {

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
    // Step 2 — Read password inputs
    // Passwords are NOT passed through clean() — htmlspecialchars
    // mangles special characters like < > & that are valid in passwords
    // --------------------------------------------------------
    $newPassword     = $_POST['new_password']     ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $ip              = getUserIP();

    // --------------------------------------------------------
    // Step 3 — Confirm passwords match
    // --------------------------------------------------------
    if ($newPassword !== $confirmPassword) {
        $error = "Passwords do not match. Please try again.";

    } else {

        // --------------------------------------------------------
        // Step 4 — PHP server-side password policy validation
        // Even though JS validates live, always validate server-side too
        // --------------------------------------------------------
        $policyErrors = validatePassword($newPassword);

        if (!empty($policyErrors)) {
            $error = "Password does not meet requirements: " . implode(', ', $policyErrors) . ".";

        } else {

            // --------------------------------------------------------
            // Step 5 — Re-validate token is still valid
            // Edge case: token could expire between page load and submit
            // --------------------------------------------------------
            $revalStmt = $conn->prepare(
                "SELECT pr.id AS reset_id, pr.user_id,
                        u.name, u.email
                 FROM password_resets pr
                 JOIN users u ON u.id = pr.user_id
                 WHERE pr.token   = ?
                   AND pr.expiry  > NOW()
                   AND pr.is_used = 0
                 LIMIT 1"
            );
            $revalStmt->bind_param("s", $token);
            $revalStmt->execute();
            $freshRow = $revalStmt->get_result()->fetch_assoc();
            $revalStmt->close();

            if (!$freshRow) {
                // Token expired between page load and submit
                $tokenValid = false;
                $error = "Your reset link has expired. Please request a new one.";

            } else {

                // --------------------------------------------------------
                // Step 6 — Hash new password (bcrypt via PASSWORD_DEFAULT)
                // Never store plain text passwords
                // --------------------------------------------------------
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                $now            = date('Y-m-d H:i:s');

                // --------------------------------------------------------
                // Step 7 — Update users table
                // Reset password + unlock account + clear failed attempts
                // + set first_login = 0 (reset link counts as verified)
                // --------------------------------------------------------
                $updateStmt = $conn->prepare(
                    "UPDATE users
                     SET password        = ?,
                         is_locked       = 0,
                         failed_attempts = 0,
                         first_login     = 0,
                         updated_at      = ?
                     WHERE id = ?"
                );
                $updateStmt->bind_param("ssi", $hashedPassword, $now, $freshRow['user_id']);
                $updateStmt->execute();
                $updateStmt->close();

                // --------------------------------------------------------
                // Step 8 — Mark token as used in password_resets
                // Single-use token — immediately invalidated after use
                // --------------------------------------------------------
                $markStmt = $conn->prepare(
                    "UPDATE password_resets SET is_used = 1 WHERE id = ?"
                );
                $markStmt->bind_param("i", $freshRow['reset_id']);
                $markStmt->execute();
                $markStmt->close();

                // --------------------------------------------------------
                // Step 9 — Send password changed notification email
                // try/catch — email failure must never break the main flow
                // --------------------------------------------------------
                try {
                    sendPasswordChanged(
                        $freshRow['email'],
                        $freshRow['name'],
                        $ip,
                        $now
                    );
                } catch (Exception $e) {
                    // Silent — password is already changed above
                }

                // --------------------------------------------------------
                // Step 10 — Log to activity_logs
                // Pre-login context — use user_id from the reset row
                // --------------------------------------------------------
                logActivity(
                    $conn,
                    $freshRow['user_id'],
                    "Password reset successfully via reset link from IP {$ip}",
                    $ip
                );

                // --------------------------------------------------------
                // Step 11 — Redirect to login with success message
                // index.php already handles msg=password_changed
                // --------------------------------------------------------
                header('Location: index.php?msg=password_changed');
                exit;
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
    <title>MediVault — Reset Password</title>
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
            max-width: 460px;
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
            margin-bottom: 24px;
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
           PASSWORD RULES CHECKLIST
           Live visual feedback as user types
        =================================================== */
        .rules-box {
            background: #F8FAFC;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 14px 16px;
            margin-bottom: 18px;
        }

        .rules-title {
            font-size: 11px;
            font-weight: 600;
            color: #94A3B8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }

        .rules-list {
            list-style: none;
            padding: 0;
            margin: 0;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .rules-list li {
            font-size: 12px;
            font-weight: 500;
            color: #EF4444;
            transition: color 0.2s ease;
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
           INVALID TOKEN STATE — centered message card body
        =================================================== */
        .token-invalid-box {
            text-align: center;
            padding: 10px 0 6px;
        }

        .token-invalid-icon {
            font-size: 48px;
            margin-bottom: 16px;
            display: block;
        }

        .token-invalid-title {
            font-size: 18px;
            font-weight: 600;
            color: #EF4444;
            margin-bottom: 8px;
        }

        .token-invalid-text {
            font-size: 13px;
            color: #94A3B8;
            margin-bottom: 24px;
            line-height: 1.6;
        }

        .btn-request-new {
            display: inline-block;
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 13px;
            font-weight: 600;
            padding: 11px 28px;
            text-decoration: none;
            cursor: pointer;
            transition: opacity 0.2s ease, transform 0.15s ease;
            box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3);
        }

        .btn-request-new:hover {
            opacity: 0.90;
            transform: translateY(-1px);
            color: #ffffff;
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

            <!-- Card Body -->
            <div class="card-body-form">

                <?php if (!$tokenValid): ?>
                <!-- ============================================
                     INVALID / EXPIRED TOKEN STATE
                     Shown when: token missing, not found in DB,
                     already expired, or already used
                ============================================ -->
                <div class="token-invalid-box">
                    <span class="token-invalid-icon">🔗</span>
                    <h1 class="token-invalid-title">Link Invalid or Expired</h1>
                    <p class="token-invalid-text">
                        This password reset link is invalid, has already been used,
                        or has expired. Reset links are valid for <strong>15 minutes</strong>
                        and can only be used once.
                    </p>
                    <a href="forgot_password.php" class="btn-request-new">
                        🔑 &nbsp;Request New Reset Link
                    </a>
                </div>

                <?php else: ?>
                <!-- ============================================
                     VALID TOKEN — SHOW RESET FORM
                ============================================ -->
                <h1 class="form-title">Set new password</h1>
                <p class="form-subtitle">Choose a strong password for your account</p>

                <!-- ============================================
                     ERROR ALERTS
                ============================================ -->
                <?php if ($error): ?>
                    <div class="alert-custom alert-error" role="alert">
                        <span class="alert-icon">⚠️</span>
                        <span><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></span>
                    </div>
                <?php endif; ?>

                <!-- ============================================
                     RESET PASSWORD FORM
                ============================================ -->
                <form method="POST"
                      action="reset_password.php"
                      autocomplete="off"
                      novalidate
                      id="resetForm">

                    <!-- CSRF Token -->
                    <input type="hidden" name="csrf_token"
                           value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                    <!-- Token passed through hidden field on POST -->
                    <input type="hidden" name="token"
                           value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">

                    <!-- New Password Field -->
                    <div class="form-group">
                        <label for="new_password" class="form-label">New Password</label>
                        <div class="password-wrapper">
                            <input
                                type="password"
                                id="new_password"
                                name="new_password"
                                class="form-control"
                                placeholder="Enter new password"
                                required
                                maxlength="72"
                                autocomplete="new-password"
                            >
                            <button
                                type="button"
                                class="toggle-password"
                                id="toggleNew"
                                aria-label="Show or hide new password"
                                title="Show/hide password"
                            >👁</button>
                        </div>
                    </div>

                    <!-- Live Password Rules Checklist -->
                    <div class="rules-box">
                        <p class="rules-title">Password Requirements</p>
                        <ul class="rules-list">
                            <li id="rule-length">❌ At least 8 characters</li>
                            <li id="rule-uppercase">❌ At least 1 uppercase letter</li>
                            <li id="rule-lowercase">❌ At least 1 lowercase letter</li>
                            <li id="rule-number">❌ At least 1 number</li>
                            <li id="rule-special">❌ At least 1 special character (!@#$%^&amp;*)</li>
                        </ul>
                    </div>

                    <!-- Confirm Password Field -->
                    <div class="form-group">
                        <label for="confirm_password" class="form-label">Confirm New Password</label>
                        <div class="password-wrapper">
                            <input
                                type="password"
                                id="confirm_password"
                                name="confirm_password"
                                class="form-control"
                                placeholder="Re-enter new password"
                                required
                                maxlength="72"
                                autocomplete="new-password"
                            >
                            <button
                                type="button"
                                class="toggle-password"
                                id="toggleConfirm"
                                aria-label="Show or hide confirm password"
                                title="Show/hide password"
                            >👁</button>
                        </div>
                    </div>

                    <!-- Submit Button -->
                    <button type="submit" class="btn-submit" id="submitBtn">
                        🔐 &nbsp;Reset Password
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
        // LIVE PASSWORD RULE CHECKER
        // Updates each rule item in real-time as user types
        // Rule element IDs match spec exactly:
        //   rule-length, rule-uppercase, rule-lowercase,
        //   rule-number, rule-special
        // ============================================================
        function checkPassword(password) {
            const rules = {
                length:    {
                    test: password.length >= 8,
                    text: "At least 8 characters"
                },
                uppercase: {
                    test: /[A-Z]/.test(password),
                    text: "At least 1 uppercase letter"
                },
                lowercase: {
                    test: /[a-z]/.test(password),
                    text: "At least 1 lowercase letter"
                },
                number: {
                    test: /[0-9]/.test(password),
                    text: "At least 1 number"
                },
                special: {
                    test: /[!@#$%^&*]/.test(password),
                    text: "At least 1 special character (!@#$%^&*)"
                }
            };

            Object.keys(rules).forEach(key => {
                const el = document.getElementById('rule-' + key);
                if (el) {
                    el.style.color   = rules[key].test ? '#22C55E' : '#EF4444';
                    el.textContent   = (rules[key].test ? '✅ ' : '❌ ') + rules[key].text;
                }
            });

            // Return true only when all rules pass
            return Object.values(rules).every(r => r.test);
        }

        // ============================================================
        // PASSWORD FIELD LISTENER
        // Fires checkPassword on every keystroke in new_password
        // ============================================================
        const newPasswordInput = document.getElementById('new_password');

        if (newPasswordInput) {
            newPasswordInput.addEventListener('input', function () {
                checkPassword(this.value);
            });
        }

        // ============================================================
        // PASSWORD SHOW / HIDE TOGGLES
        // Two separate toggles — one per password field
        // ============================================================
        function setupToggle(buttonId, inputId) {
            const btn   = document.getElementById(buttonId);
            const input = document.getElementById(inputId);
            if (!btn || !input) return;

            let visible = false;
            btn.addEventListener('click', function () {
                visible      = !visible;
                input.type   = visible ? 'text' : 'password';
                btn.textContent = visible ? '🙈' : '👁';
            });
        }

        setupToggle('toggleNew',     'new_password');
        setupToggle('toggleConfirm', 'confirm_password');

        // ============================================================
        // PREVENT DOUBLE SUBMIT
        // Disables button immediately on submit — prevents resubmission
        // Also blocks submit if password rules are not all passing
        // ============================================================
        const resetForm = document.getElementById('resetForm');
        const submitBtn = document.getElementById('submitBtn');

        if (resetForm && submitBtn) {
            resetForm.addEventListener('submit', function (e) {
                const pw      = document.getElementById('new_password').value;
                const confirm = document.getElementById('confirm_password').value;

                if (!pw || !confirm) return; // Let browser handle empty fields

                // Run final policy check before allowing submit
                const allPass = checkPassword(pw);
                if (!allPass) {
                    e.preventDefault();
                    return;
                }

                // Disable button to prevent double submit
                submitBtn.disabled    = true;
                submitBtn.textContent = '⏳  Updating...';
            });
        }
    </script>

</body>
</html>
