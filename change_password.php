<?php
// ============================================================
// MEDIVAULT — change_password.php
// Purpose:  Change password while logged in
//           Verifies current password before allowing change
//           Enforces password policy (JS live + PHP server-side)
//           Checks new password is not same as current
//           On first_login: forces change before any navigation
//           On success: updates users table, sends notification,
//           logs action, redirects to dashboard after 3 seconds
// Layout:   Full sidebar — protected page
// Access:   All roles (admin, doctor, nurse, receptionist)
// Includes: db.php, auth.php, mailer.php
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';
require 'includes/mailer.php';

// ============================================================
// ACCESS CONTROL
// All 4 roles allowed — this page is accessible to everyone
// auth.php handles: session timeout, IP check, CSRF generation,
// security headers, and first_login redirect enforcement
// ============================================================
requireRole(['admin', 'doctor', 'nurse', 'receptionist']);

// ============================================================
// PASSWORD POLICY VALIDATION — PHP server-side
// Must match the JS live rules exactly (same rules, same order)
// Returns array of error strings — empty array means valid
// Identical to reset_password.php validatePassword()
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
        $errors[] = "At least 1 special character (!@#\$%^&*)";
    return $errors;
}

// ============================================================
// FETCH CURRENT USER — always fresh from DB
// Needed for: name, email, current password hash, first_login
// ============================================================
$userId = (int)$_SESSION['user_id'];

$stmt = $conn->prepare(
    "SELECT id, name, email, password, role, first_login
     FROM users WHERE id = ? LIMIT 1"
);
$stmt->bind_param("i", $userId);
$stmt->execute();
$currentUser = $stmt->get_result()->fetch_assoc();
$stmt->close();

// If user row somehow missing — destroy session and redirect
if (!$currentUser) {
    session_unset();
    session_destroy();
    header('Location: index.php');
    exit;
}

// ============================================================
// VARIABLES
// ============================================================
$error      = '';
$success    = '';
$redirectJs = false; // triggers 3-second JS countdown on success

// ============================================================
// URL MESSAGE HANDLER
// ?msg=must_change_password — set by auth.php requireRole()
// when first_login = 1 and user tries to access other pages
// ============================================================
if (isset($_GET['msg']) && $_GET['msg'] === 'must_change_password') {
    $error = "You must change your temporary password before you can access the system.";
}

// ============================================================
// POST HANDLER — Change Password Form Submission
// ============================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // --------------------------------------------------------
    // Step 1 — CSRF Verification
    // verifyCsrf() from auth.php — also regenerates the token
    // --------------------------------------------------------
    verifyCsrf();

    // --------------------------------------------------------
    // Step 2 — Read inputs
    // Passwords NOT passed through clean() — htmlspecialchars
    // mangles special characters that are valid in passwords
    // --------------------------------------------------------
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword     = $_POST['new_password']     ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $ip              = getUserIP();

    // --------------------------------------------------------
    // Step 3 — Verify current password against stored hash
    // Must match before any further action is taken
    // --------------------------------------------------------
    if (!password_verify($currentPassword, $currentUser['password'])) {
        $error = "Your current password is incorrect. Please try again.";

    // --------------------------------------------------------
    // Step 4 — Confirm new passwords match
    // --------------------------------------------------------
    } elseif ($newPassword !== $confirmPassword) {
        $error = "New passwords do not match. Please try again.";

    // --------------------------------------------------------
    // Step 5 — Ensure new password differs from current
    // Prevents re-using the same password
    // --------------------------------------------------------
    } elseif (password_verify($newPassword, $currentUser['password'])) {
        $error = "New password must be different from your current password.";

    } else {

        // --------------------------------------------------------
        // Step 6 — PHP server-side password policy validation
        // JS validates live in the browser, but always validate
        // server-side too — never trust client-side alone
        // --------------------------------------------------------
        $policyErrors = validatePassword($newPassword);

        if (!empty($policyErrors)) {
            $error = "Password does not meet requirements: " . implode(', ', $policyErrors) . ".";

        } else {

            // --------------------------------------------------------
            // Step 7 — Hash new password (bcrypt via PASSWORD_DEFAULT)
            // Never store plain text passwords
            // --------------------------------------------------------
            $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
            $now     = date('Y-m-d H:i:s');

            // --------------------------------------------------------
            // Step 8 — Update users table
            // Set new hash, clear first_login flag, update timestamp
            // --------------------------------------------------------
            $updateStmt = $conn->prepare(
                "UPDATE users
                 SET password    = ?,
                     first_login = 0,
                     updated_at  = ?
                 WHERE id = ?"
            );
            $updateStmt->bind_param("ssi", $newHash, $now, $userId);
            $updateStmt->execute();
            $updateStmt->close();

            // --------------------------------------------------------
            // Step 9 — Clear first_login from session
            // Unlocks full sidebar navigation immediately
            // --------------------------------------------------------
            unset($_SESSION['first_login']);

            // --------------------------------------------------------
            // Step 10 — Send password changed notification email
            // try/catch — email failure must never break main flow
            // --------------------------------------------------------
            try {
                sendPasswordChanged(
                    $currentUser['email'],
                    $currentUser['name'],
                    $ip,
                    $now
                );
            } catch (Exception $e) {
                // Silent — password already changed; email is best-effort
            }

            // --------------------------------------------------------
            // Step 11 — Log the action to activity_logs
            // --------------------------------------------------------
            logActivity(
                $conn,
                $userId,
                "Password changed successfully",
                $ip
            );

            // --------------------------------------------------------
            // Step 12 — Set success and trigger 3-second JS redirect
            // Redirects to dashboard — full navigation now available
            // --------------------------------------------------------
            $success    = "Password changed successfully! Redirecting you to the dashboard in 3 seconds.";
            $redirectJs = true;

            // Update local copy so sidebar renders correctly
            $currentUser['first_login'] = 0;
        }
    }
}

// ============================================================
// SIDEBAR DISPLAY HELPERS
// ============================================================
$isFirstLogin = !empty($_SESSION['first_login']);
$userRole     = $_SESSION['user_role'] ?? $currentUser['role'];
$userName     = $_SESSION['user_name'] ?? $currentUser['name'];
$isAdmin      = ($userRole === 'admin');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Change Password</title>
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
            background: #F8FAFC;
            color: #1E293B;
            font-size: 14px;
        }

        /* ===================================================
           SIDEBAR
        =================================================== */
        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            width: 250px;
            height: 100vh;
            background: linear-gradient(180deg, #1E40AF, #2563EB);
            display: flex;
            flex-direction: column;
            z-index: 1000;
            overflow-y: auto;
        }

        .sidebar-brand {
            padding: 24px 20px 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.15);
            flex-shrink: 0;
        }

        .sidebar-brand-name {
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: 1px;
        }

        .sidebar-tagline {
            font-size: 10px;
            color: rgba(255, 255, 255, 0.6);
            margin-top: 3px;
            line-height: 1.4;
        }

        .sidebar-nav {
            flex: 1;
            padding: 12px 0;
        }

        .sidebar-nav a {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 20px;
            color: rgba(255, 255, 255, 0.85);
            text-decoration: none;
            font-size: 13px;
            font-weight: 500;
            transition: background 0.2s ease, color 0.2s ease;
        }

        .sidebar-nav a:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
        }

        .sidebar-nav a.active {
            background: rgba(255, 255, 255, 0.15);
            color: #ffffff;
            font-weight: 600;
        }

        /* Disabled state — first_login enforcement */
        .sidebar-nav a.nav-disabled {
            opacity: 0.35;
            cursor: not-allowed;
            pointer-events: none;
        }

        .sidebar-divider {
            border: none;
            border-top: 1px solid rgba(255, 255, 255, 0.15);
            margin: 8px 20px;
        }

        .sidebar-user {
            padding: 16px 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.15);
            flex-shrink: 0;
        }

        .sidebar-user-name {
            font-size: 13px;
            font-weight: 600;
            color: #ffffff;
        }

        .sidebar-user-role {
            font-size: 11px;
            color: rgba(255, 255, 255, 0.6);
            text-transform: capitalize;
            margin-top: 2px;
        }

        /* ===================================================
           TOPBAR
        =================================================== */
        .topbar {
            position: fixed;
            top: 0;
            left: 250px;
            right: 0;
            height: 60px;
            background: #ffffff;
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.08);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 30px;
            z-index: 999;
        }

        .topbar-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .topbar-title {
            font-size: 16px;
            font-weight: 600;
            color: #1E293B;
        }

        .topbar-right {
            font-size: 13px;
            color: #94A3B8;
        }

        /* Hamburger — shown on mobile only */
        .hamburger {
            display: none;
            background: none;
            border: none;
            font-size: 22px;
            cursor: pointer;
            color: #1E293B;
            padding: 4px 6px;
            line-height: 1;
        }

        /* ===================================================
           MAIN CONTENT AREA
        =================================================== */
        .main-content {
            margin-left: 250px;
            padding: 90px 30px 40px; /* top offset accounts for 60px topbar */
            min-height: 100vh;
        }

        /* ===================================================
           FIRST LOGIN BANNER
           Shown only when user is on a temporary password
        =================================================== */
        .first-login-banner {
            display: flex;
            align-items: flex-start;
            gap: 14px;
            background: #FEF3C7;
            border: 1px solid #F59E0B;
            border-left: 4px solid #F59E0B;
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 26px;
        }

        .banner-icon {
            font-size: 20px;
            flex-shrink: 0;
            margin-top: 1px;
        }

        .banner-text strong {
            display: block;
            font-size: 14px;
            font-weight: 600;
            color: #92400E;
            margin-bottom: 3px;
        }

        .banner-text p {
            font-size: 13px;
            color: #78350F;
            margin: 0;
            line-height: 1.55;
        }

        /* ===================================================
           PAGE HEADER
        =================================================== */
        .page-title {
            font-size: 22px;
            font-weight: 700;
            color: #1E293B;
            margin-bottom: 4px;
        }

        .page-subtitle {
            font-size: 13px;
            color: #94A3B8;
            margin-bottom: 28px;
        }

        /* ===================================================
           PASSWORD CARD
        =================================================== */
        .password-card {
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
            max-width: 520px;
            overflow: hidden;
        }

        .password-card-header {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            padding: 22px 30px;
        }

        .password-card-header h2 {
            font-size: 18px;
            font-weight: 600;
            color: #ffffff;
            margin: 0;
        }

        .password-card-header p {
            font-size: 12px;
            color: rgba(255, 255, 255, 0.7);
            margin: 5px 0 0;
        }

        .password-card-body {
            padding: 28px 30px 32px;
        }

        /* ===================================================
           ALERTS
        =================================================== */
        .alert-custom {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 22px;
            font-size: 13px;
            line-height: 1.55;
        }

        .alert-icon {
            font-size: 15px;
            flex-shrink: 0;
            margin-top: 1px;
        }

        .alert-error {
            background: #FEE2E2;
            border: 1px solid #FECACA;
            color: #991B1B;
        }

        .alert-success {
            background: #DCFCE7;
            border: 1px solid #BBF7D0;
            color: #166534;
        }

        /* ===================================================
           FORM ELEMENTS
        =================================================== */
        .form-group {
            margin-bottom: 18px;
        }

        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: #1E293B;
            margin-bottom: 6px;
        }

        .form-control {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            color: #1E293B;
            background: #ffffff;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
            outline: none;
        }

        .form-control:focus {
            border-color: #2563EB;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
        }

        /* Password field + show/hide toggle wrapper */
        .password-wrapper {
            position: relative;
        }

        .password-wrapper .form-control {
            padding-right: 48px;
        }

        .toggle-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            font-size: 16px;
            padding: 4px;
            line-height: 1;
            color: #94A3B8;
        }

        .toggle-password:hover {
            color: #1E293B;
        }

        /* ===================================================
           SECTION DIVIDER
        =================================================== */
        .form-divider {
            border: none;
            border-top: 1px solid #E2E8F0;
            margin: 22px 0;
        }

        /* ===================================================
           PASSWORD RULES BOX
        =================================================== */
        .rules-box {
            background: #F8FAFC;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 14px 16px;
            margin-bottom: 18px;
        }

        .rules-title {
            font-size: 12px;
            font-weight: 600;
            color: #475569;
            margin-bottom: 8px;
        }

        .rules-list {
            list-style: none;
            padding: 0;
            margin: 0;
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .rules-list li {
            font-size: 12px;
            color: #EF4444;
            transition: color 0.2s ease;
        }

        /* ===================================================
           SUBMIT BUTTON
        =================================================== */
        .btn-submit {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s ease, transform 0.1s ease;
            margin-top: 6px;
        }

        .btn-submit:hover:not(:disabled) {
            opacity: 0.92;
            transform: translateY(-1px);
        }

        .btn-submit:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        /* ===================================================
           REDIRECT COUNTDOWN (success state)
        =================================================== */
        .redirect-notice {
            text-align: center;
            font-size: 13px;
            color: #475569;
            margin-top: 14px;
        }

        .redirect-notice strong {
            color: #2563EB;
            font-weight: 600;
        }

        /* ===================================================
           SIDEBAR OVERLAY (mobile tap-to-close)
        =================================================== */
        .sidebar-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.4);
            z-index: 999;
        }

        /* ===================================================
           RESPONSIVE
        =================================================== */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-250px);
                transition: transform 0.3s ease;
            }

            .sidebar.open {
                transform: translateX(0);
            }

            .sidebar-overlay.open {
                display: block;
            }

            .topbar {
                left: 0;
                padding: 0 16px;
            }

            .hamburger {
                display: block;
            }

            .main-content {
                margin-left: 0;
                padding: 80px 16px 30px;
            }

            .password-card {
                max-width: 100%;
            }

            .password-card-body {
                padding: 22px 20px 26px;
            }
        }
    </style>
</head>
<body>

    <!-- ========================================================
         SIDEBAR
         250px fixed left — gradient background
         Admin-only links hidden for non-admin roles
         nav-disabled applied when first_login is active
    ======================================================== -->
    <aside class="sidebar" id="sidebar">

        <!-- Brand -->
        <div class="sidebar-brand">
            <div class="sidebar-brand-name">🏥 MediVault</div>
            <div class="sidebar-tagline">Securing Patient Records. Protecting Lives.</div>
        </div>

        <!-- Navigation Links -->
        <nav class="sidebar-nav">

            <a href="dashboard.php"
               <?php if ($isFirstLogin): ?>
                   class="nav-disabled"
                   aria-disabled="true"
                   tabindex="-1"
                   title="Change your temporary password first"
               <?php endif; ?>>
                📊 Dashboard
            </a>

            <a href="patients.php"
               <?php if ($isFirstLogin): ?>
                   class="nav-disabled"
                   aria-disabled="true"
                   tabindex="-1"
                   title="Change your temporary password first"
               <?php endif; ?>>
                👤 Patients
            </a>

            <?php if ($isAdmin): ?>
            <a href="assets.php"
               <?php if ($isFirstLogin): ?>
                   class="nav-disabled"
                   aria-disabled="true"
                   tabindex="-1"
                   title="Change your temporary password first"
               <?php endif; ?>>
                🏗️ Assets
            </a>

            <a href="risks.php"
               <?php if ($isFirstLogin): ?>
                   class="nav-disabled"
                   aria-disabled="true"
                   tabindex="-1"
                   title="Change your temporary password first"
               <?php endif; ?>>
                ⚠️ Risks
            </a>
            <?php endif; ?>

            <a href="incidents.php"
               <?php if ($isFirstLogin): ?>
                   class="nav-disabled"
                   aria-disabled="true"
                   tabindex="-1"
                   title="Change your temporary password first"
               <?php endif; ?>>
                🚨 Incidents
            </a>

            <?php if ($isAdmin): ?>
            <a href="logs.php"
               <?php if ($isFirstLogin): ?>
                   class="nav-disabled"
                   aria-disabled="true"
                   tabindex="-1"
                   title="Change your temporary password first"
               <?php endif; ?>>
                📋 Logs
            </a>

            <a href="users.php"
               <?php if ($isFirstLogin): ?>
                   class="nav-disabled"
                   aria-disabled="true"
                   tabindex="-1"
                   title="Change your temporary password first"
               <?php endif; ?>>
                👥 Users
            </a>
            <?php endif; ?>

            <a href="policy.php"
               <?php if ($isFirstLogin): ?>
                   class="nav-disabled"
                   aria-disabled="true"
                   tabindex="-1"
                   title="Change your temporary password first"
               <?php endif; ?>>
                📄 Policy
            </a>

            <hr class="sidebar-divider">

            <!-- Active — current page. Always enabled regardless of first_login -->
            <a href="change_password.php" class="active">
                🔑 Change Password
            </a>

            <a href="logout.php">
                🚪 Logout
            </a>

        </nav>

        <!-- User Info at Bottom -->
        <div class="sidebar-user">
            <div class="sidebar-user-name">
                👋 <?= htmlspecialchars($userName, ENT_QUOTES, 'UTF-8') ?>
            </div>
            <div class="sidebar-user-role">
                <?= htmlspecialchars(ucfirst($userRole), ENT_QUOTES, 'UTF-8') ?>
            </div>
        </div>

    </aside>

    <!-- Sidebar overlay — mobile tap-outside-to-close -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>

    <!-- ========================================================
         TOPBAR
         60px fixed — white background with shadow
         Left offset = 250px (sidebar width) on desktop
    ======================================================== -->
    <header class="topbar">
        <div class="topbar-left">
            <button class="hamburger" id="hamburgerBtn" aria-label="Toggle navigation">
                ☰
            </button>
            <span class="topbar-title">🔑 Change Password</span>
        </div>
        <span class="topbar-right">
            <?= htmlspecialchars(date('D, M j, Y'), ENT_QUOTES, 'UTF-8') ?>
        </span>
    </header>

    <!-- ========================================================
         MAIN CONTENT
         margin-left 250px on desktop, 0 on mobile
         padding-top accounts for 60px fixed topbar
    ======================================================== -->
    <main class="main-content">

        <!-- ====================================================
             FIRST LOGIN WARNING BANNER
             Only shown when $_SESSION['first_login'] is set
             Explains why navigation links are disabled
        ==================================================== -->
        <?php if ($isFirstLogin): ?>
        <div class="first-login-banner">
            <span class="banner-icon">⚠️</span>
            <div class="banner-text">
                <strong>Action Required — Change Your Temporary Password</strong>
                <p>You are using a temporary password assigned by your administrator.
                   You must set a personal password before you can access any other part
                   of the system. Navigation is disabled until this step is completed.</p>
            </div>
        </div>
        <?php endif; ?>

        <!-- Page Header -->
        <h1 class="page-title">Change Password</h1>
        <p class="page-subtitle">Update your account password. All fields are required.</p>

        <!-- ====================================================
             PASSWORD CHANGE CARD
        ==================================================== -->
        <div class="password-card">

            <!-- Card Header -->
            <div class="password-card-header">
                <h2>🔐 Set New Password</h2>
                <p>New password must meet all security requirements listed below.</p>
            </div>

            <!-- Card Body -->
            <div class="password-card-body">

                <!-- ==========================================
                     ERROR / SUCCESS ALERTS
                ========================================== -->
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
                    <!-- 3-second countdown display -->
                    <div class="redirect-notice">
                        Redirecting to dashboard in <strong id="countdown">3</strong> seconds...
                    </div>
                <?php endif; ?>

                <!-- ==========================================
                     CHANGE PASSWORD FORM
                     Hidden after success — no re-submission possible
                ========================================== -->
                <?php if (!$success): ?>
                <form method="POST" action="change_password.php" id="changeForm" autocomplete="off" novalidate>

                    <!-- CSRF Token — required on every POST -->
                    <input type="hidden" name="csrf_token"
                           value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                    <!-- ======================================
                         CURRENT PASSWORD
                    ====================================== -->
                    <div class="form-group">
                        <label for="current_password" class="form-label">Current Password</label>
                        <div class="password-wrapper">
                            <input
                                type="password"
                                id="current_password"
                                name="current_password"
                                class="form-control"
                                placeholder="Enter your current password"
                                required
                                maxlength="255"
                                autocomplete="current-password"
                                autofocus
                            >
                            <button
                                type="button"
                                class="toggle-password"
                                id="toggleCurrent"
                                aria-label="Show or hide current password"
                                title="Show/hide password"
                            >👁</button>
                        </div>
                    </div>

                    <hr class="form-divider">

                    <!-- ======================================
                         NEW PASSWORD
                    ====================================== -->
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

                    <!-- ======================================
                         CONFIRM NEW PASSWORD
                    ====================================== -->
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
                        🔐 &nbsp;Update Password
                    </button>

                </form>
                <?php endif; ?>

            </div>
            <!-- End Card Body -->

        </div>
        <!-- End Password Card -->

    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ============================================================
        // HAMBURGER — mobile sidebar toggle
        // ============================================================
        const hamburgerBtn   = document.getElementById('hamburgerBtn');
        const sidebar        = document.getElementById('sidebar');
        const sidebarOverlay = document.getElementById('sidebarOverlay');

        function openSidebar()  {
            sidebar.classList.add('open');
            sidebarOverlay.classList.add('open');
        }

        function closeSidebar() {
            sidebar.classList.remove('open');
            sidebarOverlay.classList.remove('open');
        }

        hamburgerBtn.addEventListener('click', function () {
            sidebar.classList.contains('open') ? closeSidebar() : openSidebar();
        });

        sidebarOverlay.addEventListener('click', closeSidebar);

        // ============================================================
        // LIVE PASSWORD RULE CHECKER
        // Updates each rule item in real-time as user types
        // Rule element IDs match spec exactly:
        //   rule-length, rule-uppercase, rule-lowercase,
        //   rule-number, rule-special
        // Returns true only when all 5 rules pass
        // ============================================================
        function checkPassword(password) {
            const rules = {
                length: {
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
                    el.style.color = rules[key].test ? '#22C55E' : '#EF4444';
                    el.textContent = (rules[key].test ? '✅ ' : '❌ ') + rules[key].text;
                }
            });

            // Return true only when every rule passes
            return Object.values(rules).every(r => r.test);
        }

        // ============================================================
        // PASSWORD FIELD LISTENER
        // Fires checkPassword on every keystroke in new_password field
        // ============================================================
        const newPasswordInput = document.getElementById('new_password');

        if (newPasswordInput) {
            newPasswordInput.addEventListener('input', function () {
                checkPassword(this.value);
            });
        }

        // ============================================================
        // PASSWORD SHOW / HIDE TOGGLES
        // Three separate toggles: current, new, confirm
        // Reusable setupToggle() helper — same pattern as reset_password.php
        // ============================================================
        function setupToggle(buttonId, inputId) {
            const btn   = document.getElementById(buttonId);
            const input = document.getElementById(inputId);
            if (!btn || !input) return;

            let visible = false;
            btn.addEventListener('click', function () {
                visible         = !visible;
                input.type      = visible ? 'text' : 'password';
                btn.textContent = visible ? '🙈' : '👁';
            });
        }

        setupToggle('toggleCurrent', 'current_password');
        setupToggle('toggleNew',     'new_password');
        setupToggle('toggleConfirm', 'confirm_password');

        // ============================================================
        // PREVENT DOUBLE SUBMIT
        // Blocks submit entirely if new password rules are not passing
        // Disables button on valid submit to prevent resubmission
        // ============================================================
        const changeForm = document.getElementById('changeForm');
        const submitBtn  = document.getElementById('submitBtn');

        if (changeForm && submitBtn) {
            changeForm.addEventListener('submit', function (e) {
                const current = document.getElementById('current_password').value;
                const pw      = document.getElementById('new_password').value;
                const confirm = document.getElementById('confirm_password').value;

                // Let browser handle empty field validation
                if (!current || !pw || !confirm) return;

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

        // ============================================================
        // 3-SECOND COUNTDOWN REDIRECT ON SUCCESS
        // Counts down from 3 then navigates to dashboard.php
        // Only runs when PHP sets $redirectJs = true (success state)
        // ============================================================
        <?php if ($redirectJs): ?>
        let countdownSecs  = 3;
        const countdownEl  = document.getElementById('countdown');

        const redirectTimer = setInterval(function () {
            countdownSecs--;
            if (countdownEl) countdownEl.textContent = countdownSecs;

            if (countdownSecs <= 0) {
                clearInterval(redirectTimer);
                window.location.href = 'dashboard.php';
            }
        }, 1000);
        <?php endif; ?>

        // ============================================================
        // SESSION TIMEOUT WARNING
        // At 9 minutes (540s) — alert warning shown
        // At 10 minutes (600s) — auto redirect to login
        // Applied on every protected page per spec
        // ============================================================
        setTimeout(function () {
            alert(
                '⚠️ Warning: Your session will expire in 1 minute due to inactivity.\n' +
                'Please save your work.'
            );
        }, 540000);

        setTimeout(function () {
            window.location.href = 'index.php?msg=session_expired';
        }, 600000);
    </script>

</body>
</html>