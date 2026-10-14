<?php
// ============================================================
// MEDIVAULT — includes/auth.php
// Purpose:  Session validation, role enforcement, CSRF,
//           security headers, IP check, timeout handling
// Rules:    Always included AFTER db.php on protected pages
//           Always called with requireRole() immediately after
//           Never rely on hiding links alone — always block server-side
// ============================================================

// ============================================================
// SECURITY HEADERS
// Applied on every protected page load via this file
// ============================================================
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// ============================================================
// SESSION TIMEOUT CHECK
// Idle timeout: 10 minutes (600 seconds)
// Logs the expiry, destroys session, redirects to login
// Must run before any role check
// ============================================================
$timeout = 600;

if (isset($_SESSION['user_id'])) {
    if (isset($_SESSION['last_activity'])) {
        if (time() - $_SESSION['last_activity'] > $timeout) {

            // Log the timeout before destroying session
            // $conn is available — db.php always included first
            $expired_user_id = $_SESSION['user_id'];
            $expired_ip      = getUserIP();
            $expired_action  = "Session expired due to inactivity";

            $stmt = $conn->prepare(
                "INSERT INTO activity_logs (user_id, action, ip_address)
                 VALUES (?, ?, ?)"
            );
            $stmt->bind_param("iss", $expired_user_id, $expired_action, $expired_ip);
            $stmt->execute();
            $stmt->close();

            // Destroy session and redirect
            session_unset();
            session_destroy();
            header('Location: index.php?msg=session_expired');
            exit;
        }
    }

    // Refresh last activity timestamp on every page load
    $_SESSION['last_activity'] = time();
}

// ============================================================
// SESSION IP CHECK
// Compares current request IP vs IP recorded at login
// Flags mismatch as suspicious — possible session hijack
// Sends admin alert if sendSuspiciousAlert() is available
// (mailer.php must be included on the page for alert to fire)
// ============================================================
if (isset($_SESSION['user_id'], $_SESSION['ip_address'])) {
    $currentIP = getUserIP();

    if ($_SESSION['ip_address'] !== $currentIP) {
        $mismatch_user_id = $_SESSION['user_id'];
        $mismatch_action  = "Session IP mismatch detected";
        $mismatch_reason  = "Login IP: " . $_SESSION['ip_address'] .
                            " | Current IP: " . $currentIP;

        // Log as suspicious
        logSuspicious(
            $conn,
            $mismatch_user_id,
            $mismatch_action,
            $currentIP,
            $mismatch_reason
        );

        // Alert admin if mailer is loaded on this page
        if (function_exists('sendSuspiciousAlert')) {
            $adminEmail = getAdminEmail($conn);
            if ($adminEmail) {
                sendSuspiciousAlert(
                    $adminEmail,
                    $_SESSION['user_name'] ?? 'Unknown',
                    $mismatch_action,
                    $currentIP,
                    date('Y-m-d H:i:s')
                );
            }
        }
    }
}

// ============================================================
// CSRF TOKEN GENERATION
// Token generated once per session and stored in $_SESSION
// All forms must include this token as a hidden field:
//   <input type="hidden" name="csrf_token"
//          value="<?= $_SESSION['csrf_token'] ? >">
// Validate on every POST with verifyCsrf() below
// Token is regenerated after each successful POST validation
// ============================================================
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ============================================================
// CSRF VERIFICATION HELPER
// Call at top of any POST handler block
// Usage:
//   if ($_SERVER['REQUEST_METHOD'] === 'POST') {
//       verifyCsrf();
//       // ... rest of POST logic
//   }
// ============================================================
function verifyCsrf() {
    if (
        !isset($_POST['csrf_token']) ||
        !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        // Log attempt if user is known
        // Terminate immediately — never process a forged request
        http_response_code(403);
        die("
        <div style='font-family:Arial; text-align:center; padding:50px;'>
            <h2 style='color:#EF4444;'>Invalid Request</h2>
            <p style='color:#475569;'>CSRF token mismatch. 
            Please go back and try again.</p>
            <a href='javascript:history.back()' 
               style='color:#2563EB;'>Go Back</a>
        </div>
        ");
    }

    // Regenerate token after each valid use
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ============================================================
// REQUIRE ROLE — Core Access Control Function
// Usage:
//   requireRole(['admin']);
//   requireRole(['admin','doctor']);
//   requireRole(['admin','doctor','nurse','receptionist']);
//
// Behavior:
//   1. Check session exists — redirect to login if not
//   2. Check role is in allowed array — block if not
//   3. Log unauthorized attempt as suspicious
//   4. Always exit after redirect
// ============================================================
function requireRole($allowedRoles) {
    global $conn;

    // --------------------------------------------------------
    // Step 1 — Check if user is logged in at all
    // --------------------------------------------------------
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_role'])) {
        header('Location: index.php?msg=login_required');
        exit;
    }

    // --------------------------------------------------------
    // Step 2 — Check role is permitted for this page
    // --------------------------------------------------------
    if (!in_array($_SESSION['user_role'], $allowedRoles)) {

        // Identify the page being accessed for the log entry
        $attempted_page = basename($_SERVER['PHP_SELF']);
        $ip             = getUserIP();
        $user_id        = $_SESSION['user_id'];
        $action         = "Unauthorized access attempt to " . $attempted_page;
        $reason         = "Role '" . $_SESSION['user_role'] .
                          "' attempted to access " . $attempted_page .
                          " (allowed: " . implode(', ', $allowedRoles) . ")";

        // Log as suspicious — shows highlighted red in logs.php
        logSuspicious($conn, $user_id, $action, $ip, $reason);

        // Alert admin if mailer is loaded on this page
        if (function_exists('sendSuspiciousAlert')) {
            $adminEmail = getAdminEmail($conn);
            if ($adminEmail) {
                sendSuspiciousAlert(
                    $adminEmail,
                    $_SESSION['user_name'] ?? 'Unknown',
                    $action,
                    $ip,
                    date('Y-m-d H:i:s')
                );
            }
        }

        // Redirect and stop execution — never let page load
        header('Location: index.php?msg=unauthorized');
        exit;
    }

    // --------------------------------------------------------
    // Step 3 — Enforce first_login password change
    // If first_login = 1, only allow change_password.php
    // and logout.php — block everything else
    // --------------------------------------------------------
    if (!empty($_SESSION['first_login'])) {
        $current_page = basename($_SERVER['PHP_SELF']);
        $free_pages   = ['change_password.php', 'logout.php'];

        if (!in_array($current_page, $free_pages)) {
            header('Location: change_password.php?msg=must_change_password');
            exit;
        }
    }
}
