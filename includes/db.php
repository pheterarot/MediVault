<?php
// ============================================================
// MEDIVAULT — includes/db.php
// Purpose:  Database connection + core helper functions
// Rules:    No session_start(), no HTML, no page logic
//           Just $conn and helper functions
//           Every page includes this file first
// ============================================================

// ============================================================
// ERROR DISPLAY — off in production, never show PHP errors
// Uncomment the dev lines below only during local debugging
// ============================================================
ini_set('display_errors', 0);
error_reporting(0);

// -- Dev only (remove before demo) --------------------------
// ini_set('display_errors', 1);
// error_reporting(E_ALL);
// -----------------------------------------------------------

// ============================================================
// DATABASE CONNECTION
// One codebase, three environments — settings are chosen in this order:
//
//   1. Defaults          → XAMPP localhost (root, no password)
//   2. Environment vars  → Docker (DB_HOST, DB_NAME, DB_USER, DB_PASS)
//   3. config.production.php (optional, same folder, NOT in Git)
//                        → InfinityFree credentials; overrides the above
//
// To deploy on InfinityFree: upload includes/config.production.php
// containing your real credentials (see config.production.example.php).
// Never commit real credentials to GitHub.
// ============================================================
$host     = 'localhost';
$dbname   = 'medivault';
$username = 'root';
$password = '';

// Docker / environment variables
if (getenv('DB_HOST') !== false) { $host     = getenv('DB_HOST'); }
if (getenv('DB_NAME') !== false) { $dbname   = getenv('DB_NAME'); }
if (getenv('DB_USER') !== false) { $username = getenv('DB_USER'); }
if (getenv('DB_PASS') !== false) { $password = getenv('DB_PASS'); }

// InfinityFree (or any production host) — optional override file
if (file_exists(__DIR__ . '/config.production.php')) {
    require __DIR__ . '/config.production.php';
}

// PHP 8.1+ throws an exception on connection failure instead of
// setting connect_error — catch it so the friendly message shows
// instead of a blank page.
try {
    $conn = new mysqli($host, $username, $password, $dbname);
} catch (mysqli_sql_exception $e) {
    $conn = null;
}

if (!$conn || $conn->connect_error) {
    die("
    <div style='font-family:Arial; text-align:center; padding:50px;'>
        <h2 style='color:#EF4444;'>Database Connection Failed</h2>
        <p style='color:#475569;'>Please contact the system administrator.</p>
    </div>
    ");
}

$conn->set_charset('utf8mb4');

// ============================================================
// HELPER FUNCTION 1 — clean()
// Purpose:  Sanitize ALL user input before use or display
//           Prevents XSS — never echo raw user input
// Usage:    $name = clean($_POST['name']);
// ============================================================
function clean($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// ============================================================
// HELPER FUNCTION 2 — getUserIP()
// Purpose:  Get the current visitor's IP address
//           Single source of truth — always call this,
//           never access $_SERVER['REMOTE_ADDR'] directly
// Usage:    $ip = getUserIP();
// ============================================================
function getUserIP() {
    return $_SERVER['REMOTE_ADDR'];
}

// ============================================================
// HELPER FUNCTION 3 — logActivity()
// Purpose:  Log a normal (non-suspicious) action to activity_logs
//           Every significant action in the system must be logged
// Usage:    logActivity($conn, $userId, "Login successful", $ip);
// ============================================================
function logActivity($conn, $userId, $action, $ip) {
    $stmt = $conn->prepare(
        "INSERT INTO activity_logs (user_id, action, ip_address)
         VALUES (?, ?, ?)"
    );
    $stmt->bind_param("iss", $userId, $action, $ip);
    $stmt->execute();
    $stmt->close();
}

// ============================================================
// HELPER FUNCTION 4 — logSuspicious()
// Purpose:  Log a flagged suspicious event to activity_logs
//           Sets is_suspicious = 1 and records the reason
//           Used by: brute force, IP mismatch, rapid access,
//           unusual hours, unauthorized page access
// Usage:    logSuspicious($conn, $userId, "Rapid access", $ip, "10 records in 60s");
// ============================================================
function logSuspicious($conn, $userId, $action, $ip, $reason) {
    $stmt = $conn->prepare(
        "INSERT INTO activity_logs
         (user_id, action, ip_address, is_suspicious, flagged_reason)
         VALUES (?, ?, ?, 1, ?)"
    );
    $stmt->bind_param("isss", $userId, $action, $ip, $reason);
    $stmt->execute();
    $stmt->close();
}

// ============================================================
// HELPER FUNCTION 5 — getAdminEmail()
// Purpose:  Retrieve the first admin's email address
//           Used when sending admin alert emails:
//           sendIncidentAlert(), sendSuspiciousAlert()
// Usage:    $adminEmail = getAdminEmail($conn);
// ============================================================
function getAdminEmail($conn) {
    $stmt = $conn->prepare(
        "SELECT email FROM users WHERE role = 'admin' LIMIT 1"
    );
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $result['email'] ?? null;
}

function sanitizeForDb($input) {
    return trim($input);
}