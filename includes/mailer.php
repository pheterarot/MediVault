<?php
// ============================================================
// MEDIVAULT — includes/mailer.php
// Purpose:  All email sending functions — never call PHPMailer
//           directly from page files, always use these functions
// Requires: PHPMailer files in /src/ at project root
// Rules:    All functions return true on success, false on fail
//           Email failure never breaks main page flow
//           Always wrap sends in try/catch
//           Always set AltBody plain text fallback
// ============================================================

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// PHPMailer paths relative to /includes/ — go up one level to root
require dirname(__DIR__) . '/src/Exception.php';
require dirname(__DIR__) . '/src/PHPMailer.php';
require dirname(__DIR__) . '/src/SMTP.php';

// ============================================================
// SITE URL — used to build links inside emails
// Auto-detects protocol, host, AND subfolder at runtime.
// dirname(SCRIPT_NAME) gives the folder of the calling script
// (mailer.php is always included, so SCRIPT_NAME = caller).
// Root deploy  → SCRIPT_NAME='/index.php'      → SITE_URL='https://domain.com/'
// Subfolder    → SCRIPT_NAME='/app/index.php'  → SITE_URL='https://domain.com/app/'
// No hardcoded path — works on InfinityFree and any host.
// ============================================================
$protocol  = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
$host      = $_SERVER['HTTP_HOST'];
$scriptDir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
define('SITE_URL', "$protocol://$host$scriptDir/");

// ============================================================
// EMAIL BRAND BUILDER — buildEmail()
// Internal helper — wraps any body content in the
// standard MediVault branded header and footer
// Every email uses the exact same header and footer per spec
// ============================================================
function buildEmail($bodyContent) {
    return "
    <div style='max-width:560px; margin:40px auto;
    font-family:Arial,sans-serif; background:#ffffff;
    border-radius:12px; overflow:hidden;
    box-shadow:0 4px 12px rgba(0,0,0,0.08);'>

        <div style='background:linear-gradient(135deg,#1E40AF,#2563EB);
        padding:30px; text-align:center;'>
            <h1 style='color:#ffffff; margin:0;
            font-size:26px; letter-spacing:2px;'>
            &#127973; MediVault</h1>
            <p style='color:#BAE6FD; margin:5px 0 0;
            font-size:12px;'>
            Securing Patient Records. Protecting Lives.</p>
        </div>

        <div style='padding:35px 40px;'>
            {$bodyContent}
        </div>

        <div style='background:#F1F5F9; padding:20px 40px;
        text-align:center;'>
            <p style='color:#94A3B8; font-size:12px; margin:0;'>
            MediVault Security System &copy; 2025</p>
            <p style='color:#CBD5E1; font-size:11px;
            margin:5px 0 0;'>
            This is an automated message. Do not reply.</p>
        </div>

    </div>
    ";
}

// ============================================================
// MAILER FACTORY — getMailer()
// Returns a fully configured PHPMailer instance
// All email functions call this — never configure SMTP inline
// SMTP credentials come from environment variables or
//            includes/config.production.php (not committed to Git)
//            setFrom MUST stay as silvestrearot@gmail.com
//            (verified sender in Brevo — any other = silent fail)
// ============================================================
function getMailer() {
    // Settings order: Docker env vars -> config.production.php constants -> Brevo host
    // Credentials are NEVER hardcoded here (this file goes to GitHub).
    $smtpHost = getenv('SMTP_HOST') ?: (defined('SMTP_HOST') ? SMTP_HOST : 'smtp-relay.brevo.com');
    $smtpPort = (int)(getenv('SMTP_PORT') ?: (defined('SMTP_PORT') ? SMTP_PORT : 587));
    $smtpUser = getenv('SMTP_USER') ?: (defined('SMTP_USER') ? SMTP_USER : '');
    $smtpPass = getenv('SMTP_PASS') ?: (defined('SMTP_PASS') ? SMTP_PASS : '');

    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = $smtpHost;
    $mail->Port = $smtpPort;

    if ($smtpUser !== '') {
        // Real SMTP (Brevo) — authenticated + STARTTLS
        $mail->SMTPAuth   = true;
        $mail->Username   = $smtpUser;
        $mail->Password   = $smtpPass;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    } else {
        // Local mail catcher (Mailpit in Docker) — no auth, no TLS
        $mail->SMTPAuth    = false;
        $mail->SMTPSecure  = '';
        $mail->SMTPAutoTLS = false;
    }

    $mail->setFrom('silvestrearot@gmail.com', 'MediVault Security');
    $mail->isHTML(true);
    return $mail;
}

// ============================================================
// EMAIL 1 — sendOTP()
// Trigger:    User submits correct email + password on login
// Recipient:  The logging-in user
// ============================================================
function sendOTP($email, $otp, $name) {
    try {
        $mail = getMailer();
        $mail->addAddress($email, $name);
        $mail->Subject = 'MediVault — Your One-Time Password';

        $body = "
        <h2 style='color:#1E293B; font-size:20px; margin-top:0;'>
        Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . " &#128075;</h2>
        <p style='color:#475569; font-size:15px;'>
        Use the OTP below to complete your login.
        Do not share this code with anyone.</p>

        <div style='background:#EFF6FF;
        border:2px dashed #2563EB;
        border-radius:10px; padding:25px;
        text-align:center; margin:25px 0;'>
            <span style='font-size:40px; font-weight:bold;
            color:#1E40AF; letter-spacing:10px;'>
            " . htmlspecialchars($otp, ENT_QUOTES, 'UTF-8') . "</span>
        </div>

        <p style='color:#94A3B8; font-size:13px;'>
        &#9201; Expires in <strong>5 minutes</strong>.</p>
        <p style='color:#94A3B8; font-size:13px;'>
        If you did not request this OTP,
        please contact your administrator immediately.</p>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "Hello {$name}, your MediVault OTP is: {$otp}. It expires in 5 minutes. Do not share this code.";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// EMAIL 2 — sendWelcome()
// Trigger:    Admin creates a new user account
// Recipient:  The newly created user
// ============================================================
function sendWelcome($email, $name, $role, $tempPassword) {
    try {
        $mail = getMailer();
        $mail->addAddress($email, $name);
        $mail->Subject = 'MediVault — Your Account Has Been Created';

        $loginUrl = SITE_URL . 'index.php?relogin=1';

        // Credentials are split into two separate styled boxes to avoid
        // spam filter flags — sending email + password together in one
        // block triggers phishing detection on Brevo and most relays.
        $body = "
        <h2 style='color:#1E293B; font-size:20px; margin-top:0;'>
        Welcome to MediVault, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "! &#127973;</h2>
        <p style='color:#475569; font-size:15px;'>
        Your account has been created by the administrator.
        Below are your login details — keep them safe.</p>

        <div style='background:#F8FAFC;
        border-left:4px solid #2563EB;
        border-radius:8px; padding:20px; margin:20px 0;'>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Login:</strong> " . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Role:</strong> " . htmlspecialchars(ucfirst($role), ENT_QUOTES, 'UTF-8') . "</p>
        </div>

        <p style='color:#475569; font-size:14px; margin:0 0 8px;'>
        Your temporary access code:</p>
        <div style='background:#EFF6FF;
        border:2px dashed #2563EB;
        border-radius:10px; padding:18px 24px;
        text-align:center; margin-bottom:20px;'>
            <span style='font-size:22px; font-weight:700;
            color:#1E40AF; letter-spacing:3px; font-family:monospace;'>
            " . htmlspecialchars($tempPassword, ENT_QUOTES, 'UTF-8') . "
            </span>
        </div>

        <div style='background:#FEF3C7;
        border-radius:8px; padding:15px; margin:20px 0;'>
            <p style='color:#92400E; margin:0; font-size:13px;'>
            &#9888;&#65039; You will be required to change this on first login.
            Do not share your access details with anyone.</p>
        </div>

        <a href='{$loginUrl}'
        style='display:inline-block; background:#2563EB;
        color:#ffffff; padding:12px 30px;
        border-radius:8px; text-decoration:none;
        font-weight:600; margin-top:10px;'>
        Login to MediVault</a>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "Welcome to MediVault, {$name}! Your login: {$email} | Role: {$role} | Temporary access code: {$tempPassword}. You must change this on first login. Login at: {$loginUrl}";
        $mail->send();
        return true;

    } catch (Exception $e) {
        error_log('[MediVault] sendWelcome failed for ' . $email . ': ' . $e->getMessage());
        return false;
    }
}

// ============================================================
// EMAIL 3 — sendLoginNotif()
// Trigger:    Successful OTP verification — user fully logged in
// Recipient:  The logged-in user
// ============================================================

// ============================================================
// LOCATION HELPER — getLocationFromIP()
// Calls ip-api.com (free, no key needed) to get city/region/country
// Falls back gracefully if blocked or unavailable
// Localhost IPs return a dev-friendly label instead of failing
// ============================================================
function getLocationFromIP($ip) {
    // Localhost — no real location available
    if ($ip === '127.0.0.1' || $ip === '::1' || strpos($ip, '192.168.') === 0 || strpos($ip, '10.') === 0) {
        return 'Local / Development environment';
    }

    try {
        $url      = "http://ip-api.com/json/" . urlencode($ip) . "?fields=status,city,regionName,country";
        $response = @file_get_contents($url);

        if ($response === false) {
            return 'Location unavailable';
        }

        $data = json_decode($response, true);

        if (isset($data['status']) && $data['status'] === 'success') {
            $parts = array_filter([
                $data['city']       ?? '',
                $data['regionName'] ?? '',
                $data['country']    ?? '',
            ]);
            return implode(', ', $parts) ?: 'Location unavailable';
        }

        return 'Location unavailable';

    } catch (Exception $e) {
        return 'Location unavailable';
    }
}

function sendLoginNotif($email, $name, $ip, $browser, $time) {
    try {
        $mail     = getMailer();
        $location = getLocationFromIP($ip);
        $mail->addAddress($email, $name);
        $mail->Subject = 'MediVault — New Login Detected on Your Account';

        $body = "
        <h2 style='color:#1E293B; font-size:20px; margin-top:0;'>
        New Login Detected &#128272;</h2>
        <p style='color:#475569; font-size:15px;'>
        A new login was detected on your MediVault account.
        Here are the details:</p>

        <div style='background:#F8FAFC;
        border-left:4px solid #2563EB;
        border-radius:8px; padding:20px; margin:20px 0;'>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Date &amp; Time:</strong> " . htmlspecialchars($time, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>IP Address:</strong> " . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Location:</strong> " . htmlspecialchars($location, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Browser/Device:</strong> " . htmlspecialchars($browser, ENT_QUOTES, 'UTF-8') . "</p>
        </div>

        <div style='background:#DCFCE7;
        border-radius:8px; padding:15px; margin:10px 0;'>
            <p style='color:#166534; margin:0; font-size:13px;'>
            &#9989; If this was you, no action is needed.</p>
        </div>

        <div style='background:#FEE2E2;
        border-radius:8px; padding:15px; margin:10px 0;'>
            <p style='color:#991B1B; margin:0; font-size:13px;'>
            &#128680; If this was NOT you, contact your administrator
            immediately to lock your account.</p>
        </div>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "MediVault Login Alert for {$name}: Time: {$time} | IP: {$ip} | Location: {$location} | Device: {$browser}. If this was not you, contact your administrator immediately.";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// EMAIL 4 — sendAccountLocked()
// Trigger:    Failed login attempts reach 5
// Recipient:  The locked-out user
// ============================================================
function sendAccountLocked($email, $name, $ip) {
    try {
        $mail = getMailer();
        $mail->addAddress($email, $name);
        $mail->Subject = 'MediVault — Your Account Has Been Locked';

        $time = date('Y-m-d H:i:s');

        $body = "
        <h2 style='color:#EF4444; font-size:20px; margin-top:0;'>
        &#128274; Account Locked</h2>
        <p style='color:#475569; font-size:15px;'>
        Your MediVault account has been locked due to
        5 consecutive failed login attempts.</p>

        <div style='background:#FEE2E2;
        border-left:4px solid #EF4444;
        border-radius:8px; padding:20px; margin:20px 0;'>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Time:</strong> " . htmlspecialchars($time, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>IP Address:</strong> " . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') . "</p>
        </div>

        <p style='color:#475569; font-size:14px;'>
        To unlock your account you can:</p>
        <p style='color:#475569; font-size:14px;'>
        &rarr; Use Forgot Password to reset and unlock<br>
        &rarr; Contact your system administrator</p>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "MediVault Account Locked for {$name}: Your account was locked after 5 failed login attempts at {$time} from IP {$ip}. Use Forgot Password or contact your administrator to unlock.";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// EMAIL 4B — sendAccountLockedByAdmin()
// Trigger:    Admin manually locks a user account via users.php
// Recipient:  The locked user
// Note:       Different from sendAccountLocked() — this is NOT
//             triggered by failed attempts. No IP shown since
//             it was an administrative action, not an intrusion.
// ============================================================
function sendAccountLockedByAdmin($email, $name) {
    try {
        $mail = getMailer();
        $mail->addAddress($email, $name);
        $mail->Subject = 'MediVault — Your Account Has Been Locked';

        $time = date('Y-m-d H:i:s');

        $body = "
        <h2 style='color:#EF4444; font-size:20px; margin-top:0;'>
        &#128274; Account Locked by Administrator</h2>
        <p style='color:#475569; font-size:15px;'>
        Your MediVault account has been locked by
        the system administrator.</p>

        <div style='background:#FEE2E2;
        border-left:4px solid #EF4444;
        border-radius:8px; padding:20px; margin:20px 0;'>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Time:</strong> " . htmlspecialchars($time, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Locked By:</strong> System Administrator</p>
        </div>

        <div style='background:#FEF3C7;
        border-radius:8px; padding:15px; margin:20px 0;'>
            <p style='color:#92400E; margin:0; font-size:13px;'>
            &#9888;&#65039; This action was performed by an administrator.
            You will not be able to login until your account
            is unlocked. Please contact your administrator
            for assistance.</p>
        </div>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "MediVault Account Locked for {$name}: Your account was locked by the system administrator at {$time}. You cannot login until it is unlocked. Please contact your administrator for assistance.";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// EMAIL 5 — sendAccountUnlocked()
// Trigger:    Admin unlocks account via users.php
// Recipient:  The unlocked user
// ============================================================
function sendAccountUnlocked($email, $name) {
    try {
        $mail = getMailer();
        $mail->addAddress($email, $name);
        $mail->Subject = 'MediVault — Your Account Has Been Unlocked';

        $loginUrl = SITE_URL . 'index.php?relogin=1';

        $body = "
        <h2 style='color:#22C55E; font-size:20px; margin-top:0;'>
        &#9989; Account Unlocked</h2>
        <p style='color:#475569; font-size:15px;'>
        Your MediVault account has been unlocked
        by the administrator. You can now login again.</p>

        <div style='background:#DCFCE7;
        border-left:4px solid #22C55E;
        border-radius:8px; padding:15px; margin:20px 0;'>
            <p style='color:#166534; margin:0; font-size:13px;'>
            For your security, please use a strong password
            and do not share your credentials with anyone.</p>
        </div>

        <a href='{$loginUrl}'
        style='display:inline-block; background:#2563EB;
        color:#ffffff; padding:12px 30px;
        border-radius:8px; text-decoration:none;
        font-weight:600; margin-top:10px;'>
        Login to MediVault</a>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "MediVault Account Unlocked for {$name}: Your account has been unlocked by the administrator. You can now login at: {$loginUrl}";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// EMAIL 6 — sendPasswordReset()
// Trigger:    User submits forgot password form
// Recipient:  The requesting user
// Note:       $resetLink is the full URL already built by
//             forgot_password.php — passed in complete
// ============================================================
function sendPasswordReset($email, $name, $resetLink) {
    try {
        $mail = getMailer();
        $mail->addAddress($email, $name);
        $mail->Subject = 'MediVault — Password Reset Request';

        $body = "
        <h2 style='color:#1E293B; font-size:20px; margin-top:0;'>
        Password Reset Request &#128273;</h2>
        <p style='color:#475569; font-size:15px;'>
        We received a request to reset your MediVault
        password. Click the button below to proceed.
        This link expires in <strong>15 minutes</strong>
        and can only be used once.</p>

        <div style='text-align:center; margin:30px 0;'>
        <a href='" . htmlspecialchars($resetLink, ENT_QUOTES, 'UTF-8') . "'
        style='display:inline-block; background:#2563EB;
        color:#ffffff; padding:14px 35px;
        border-radius:8px; text-decoration:none;
        font-weight:600; font-size:15px;'>
        Reset My Password</a>
        </div>

        <div style='background:#FEF3C7;
        border-radius:8px; padding:15px; margin:20px 0;'>
            <p style='color:#92400E; margin:0; font-size:13px;'>
            &#9888;&#65039; If you did not request this,
            ignore this email. Your password will
            not be changed.</p>
        </div>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "MediVault Password Reset for {$name}: Click this link to reset your password (expires in 15 minutes, one-time use only): {$resetLink}. If you did not request this, ignore this email.";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// EMAIL 7 — sendPasswordChanged()
// Trigger:    User successfully changes password
//             (via change_password.php or reset_password.php)
// Recipient:  The user whose password changed
// ============================================================
function sendPasswordChanged($email, $name, $ip, $time) {
    try {
        $mail = getMailer();
        $mail->addAddress($email, $name);
        $mail->Subject = 'MediVault — Your Password Has Been Changed';

        $body = "
        <h2 style='color:#1E293B; font-size:20px; margin-top:0;'>
        Password Changed Successfully &#9989;</h2>
        <p style='color:#475569; font-size:15px;'>
        Your MediVault password was successfully changed.</p>

        <div style='background:#F8FAFC;
        border-left:4px solid #2563EB;
        border-radius:8px; padding:20px; margin:20px 0;'>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Time:</strong> " . htmlspecialchars($time, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>IP Address:</strong> " . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') . "</p>
        </div>

        <div style='background:#FEE2E2;
        border-radius:8px; padding:15px; margin:10px 0;'>
            <p style='color:#991B1B; margin:0; font-size:13px;'>
            &#128680; If you did not make this change,
            contact your administrator immediately.</p>
        </div>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "MediVault Password Changed for {$name}: Your password was changed at {$time} from IP {$ip}. If you did not make this change, contact your administrator immediately.";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// EMAIL 8 — sendIncidentAlert()
// Trigger:    Any user reports a new incident via incidents.php
// Recipient:  Admin email (fetched via getAdminEmail())
// ============================================================
function sendIncidentAlert($adminEmail, $reporterName, $title, $priority) {
    try {
        $mail = getMailer();
        $mail->addAddress($adminEmail);
        $mail->Subject = 'MediVault — New Incident Reported';

        $incidentsUrl = SITE_URL . 'incidents.php';
        $time         = date('Y-m-d H:i:s');

        $body = "
        <h2 style='color:#EF4444; font-size:20px; margin-top:0;'>
        &#128680; New Incident Reported</h2>
        <p style='color:#475569; font-size:15px;'>
        A new security incident has been reported
        and requires your attention.</p>

        <div style='background:#FEE2E2;
        border-left:4px solid #EF4444;
        border-radius:8px; padding:20px; margin:20px 0;'>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Title:</strong> " . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Reported By:</strong> " . htmlspecialchars($reporterName, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Priority:</strong> " . htmlspecialchars($priority, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Time:</strong> " . htmlspecialchars($time, ENT_QUOTES, 'UTF-8') . "</p>
        </div>

        <a href='{$incidentsUrl}'
        style='display:inline-block; background:#EF4444;
        color:#ffffff; padding:12px 30px;
        border-radius:8px; text-decoration:none;
        font-weight:600; margin-top:10px;'>
        View Incident</a>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "MediVault Incident Alert: New incident reported by {$reporterName}. Title: {$title} | Priority: {$priority} | Time: {$time}. View at: {$incidentsUrl}";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// EMAIL 9 — sendSuspiciousAlert()
// Trigger:    System detects suspicious activity
//             (rapid access, IP mismatch, unusual hours,
//              unauthorized page attempt, brute force)
// Recipient:  Admin email (fetched via getAdminEmail())
// ============================================================
function sendSuspiciousAlert($adminEmail, $suspiciousUser, $reason, $ip, $time) {
    try {
        $mail = getMailer();
        $mail->addAddress($adminEmail);
        $mail->Subject = 'MediVault — ⚠️ Suspicious Activity Detected';

        $logsUrl = SITE_URL . 'logs.php';

        $body = "
        <h2 style='color:#EF4444; font-size:20px; margin-top:0;'>
        &#9888;&#65039; Suspicious Activity Detected</h2>
        <p style='color:#475569; font-size:15px;'>
        The system has detected suspicious activity
        that requires your immediate attention.</p>

        <div style='background:#FEE2E2;
        border-left:4px solid #EF4444;
        border-radius:8px; padding:20px; margin:20px 0;'>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>User:</strong> " . htmlspecialchars($suspiciousUser, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Reason:</strong> " . htmlspecialchars($reason, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>IP Address:</strong> " . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') . "</p>
            <p style='margin:5px 0; color:#1E293B;'>
            <strong>Time:</strong> " . htmlspecialchars($time, ENT_QUOTES, 'UTF-8') . "</p>
        </div>

        <p style='color:#475569; font-size:14px;'>
        Recommended actions:<br>
        &rarr; Review activity logs immediately<br>
        &rarr; Lock account if necessary<br>
        &rarr; Investigate the flagged activity</p>

        <a href='{$logsUrl}'
        style='display:inline-block; background:#EF4444;
        color:#ffffff; padding:12px 30px;
        border-radius:8px; text-decoration:none;
        font-weight:600; margin-top:10px;'>
        View Activity Logs</a>
        ";

        $mail->Body    = buildEmail($body);
        $mail->AltBody = "MediVault Suspicious Activity Alert: User: {$suspiciousUser} | Reason: {$reason} | IP: {$ip} | Time: {$time}. Recommended: review logs, lock account if needed. Logs at: {$logsUrl}";
        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}