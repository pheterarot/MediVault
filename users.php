<?php
// ============================================================
// MEDIVAULT — users.php
// Purpose:  Admin user management — create accounts, view all
//           users, change roles, lock/unlock, reset attempts
// Layout:   Full sidebar
// Access:   Admin only
// Rules:    Always included AFTER db.php and auth.php
//           mailer.php included for sendWelcome(),
//           sendAccountLocked(), sendAccountUnlocked()
//           Admin cannot lock/change role on own account
//           All actions logged to activity_logs
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';
require 'includes/mailer.php';

// ============================================================
// ACCESS CONTROL — admin only
// ============================================================
requireRole(['admin']);

$userId   = $_SESSION['user_id'];
$userName = $_SESSION['user_name'];
$userRole = $_SESSION['user_role'];
$ip       = getUserIP();

// ============================================================
// FLASH MESSAGE VARIABLES
// Set during POST processing, displayed in HTML below
// ============================================================
$successMsg = '';
$errorMsg   = '';

// ============================================================
// POST HANDLER — all form actions handled here before HTML
// Every action: verifyCsrf() first, then logic, then log
// ============================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrf();

    $action = $_POST['action'] ?? '';

    // --------------------------------------------------------
    // ACTION 1 — CREATE NEW USER
    // --------------------------------------------------------
    if ($action === 'create_user') {

        $newName  = clean($_POST['name']  ?? '');
        $newEmail = clean($_POST['email'] ?? '');
        $newRole  = clean($_POST['role']  ?? '');

        // --- Server-side validation ---
        $allowedRoles = ['admin', 'doctor', 'nurse', 'receptionist'];

        if (empty($newName) || empty($newEmail) || empty($newRole)) {
            $errorMsg = "All fields are required.";

        } elseif (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            $errorMsg = "Please enter a valid email address.";

        } elseif (!in_array($newRole, $allowedRoles)) {
            $errorMsg = "Invalid role selected.";

        } else {
            // Check for duplicate email
            $checkStmt = $conn->prepare(
                "SELECT id FROM users WHERE email = ? LIMIT 1"
            );
            $checkStmt->bind_param("s", $newEmail);
            $checkStmt->execute();
            $checkStmt->store_result();
            $emailExists = $checkStmt->num_rows > 0;
            $checkStmt->close();

            if ($emailExists) {
                $errorMsg = "An account with that email already exists.";

            } else {
                // Generate temp password: MediVault@ + 4-digit random
                $randomDigits = str_pad(rand(0, 9999), 4, '0', STR_PAD_LEFT);
                $tempPassword = 'MediVault@' . $randomDigits;
                $hashedPassword = password_hash($tempPassword, PASSWORD_DEFAULT);

                // Insert new user
                $insertStmt = $conn->prepare(
                    "INSERT INTO users
                     (name, email, password, role, first_login, created_by)
                     VALUES (?, ?, ?, ?, 1, ?)"
                );
                $insertStmt->bind_param(
                    "ssssi",
                    $newName,
                    $newEmail,
                    $hashedPassword,
                    $newRole,
                    $userId
                );

                if ($insertStmt->execute()) {
                    // Send welcome email — failure must not break the flow
                    $emailSent = sendWelcome($newEmail, $newName, $newRole, $tempPassword);

                    // Log account creation
                    $logAction = "Created new user account: {$newName} ({$newEmail}) as {$newRole}";
                    logActivity($conn, $userId, $logAction, $ip);

                    $successMsg = "Account created for <strong>" . htmlspecialchars($newName, ENT_QUOTES, 'UTF-8') . "</strong>."
                        . ($emailSent
                            ? " Welcome email sent successfully."
                            : " <em>Note: Welcome email could not be sent — check mailer config.</em>");
                } else {
                    $errorMsg = "Database error. Could not create account. Please try again.";
                }
                $insertStmt->close();
            }
        }

    // --------------------------------------------------------
    // ACTION 2 — CHANGE ROLE
    // Admin cannot change their own role
    // --------------------------------------------------------
    } elseif ($action === 'change_role') {

        $targetId  = (int)($_POST['target_id'] ?? 0);
        $newRole   = clean($_POST['new_role'] ?? '');
        $allowedRoles = ['admin', 'doctor', 'nurse', 'receptionist'];

        if ($targetId === (int)$userId) {
            $errorMsg = "You cannot change your own role.";

        } elseif (!in_array($newRole, $allowedRoles) || $targetId < 1) {
            $errorMsg = "Invalid request.";

        } else {
            // Fetch target user name for the log
            $nameStmt = $conn->prepare("SELECT name FROM users WHERE id = ? LIMIT 1");
            $nameStmt->bind_param("i", $targetId);
            $nameStmt->execute();
            $nameRow = $nameStmt->get_result()->fetch_assoc();
            $nameStmt->close();

            if (!$nameRow) {
                $errorMsg = "User not found.";
            } else {
                $updateStmt = $conn->prepare(
                    "UPDATE users SET role = ? WHERE id = ?"
                );
                $updateStmt->bind_param("si", $newRole, $targetId);

                if ($updateStmt->execute()) {
                    $logAction = "Changed role of {$nameRow['name']} (ID: {$targetId}) to {$newRole}";
                    logActivity($conn, $userId, $logAction, $ip);
                    $successMsg = "Role updated to <strong>" . htmlspecialchars(ucfirst($newRole), ENT_QUOTES, 'UTF-8') . "</strong> for <strong>" . htmlspecialchars($nameRow['name'], ENT_QUOTES, 'UTF-8') . "</strong>.";
                } else {
                    $errorMsg = "Could not update role. Please try again.";
                }
                $updateStmt->close();
            }
        }

    // --------------------------------------------------------
    // ACTION 3 — LOCK ACCOUNT
    // Admin cannot lock their own account
    // Calls sendAccountLocked($email, $name, $ip)
    // --------------------------------------------------------
    } elseif ($action === 'lock_account') {

        $targetId = (int)($_POST['target_id'] ?? 0);

        if ($targetId === (int)$userId) {
            $errorMsg = "You cannot lock your own account.";

        } elseif ($targetId < 1) {
            $errorMsg = "Invalid request.";

        } else {
            // Fetch target user's name + email for email notification
            $uStmt = $conn->prepare(
                "SELECT name, email FROM users WHERE id = ? LIMIT 1"
            );
            $uStmt->bind_param("i", $targetId);
            $uStmt->execute();
            $uRow = $uStmt->get_result()->fetch_assoc();
            $uStmt->close();

            if (!$uRow) {
                $errorMsg = "User not found.";
            } else {
                $lockStmt = $conn->prepare(
                    "UPDATE users SET is_locked = 1 WHERE id = ?"
                );
                $lockStmt->bind_param("i", $targetId);

                if ($lockStmt->execute()) {
                    // Send locked notification to the affected user
                    sendAccountLocked($uRow['email'], $uRow['name'], $ip);

                    $logAction = "Locked account of {$uRow['name']} (ID: {$targetId})";
                    logActivity($conn, $userId, $logAction, $ip);
                    $successMsg = "Account for <strong>" . htmlspecialchars($uRow['name'], ENT_QUOTES, 'UTF-8') . "</strong> has been locked.";
                } else {
                    $errorMsg = "Could not lock account. Please try again.";
                }
                $lockStmt->close();
            }
        }

    // --------------------------------------------------------
    // ACTION 4 — UNLOCK ACCOUNT
    // Resets failed_attempts to 0 as well
    // Calls sendAccountUnlocked($email, $name)
    // --------------------------------------------------------
    } elseif ($action === 'unlock_account') {

        $targetId = (int)($_POST['target_id'] ?? 0);

        if ($targetId < 1) {
            $errorMsg = "Invalid request.";
        } else {
            $uStmt = $conn->prepare(
                "SELECT name, email FROM users WHERE id = ? LIMIT 1"
            );
            $uStmt->bind_param("i", $targetId);
            $uStmt->execute();
            $uRow = $uStmt->get_result()->fetch_assoc();
            $uStmt->close();

            if (!$uRow) {
                $errorMsg = "User not found.";
            } else {
                $unlockStmt = $conn->prepare(
                    "UPDATE users SET is_locked = 0, failed_attempts = 0 WHERE id = ?"
                );
                $unlockStmt->bind_param("i", $targetId);

                if ($unlockStmt->execute()) {
                    // Send unlocked notification to the affected user
                    sendAccountUnlocked($uRow['email'], $uRow['name']);

                    $logAction = "Unlocked account of {$uRow['name']} (ID: {$targetId}) and reset failed attempts";
                    logActivity($conn, $userId, $logAction, $ip);
                    $successMsg = "Account for <strong>" . htmlspecialchars($uRow['name'], ENT_QUOTES, 'UTF-8') . "</strong> has been unlocked.";
                } else {
                    $errorMsg = "Could not unlock account. Please try again.";
                }
                $unlockStmt->close();
            }
        }

    // --------------------------------------------------------
    // ACTION 5 — SEND PASSWORD RESET LINK
    // Admin sends a reset link to any user on their behalf
    // Generates a fresh token, stores it, emails the user
    // --------------------------------------------------------
    } elseif ($action === 'send_reset_link') {

        $targetId = (int)($_POST['target_id'] ?? 0);

        if ($targetId < 1) {
            $errorMsg = "Invalid request.";
        } else {
            $uStmt = $conn->prepare(
                "SELECT name, email FROM users WHERE id = ? LIMIT 1"
            );
            $uStmt->bind_param("i", $targetId);
            $uStmt->execute();
            $uRow = $uStmt->get_result()->fetch_assoc();
            $uStmt->close();

            if (!$uRow) {
                $errorMsg = "User not found.";
            } else {
                // Generate a secure token valid for 15 minutes
                $token  = bin2hex(random_bytes(32));
                $expiry = date('Y-m-d H:i:s', strtotime('+15 minutes'));

                $tokenStmt = $conn->prepare(
                    "UPDATE users
                     SET reset_token = ?, reset_expiry = ?, reset_used = 0
                     WHERE id = ?"
                );
                $tokenStmt->bind_param("ssi", $token, $expiry, $targetId);

                if ($tokenStmt->execute()) {
                    $protocol  = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
                    $host      = $_SERVER['HTTP_HOST'];
                    $resetLink = "$protocol://$host/MediVault/reset_password.php?token=$token";

                    // On localhost Brevo rejects emails with localhost URLs.
                    // Log the link so admin can copy-paste it manually during local testing.
                    // On live, the email sends normally with the full clickable link.
                    if (defined('IS_LOCALHOST') && IS_LOCALHOST) {
                        error_log("[MediVault] Password reset link for {$uRow['name']}: $resetLink");
                    }

                    $emailSent = sendPasswordReset($uRow['email'], $uRow['name'], $resetLink);

                    $logAction = "Admin sent password reset link to {$uRow['name']} (ID: {$targetId})";
                    logActivity($conn, $userId, $logAction, $ip);

                    $successMsg = "Password reset link sent to <strong>" . htmlspecialchars($uRow['name'], ENT_QUOTES, 'UTF-8') . "</strong>."
                        . ($emailSent
                            ? " Email delivered successfully."
                            : " <em>Note: Email could not be sent — check mailer config.</em>");
                } else {
                    $errorMsg = "Could not generate reset token. Please try again.";
                }
                $tokenStmt->close();
            }
        }

    // --------------------------------------------------------
    // ACTION 6 — RESET FAILED ATTEMPTS
    // No self-restriction — safe action
    // --------------------------------------------------------
    } elseif ($action === 'reset_attempts') {

        $targetId = (int)($_POST['target_id'] ?? 0);

        if ($targetId < 1) {
            $errorMsg = "Invalid request.";
        } else {
            $uStmt = $conn->prepare(
                "SELECT name FROM users WHERE id = ? LIMIT 1"
            );
            $uStmt->bind_param("i", $targetId);
            $uStmt->execute();
            $uRow = $uStmt->get_result()->fetch_assoc();
            $uStmt->close();

            if (!$uRow) {
                $errorMsg = "User not found.";
            } else {
                $resetStmt = $conn->prepare(
                    "UPDATE users SET failed_attempts = 0 WHERE id = ?"
                );
                $resetStmt->bind_param("i", $targetId);

                if ($resetStmt->execute()) {
                    $logAction = "Reset failed login attempts for {$uRow['name']} (ID: {$targetId})";
                    logActivity($conn, $userId, $logAction, $ip);
                    $successMsg = "Failed attempts reset for <strong>" . htmlspecialchars($uRow['name'], ENT_QUOTES, 'UTF-8') . "</strong>.";
                } else {
                    $errorMsg = "Could not reset attempts. Please try again.";
                }
                $resetStmt->close();
            }
        }

    } elseif ($action === 'edit_user') {

        // --------------------------------------------------------
        // Edit user name and email
        // Admin cannot edit their own account via this action
        // --------------------------------------------------------
        $targetId = (int)($_POST['target_id'] ?? 0);
        $newName  = trim(clean($_POST['new_name']  ?? ''));
        $newEmail = trim(clean($_POST['new_email'] ?? ''));

        if ($targetId === $userId) {
            $errorMsg = "You cannot edit your own account here.";

        } elseif ($targetId < 1) {
            $errorMsg = "Invalid request.";

        } elseif ($newName === '') {
            $errorMsg = "Name cannot be empty.";

        } elseif (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            $errorMsg = "Please enter a valid email address.";

        } else {
            // Check duplicate email — exclude the target user's own current email
            $dupStmt = $conn->prepare(
                "SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1"
            );
            $dupStmt->bind_param("si", $newEmail, $targetId);
            $dupStmt->execute();
            $dupStmt->store_result();
            $emailTaken = $dupStmt->num_rows > 0;
            $dupStmt->close();

            if ($emailTaken) {
                $errorMsg = "An account with that email already exists.";
            } else {
                $editStmt = $conn->prepare(
                    "UPDATE users SET name = ?, email = ? WHERE id = ?"
                );
                $editStmt->bind_param("ssi", $newName, $newEmail, $targetId);

                if ($editStmt->execute()) {
                    $logAction = "Edited user info for {$newName} (ID: {$targetId})";
                    logActivity($conn, $userId, $logAction, $ip);
                    $successMsg = "Account info updated for <strong>" . htmlspecialchars($newName, ENT_QUOTES, 'UTF-8') . "</strong>.";
                } else {
                    $errorMsg = "Could not update user info. Please try again.";
                }
                $editStmt->close();
            }
        }

    // --------------------------------------------------------
    // ACTION 7 — SOFT DELETE USER
    // Sets deleted_at and deleted_by; cannot delete own account
    // Server-side guard: AND id != $userId in the WHERE clause
    // --------------------------------------------------------
    } elseif ($action === 'soft_delete_user') {

        $targetId = (int)($_POST['target_id'] ?? 0);

        if ($targetId === (int)$userId) {
            $errorMsg = "You cannot delete your own account.";

        } elseif ($targetId < 1) {
            $errorMsg = "Invalid request.";

        } else {
            // Fetch name for the log before deleting
            $uStmt = $conn->prepare("SELECT name FROM users WHERE id = ? AND id != ? LIMIT 1");
            $uStmt->bind_param("ii", $targetId, $userId);
            $uStmt->execute();
            $uRow = $uStmt->get_result()->fetch_assoc();
            $uStmt->close();

            if (!$uRow) {
                $errorMsg = "User not found or cannot be deleted.";
            } else {
                $delStmt = $conn->prepare(
                    "UPDATE users SET deleted_at = NOW(), deleted_by = ? WHERE id = ? AND id != ?"
                );
                $delStmt->bind_param("iii", $userId, $targetId, $userId);

                if ($delStmt->execute() && $delStmt->affected_rows > 0) {
                    $logAction = "Soft deleted user: {$uRow['name']} (ID: {$targetId})";
                    logActivity($conn, $userId, $logAction, $ip);
                    $successMsg = "User <strong>" . htmlspecialchars($uRow['name'], ENT_QUOTES, 'UTF-8') . "</strong> has been deleted and moved to trash.";
                } else {
                    $errorMsg = "Could not delete user. Please try again.";
                }
                $delStmt->close();
            }
        }

    // --------------------------------------------------------
    // ACTION 8 — RESTORE USER
    // Clears deleted_at and deleted_by — admin only
    // --------------------------------------------------------
    } elseif ($action === 'restore_user') {

        $targetId = (int)($_POST['target_id'] ?? 0);

        if ($targetId < 1) {
            $errorMsg = "Invalid request.";
        } else {
            // Fetch name from deleted records for the log
            $uStmt = $conn->prepare("SELECT name FROM users WHERE id = ? AND deleted_at IS NOT NULL LIMIT 1");
            $uStmt->bind_param("i", $targetId);
            $uStmt->execute();
            $uRow = $uStmt->get_result()->fetch_assoc();
            $uStmt->close();

            if (!$uRow) {
                $errorMsg = "User not found in trash.";
            } else {
                $restoreStmt = $conn->prepare(
                    "UPDATE users SET deleted_at = NULL, deleted_by = NULL WHERE id = ?"
                );
                $restoreStmt->bind_param("i", $targetId);

                if ($restoreStmt->execute()) {
                    $logAction = "Restored user: {$uRow['name']} (ID: {$targetId})";
                    logActivity($conn, $userId, $logAction, $ip);
                    $successMsg = "User <strong>" . htmlspecialchars($uRow['name'], ENT_QUOTES, 'UTF-8') . "</strong> has been restored.";
                } else {
                    $errorMsg = "Could not restore user. Please try again.";
                }
                $restoreStmt->close();
            }
        }
    }
}

// ============================================================
// FETCH ALL USERS FOR TABLE
// LEFT JOIN to get created_by name (nullable — seed data = NULL)
// Ordered by created_at DESC — newest first
// Soft delete: exclude soft-deleted users
// ============================================================
$allUsers = [];
$usersStmt = $conn->prepare(
    "SELECT
        u.id,
        u.name,
        u.email,
        u.role,
        u.failed_attempts,
        u.is_locked,
        u.first_login,
        u.created_at,
        COALESCE(creator.name, 'System') AS created_by_name
     FROM users u
     LEFT JOIN users AS creator ON creator.id = u.created_by
     WHERE u.deleted_at IS NULL
     ORDER BY u.id DESC, u.created_at DESC"
);
$usersStmt->execute();
$usersResult = $usersStmt->get_result();
while ($row = $usersResult->fetch_assoc()) {
    $allUsers[] = $row;
}
$usersStmt->close();

// ============================================================
// FETCH DELETED USERS FOR TRASH SECTION (Admin only)
// ============================================================
$deletedUsers = [];
$trashStmt = $conn->prepare(
    "SELECT id, name, email, role, deleted_at
     FROM users
     WHERE deleted_at IS NOT NULL
     ORDER BY deleted_at DESC"
);
$trashStmt->execute();
$trashResult = $trashStmt->get_result();
while ($row = $trashResult->fetch_assoc()) {
    $deletedUsers[] = $row;
}
$trashStmt->close();

// Log page access
logActivity($conn, $userId, "Viewed Users management page", $ip);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Users</title>
    <link rel="icon" href="assets/images/favicon.ico">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* ======================================================
           BASE RESET
        ====================================================== */
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

        /* ======================================================
           SIDEBAR — identical to dashboard.php
        ====================================================== */
        .sidebar {
            width: 250px;
            height: 100vh;
            background: linear-gradient(180deg, #1E40AF, #2563EB);
            position: fixed;
            left: 0;
            top: 0;
            overflow-y: auto;
            z-index: 1000;
            display: flex;
            flex-direction: column;
        }

        .sidebar-brand {
            padding: 25px 20px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }

        .sidebar-brand h4 {
            color: #ffffff;
            font-size: 20px;
            font-weight: 700;
            margin: 0;
            letter-spacing: 1px;
        }

        .sidebar-brand p {
            color: #BAE6FD;
            font-size: 11px;
            margin: 3px 0 0;
        }

        .sidebar nav {
            padding: 15px 0;
            flex: 1;
        }

        .sidebar nav a {
            display: flex;
            align-items: center;
            gap: 10px;
            color: rgba(255,255,255,0.8);
            padding: 11px 20px;
            text-decoration: none;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s;
            border-left: 3px solid transparent;
        }

        .sidebar nav a:hover,
        .sidebar nav a.active {
            background: rgba(255,255,255,0.12);
            color: #ffffff;
            border-left-color: #38BDF8;
        }

        .sidebar-divider {
            border: none;
            border-top: 1px solid rgba(255,255,255,0.1);
            margin: 8px 0;
        }

        .sidebar-footer {
            padding: 15px 20px;
            border-top: 1px solid rgba(255,255,255,0.1);
        }

        .sidebar-footer .user-info p {
            color: rgba(255,255,255,0.7);
            font-size: 12px;
            margin: 0;
            font-weight: 500;
        }

        .sidebar-footer .role-badge {
            display: inline-block;
            background: rgba(255,255,255,0.15);
            color: #ffffff;
            padding: 2px 8px;
            border-radius: 20px;
            font-size: 10px;
            margin-top: 5px;
            text-transform: capitalize;
        }

        .sidebar-footer a {
            display: flex;
            align-items: center;
            gap: 8px;
            color: rgba(255,255,255,0.7);
            text-decoration: none;
            font-size: 12px;
            padding: 6px 0;
            transition: color 0.2s;
        }

        .sidebar-footer a:hover {
            color: #ffffff;
        }

        .sidebar-footer .footer-links {
            margin-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.1);
            padding-top: 8px;
        }

        /* ======================================================
           TOPBAR
        ====================================================== */
        .topbar {
            position: fixed;
            top: 0;
            left: 250px;
            right: 0;
            height: 60px;
            background: #ffffff;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
            display: flex;
            align-items: center;
            padding: 0 30px;
            z-index: 900;
            gap: 12px;
        }

        .hamburger {
            display: none;
            background: none;
            border: none;
            font-size: 22px;
            cursor: pointer;
            color: #1E293B;
            padding: 4px;
            line-height: 1;
        }

        .topbar-title {
            font-size: 16px;
            font-weight: 600;
            color: #1E293B;
        }

        .topbar-right {
            margin-left: auto;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .topbar-user {
            font-size: 13px;
            color: #94A3B8;
        }

        .topbar-role-badge {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: capitalize;
        }

        /* ======================================================
           MAIN CONTENT AREA
        ====================================================== */
        .main-content {
            margin-left: 250px;
            padding: 30px;
            padding-top: 90px;
            min-height: 100vh;
        }

        .page-header {
            margin-bottom: 25px;
        }

        .page-header h2 {
            font-size: 24px;
            font-weight: 700;
            color: #1E293B;
            margin: 0;
        }

        .page-header p {
            color: #94A3B8;
            font-size: 13px;
            margin: 5px 0 0;
        }

        /* ======================================================
           SECTION CARDS
        ====================================================== */
        .section-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            background: #ffffff;
            margin-bottom: 28px;
            overflow: hidden;
        }

        .section-card .card-header-mv {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            font-weight: 600;
            font-size: 15px;
            padding: 15px 20px;
            border: none;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-card .card-body-mv {
            padding: 24px;
        }

        /* ======================================================
           FORM ELEMENTS
        ====================================================== */
        .form-label {
            font-size: 13px;
            font-weight: 600;
            color: #475569;
            margin-bottom: 6px;
        }

        .form-control,
        .form-select {
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-size: 13px;
            font-family: 'Poppins', sans-serif;
            color: #1E293B;
            padding: 9px 14px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: #2563EB;
            box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
            outline: none;
        }

        .form-control::placeholder {
            color: #94A3B8;
            font-size: 13px;
        }

        /* ======================================================
           BUTTONS — spec colors
        ====================================================== */
        .btn-primary-mv {
            background: #2563EB;
            border: none;
            border-radius: 8px;
            color: #ffffff;
            font-family: 'Poppins', sans-serif;
            font-weight: 600;
            font-size: 13px;
            padding: 9px 22px;
            cursor: pointer;
            transition: background 0.2s, transform 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .btn-primary-mv:hover {
            background: #1E40AF;
            transform: translateY(-1px);
        }

        .btn-sm-mv {
            border: none;
            border-radius: 6px;
            color: #ffffff;
            font-family: 'Poppins', sans-serif;
            font-weight: 600;
            font-size: 11px;
            padding: 4px 8px;
            cursor: pointer;
            transition: background 0.2s, transform 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 3px;
            white-space: nowrap;
        }

        .btn-sm-mv:hover {
            transform: translateY(-1px);
        }

        .btn-danger-mv  { background: #EF4444; }
        .btn-danger-mv:hover  { background: #DC2626; }

        .btn-success-mv { background: #22C55E; }
        .btn-success-mv:hover { background: #16A34A; }

        .btn-warning-mv { background: #F59E0B; color: #fff; }
        .btn-warning-mv:hover { background: #D97706; }

        .btn-info-mv    { background: #38BDF8; }
        .btn-info-mv:hover    { background: #0EA5E9; }

        .btn-role-mv {
            background: #2563EB;
            border: none;
            border-radius: 6px;
            color: #ffffff;
            font-family: 'Poppins', sans-serif;
            font-weight: 600;
            font-size: 11px;
            padding: 5px 11px;
            cursor: pointer;
            transition: background 0.2s;
            white-space: nowrap;
        }

        .btn-role-mv:hover { background: #1E40AF; }

        /* Role filter tab buttons */
        .role-filter-btn {
            padding: 6px 14px;
            border: 1px solid #E2E8F0;
            border-radius: 20px;
            background: #F8FAFC;
            color: #64748B;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
        }
        .role-filter-btn:hover {
            background: #EFF6FF;
            border-color: #2563EB;
            color: #2563EB;
        }
        .role-filter-btn.active {
            background: #2563EB;
            border-color: #2563EB;
            color: #ffffff;
        }

        /* Edit button */
        .btn-edit-mv {
            background: #F0FDF4;
            color: #166534;
            border: 1px solid #86EFAC;
        }

        .btn-edit-mv:hover {
            background: #DCFCE7;
            border-color: #4ADE80;
        }

        /* Disabled / own-account button */
        .btn-disabled-mv {
            background: #CBD5E1;
            border: none;
            border-radius: 6px;
            color: #94A3B8;
            font-family: 'Poppins', sans-serif;
            font-weight: 600;
            font-size: 11px;
            padding: 5px 11px;
            cursor: not-allowed;
            white-space: nowrap;
        }

        /* ======================================================
           ALERT MESSAGES
        ====================================================== */
        .alert-mv {
            border-radius: 10px;
            padding: 14px 18px;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 22px;
            display: flex;
            align-items: flex-start;
            gap: 10px;
            border: none;
        }

        .alert-success-mv {
            background: #F0FDF4;
            border-left: 4px solid #22C55E;
            color: #166534;
        }

        .alert-error-mv {
            background: #FEF2F2;
            border-left: 4px solid #EF4444;
            color: #991B1B;
        }

        /* ======================================================
           BADGES
        ====================================================== */
        .badge-mv {
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            display: inline-block;
            white-space: nowrap;
        }

        .badge-active     { background: #DCFCE7; color: #166534; }
        .badge-locked     { background: #FEE2E2; color: #991B1B; }
        .badge-temp       { background: #FEF3C7; color: #92400E; }
        .badge-set        { background: #DCFCE7; color: #166534; }
        .badge-role-admin        { background: #EFF6FF; color: #1E40AF; }
        .badge-role-doctor       { background: #F0FDF4; color: #166534; }
        .badge-role-nurse        { background: #FFF7ED; color: #9A3412; }
        .badge-role-receptionist { background: #F5F3FF; color: #5B21B6; }

        /* ======================================================
           TABLE
        ====================================================== */
        .table-mv {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .table-mv thead th {
            background: #F8FAFC;
            color: #64748B;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 8px 10px;
            border-bottom: 2px solid #E2E8F0;
            white-space: nowrap;
        }

        .table-mv tbody td {
            padding: 7px 10px;
            border-bottom: 1px solid #F1F5F9;
            color: #1E293B;
            vertical-align: middle;
        }

        .table-mv tbody tr:last-child td {
            border-bottom: none;
        }

        .table-mv tbody tr:hover td {
            background: #F8FAFC;
        }

        /* Highlight locked rows lightly */
        .table-mv tbody tr.row-locked td {
            background: #FEF2F2;
        }

        .table-mv tbody tr.row-locked:hover td {
            background: #FEE2E2;
        }

        /* Self-row subtle highlight */
        .table-mv tbody tr.row-self td {
            background: #EFF6FF;
        }

        .table-mv tbody tr.row-self:hover td {
            background: #DBEAFE;
        }

        /* User name display */
        .user-name-cell {
            font-weight: 600;
            color: #1E293B;
        }

        .user-email-cell {
            font-size: 12px;
            color: #64748B;
            margin-top: 1px;
        }

        /* Actions cell — wrap nicely */
        .actions-cell {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            align-items: center;
        }

        /* Role change inline form */
        .role-change-form {
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }

        .role-select-inline {
            border: 1px solid #E2E8F0;
            border-radius: 6px;
            font-size: 11px;
            font-family: 'Poppins', sans-serif;
            color: #1E293B;
            padding: 4px 8px;
            background: #fff;
            cursor: pointer;
        }

        .role-select-inline:focus {
            border-color: #2563EB;
            outline: none;
        }

        /* Attempts count */
        .attempts-cell {
            font-weight: 600;
            color: #1E293B;
        }

        .attempts-cell.has-attempts {
            color: #EF4444;
        }

        /* ======================================================
           TEMP PASSWORD DISPLAY IN SUCCESS BOX
        ====================================================== */
        .temp-pwd-box {
            background: #EFF6FF;
            border: 2px dashed #2563EB;
            border-radius: 10px;
            padding: 12px 18px;
            font-family: monospace;
            font-size: 16px;
            font-weight: 700;
            color: #1E40AF;
            letter-spacing: 2px;
            display: inline-block;
            margin-top: 6px;
        }

        /* ======================================================
           MOBILE OVERLAY
        ====================================================== */
        #overlay {
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 999;
        }

        #overlay.show {
            display: block !important;
        }

        /* ======================================================
           RESPONSIVE — mobile sidebar collapse
        ====================================================== */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-250px);
                transition: transform 0.3s ease;
            }

            .sidebar.open {
                transform: translateX(0);
            }

            .topbar {
                left: 0;
                padding: 0 15px;
            }

            .main-content {
                margin-left: 0;
                padding: 20px 15px;
                padding-top: 80px;
            }

            .hamburger {
                display: block !important;
            }

            .topbar-user {
                display: none;
            }

            .actions-cell {
                flex-direction: column;
                align-items: flex-start;
            }

            .section-card .card-body-mv {
                padding: 16px;
            }
        }

        @media (min-width: 769px) {
            .hamburger {
                display: none !important;
            }
        }

        /* ======================================================
           TOOLTIP WRAPPER — own-account disabled actions
        ====================================================== */
        .tooltip-wrapper {
            position: relative;
            display: inline-block;
        }

        .tooltip-wrapper .tooltip-text {
            visibility: hidden;
            opacity: 0;
            background: #1E293B;
            color: #ffffff;
            font-size: 11px;
            font-weight: 500;
            text-align: center;
            border-radius: 6px;
            padding: 5px 10px;
            position: absolute;
            bottom: 130%;
            left: 50%;
            transform: translateX(-50%);
            white-space: nowrap;
            z-index: 10;
            transition: opacity 0.2s;
            pointer-events: none;
        }

        .tooltip-wrapper .tooltip-text::after {
            content: '';
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translateX(-50%);
            border: 5px solid transparent;
            border-top-color: #1E293B;
        }

        .tooltip-wrapper:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }

        /* ======================================================
           SECTION SPACING
        ====================================================== */
        .section-gap {
            margin-bottom: 28px;
        }

        /* Table wrapper user count label */
        .table-meta {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
            flex-wrap: wrap;
            gap: 8px;
        }

        .table-meta-count {
            font-size: 12px;
            color: #94A3B8;
            font-weight: 500;
        }

    </style>
</head>
<body>

<!-- ============================================================
     MOBILE OVERLAY — closes sidebar on backdrop click
============================================================ -->
<div id="overlay"></div>

<!-- ============================================================
     SIDEBAR — identical to dashboard.php, active = users.php
============================================================ -->
<aside class="sidebar" id="sidebar">

    <!-- Brand -->
    <div class="sidebar-brand">
        <h4>🏥 MediVault</h4>
        <p>Securing Patient Records. Protecting Lives.</p>
    </div>

    <!-- Navigation Links — visibility per spec rules -->
    <nav>
        <!-- Dashboard — all roles -->
        <a href="dashboard.php">
            <span>📊</span> Dashboard
        </a>

        <!-- Patients — all roles -->
        <a href="patients.php">
            <span>👤</span> Patients
        </a>

        <!-- Assets — ADMIN ONLY -->
        <?php if ($userRole === 'admin'): ?>
        <a href="assets.php">
            <span>🏗️</span> Assets
        </a>
        <?php endif; ?>

        <!-- Risks — ADMIN ONLY -->
        <?php if ($userRole === 'admin'): ?>
        <a href="risks.php">
            <span>⚠️</span> Risks
        </a>
        <?php endif; ?>

        <!-- Incidents — all roles -->
        <a href="incidents.php">
            <span>🚨</span> Incidents
        </a>

        <!-- Logs — ADMIN ONLY -->
        <?php if ($userRole === 'admin'): ?>
        <a href="logs.php">
            <span>📋</span> Logs
        </a>
        <?php endif; ?>

        <!-- Users — ADMIN ONLY — ACTIVE on this page -->
        <?php if ($userRole === 'admin'): ?>
        <a href="users.php" class="active">
            <span>👥</span> Users
        </a>
        <?php endif; ?>

        <!-- Policy — all roles -->
        <a href="policy.php">
            <span>📄</span> Policy
        </a>

        <!-- Audit Export — ADMIN ONLY -->

    </nav>

    <!-- Footer — user info + utility links -->
    <div class="sidebar-footer">
        <div class="user-info">
            <p>👋 <?= htmlspecialchars($userName, ENT_QUOTES, 'UTF-8') ?></p>
            <span class="role-badge"><?= htmlspecialchars($userRole, ENT_QUOTES, 'UTF-8') ?></span>
        </div>
        <div class="footer-links">
            <a href="change_password.php">
                <span>🔑</span> Change Password
            </a>
            <a href="logout.php">
                <span>🚪</span> Logout
            </a>
        </div>
    </div>

</aside>
<!-- End Sidebar -->

<!-- ============================================================
     TOPBAR — 60px fixed, white with shadow
============================================================ -->
<div class="topbar">
    <!-- Hamburger — mobile only -->
    <button class="hamburger" id="hamburger" aria-label="Toggle navigation">&#9776;</button>

    <span class="topbar-title">👥 User Management</span>

    <div class="topbar-right">
        <span class="topbar-user">Welcome back, <?= htmlspecialchars($userName, ENT_QUOTES, 'UTF-8') ?></span>
        <span class="topbar-role-badge"><?= htmlspecialchars($userRole, ENT_QUOTES, 'UTF-8') ?></span>
    </div>
</div>

<!-- ============================================================
     MAIN CONTENT
============================================================ -->
<main class="main-content">

    <!-- --------------------------------------------------------
         PAGE HEADER
    -------------------------------------------------------- -->
    <div class="page-header">
        <h2>User Management</h2>
        <p>Create accounts, manage roles, and control access — <?= date('l, F j, Y') ?></p>
    </div>

    <!-- --------------------------------------------------------
         FLASH MESSAGES — success or error from POST
    -------------------------------------------------------- -->
    <?php if ($successMsg): ?>
    <div class="alert-mv alert-success-mv">
        <span style="font-size:16px;">✅</span>
        <span><?= $successMsg ?></span>
    </div>
    <?php endif; ?>

    <?php if ($errorMsg): ?>
    <div class="alert-mv alert-error-mv">
        <span style="font-size:16px;">❌</span>
        <span><?= htmlspecialchars($errorMsg, ENT_QUOTES, 'UTF-8') ?></span>
    </div>
    <?php endif; ?>

    <!-- ========================================================
         SECTION 1 — CREATE NEW USER FORM
    ========================================================= -->
    <div class="section-card section-gap">
        <div class="card-header-mv">
            <span>➕</span> Create New User
        </div>
        <div class="card-body-mv">

            <p style="font-size:13px; color:#64748B; margin-bottom:20px;">
                Fill in the details below. The system will generate a temporary password and send a welcome email to the new user.
                They will be required to change it on first login.
            </p>

            <form method="POST" action="users.php" autocomplete="off">
                <!-- CSRF token — required on every POST form -->
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="action" value="create_user">

                <div class="row g-3">

                    <!-- Name -->
                    <div class="col-12 col-md-4">
                        <label class="form-label" for="name">Full Name</label>
                        <input
                            type="text"
                            class="form-control"
                            id="name"
                            name="name"
                            placeholder="e.g. Dr. Maria Santos"
                            maxlength="100"
                            required
                        >
                    </div>

                    <!-- Email -->
                    <div class="col-12 col-md-4">
                        <label class="form-label" for="email">Email Address</label>
                        <input
                            type="email"
                            class="form-control"
                            id="email"
                            name="email"
                            placeholder="e.g. maria@hospital.com"
                            maxlength="100"
                            required
                        >
                    </div>

                    <!-- Role -->
                    <div class="col-12 col-md-2">
                        <label class="form-label" for="role">Role</label>
                        <select class="form-select" id="role" name="role" required>
                            <option value="" disabled selected>Select role</option>
                            <option value="admin">Admin</option>
                            <option value="doctor">Doctor</option>
                            <option value="nurse">Nurse</option>
                            <option value="receptionist">Receptionist</option>
                        </select>
                    </div>

                    <!-- Submit -->
                    <div class="col-12 col-md-2 d-flex align-items-end">
                        <button type="submit" class="btn-primary-mv w-100" style="justify-content:center;">
                            <span>➕</span> Create Account
                        </button>
                    </div>

                </div>

                <!-- Temp password notice -->
                <div style="margin-top:16px; padding:12px 16px; background:#F8FAFC; border-radius:8px; border:1px solid #E2E8F0;">
                    <span style="font-size:12px; color:#64748B;">
                        🔐 <strong>No password field needed.</strong>
                        The system will auto-generate a temporary password in the format
                        <code style="background:#EFF6FF; color:#1E40AF; padding:2px 6px; border-radius:4px; font-size:12px;">MediVault@XXXX</code>
                        and send it to the user's email.
                    </span>
                </div>

            </form>
        </div>
    </div>
    <!-- End Section 1 -->

    <!-- ========================================================
         SECTION 2 — ALL USERS TABLE
    ========================================================= -->
    <div class="section-card">
        <div class="card-header-mv">
            <span>👥</span> All Users
            <span style="margin-left:auto; font-size:12px; font-weight:500; opacity:0.85;">
                <span id="userCount"><?= count($allUsers) ?></span> account<?= count($allUsers) !== 1 ? 's' : '' ?> total
            </span>
        </div>
        <div class="card-body-mv" style="padding:16px 20px 0;">

            <!-- Search + Role Filter toolbar -->
            <div style="display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-bottom:14px;">

                <!-- Live search input -->
                <input
                    type="text"
                    id="userSearch"
                    placeholder="🔍  Search by name or email…"
                    oninput="filterUsers()"
                    style="flex:1; min-width:200px; padding:8px 14px;
                           border:1px solid #E2E8F0; border-radius:8px;
                           font-size:13px; color:#1E293B; outline:none;"
                    onfocus="this.style.borderColor='#2563EB'"
                    onblur="this.style.borderColor='#E2E8F0'"
                >

                <!-- Role filter tabs -->
                <div style="display:flex; gap:6px; flex-wrap:wrap;">
                    <button class="role-filter-btn active" onclick="setRoleFilter('all', this)">All</button>
                    <button class="role-filter-btn" onclick="setRoleFilter('admin', this)">Admin</button>
                    <button class="role-filter-btn" onclick="setRoleFilter('doctor', this)">Doctor</button>
                    <button class="role-filter-btn" onclick="setRoleFilter('nurse', this)">Nurse</button>
                    <button class="role-filter-btn" onclick="setRoleFilter('receptionist', this)">Receptionist</button>
                </div>

            </div>

        </div>
        <div class="card-body-mv" style="padding:0;">

            <div class="table-responsive">
                <table class="table-mv">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name / Email</th>
                            <th>Role</th>
                            <th>Failed Attempts</th>
                            <th>Status</th>
                            <th>First Login</th>
                            <th>Created By</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($allUsers)): ?>
                        <tr>
                            <td colspan="9" style="text-align:center; padding:30px; color:#94A3B8; font-size:13px;">
                                No users found in the system.
                            </td>
                        </tr>
                        <?php else: ?>
                        <?php foreach ($allUsers as $u):
                            $isSelf   = ((int)$u['id'] === (int)$userId);
                            $isLocked = ((int)$u['is_locked'] === 1);

                            // Row class: self = blue, locked = red, else default
                            $rowClass = $isSelf ? 'row-self' : ($isLocked ? 'row-locked' : '');

                            // Role badge class
                            $roleBadgeClass = match($u['role']) {
                                'admin'        => 'badge-role-admin',
                                'doctor'       => 'badge-role-doctor',
                                'nurse'        => 'badge-role-nurse',
                                'receptionist' => 'badge-role-receptionist',
                                default        => 'badge-role-doctor',
                            };

                            // Failed attempts color
                            $attemptsClass = ((int)$u['failed_attempts'] > 0) ? 'has-attempts' : '';
                        ?>
                        <tr class="<?= $rowClass ?>">

                            <!-- ID -->
                            <td style="color:#94A3B8; font-size:12px; font-weight:600;">
                                #<?= (int)$u['id'] ?>
                                <?php if ($isSelf): ?>
                                    <span style="font-size:10px; background:#DBEAFE; color:#1E40AF; padding:1px 5px; border-radius:4px; margin-left:2px;">You</span>
                                <?php endif; ?>
                            </td>

                            <!-- Name + Email -->
                            <td>
                                <div class="user-name-cell"><?= htmlspecialchars($u['name'], ENT_QUOTES, 'UTF-8') ?></div>
                                <div class="user-email-cell"><?= htmlspecialchars($u['email'], ENT_QUOTES, 'UTF-8') ?></div>
                            </td>

                            <!-- Role badge -->
                            <td>
                                <span class="badge-mv <?= $roleBadgeClass ?>" data-role="<?= htmlspecialchars($u['role'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= htmlspecialchars(ucfirst($u['role']), ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>

                            <!-- Failed Attempts -->
                            <td>
                                <span class="attempts-cell <?= $attemptsClass ?>">
                                    <?= (int)$u['failed_attempts'] ?>
                                </span>
                            </td>

                            <!-- Status badge -->
                            <td>
                                <?php if ($isLocked): ?>
                                    <span class="badge-mv badge-locked">🔒 Locked</span>
                                <?php else: ?>
                                    <span class="badge-mv badge-active">✅ Active</span>
                                <?php endif; ?>
                            </td>

                            <!-- First Login badge -->
                            <td>
                                <?php if ((int)$u['first_login'] === 1): ?>
                                    <span class="badge-mv badge-temp">⚠️ Temp Password</span>
                                <?php else: ?>
                                    <span class="badge-mv badge-set">🔑 Password Set</span>
                                <?php endif; ?>
                            </td>

                            <!-- Created By -->
                            <td style="font-size:12px; color:#64748B;">
                                <?= htmlspecialchars($u['created_by_name'], ENT_QUOTES, 'UTF-8') ?>
                            </td>

                            <!-- Date -->
                            <td style="font-size:12px; color:#64748B; white-space:nowrap;">
                                <?= date('M j, Y', strtotime($u['created_at'])) ?>
                            </td>

                            <!-- ACTIONS -->
                            <td>
                                <div class="actions-cell">

                                    <!-- ----------------------------------------
                                         ACTION A — CHANGE ROLE
                                         Disabled for admin's own row
                                    ---------------------------------------- -->
                                    <?php if ($isSelf): ?>
                                        <div class="tooltip-wrapper">
                                            <span class="btn-disabled-mv">🔄 Role</span>
                                            <span class="tooltip-text">You cannot modify your own account</span>
                                        </div>
                                    <?php else: ?>
                                        <form method="POST" action="users.php" class="role-change-form">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                            <input type="hidden" name="action" value="change_role">
                                            <input type="hidden" name="target_id" value="<?= (int)$u['id'] ?>">
                                            <select
                                                name="new_role"
                                                class="role-select-inline"
                                                onchange="this.form.submit()"
                                                title="Change role"
                                            >
                                                <option value="admin"        <?= $u['role'] === 'admin'        ? 'selected' : '' ?>>Admin</option>
                                                <option value="doctor"       <?= $u['role'] === 'doctor'       ? 'selected' : '' ?>>Doctor</option>
                                                <option value="nurse"        <?= $u['role'] === 'nurse'        ? 'selected' : '' ?>>Nurse</option>
                                                <option value="receptionist" <?= $u['role'] === 'receptionist' ? 'selected' : '' ?>>Receptionist</option>
                                            </select>
                                        </form>
                                    <?php endif; ?>

                                    <!-- ----------------------------------------
                                         ACTION B — LOCK / UNLOCK
                                         Disabled for admin's own row
                                    ---------------------------------------- -->
                                    <?php if ($isSelf): ?>
                                        <div class="tooltip-wrapper">
                                            <span class="btn-disabled-mv">🔒 Lock</span>
                                            <span class="tooltip-text">You cannot modify your own account</span>
                                        </div>
                                    <?php elseif ($isLocked): ?>
                                        <!-- Unlock button -->
                                        <form method="POST" action="users.php" style="display:inline;">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                            <input type="hidden" name="action" value="unlock_account">
                                            <input type="hidden" name="target_id" value="<?= (int)$u['id'] ?>">
                                            <button
                                                type="submit"
                                                class="btn-sm-mv btn-success-mv"
                                                onclick="return confirm('Unlock account for <?= htmlspecialchars(addslashes($u['name']), ENT_QUOTES, 'UTF-8') ?>?')"
                                                title="Unlock this account"
                                            >
                                                🔓 Unlock
                                            </button>
                                        </form>
                                    <?php else: ?>
                                        <!-- Lock button -->
                                        <form method="POST" action="users.php" style="display:inline;">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                            <input type="hidden" name="action" value="lock_account">
                                            <input type="hidden" name="target_id" value="<?= (int)$u['id'] ?>">
                                            <button
                                                type="submit"
                                                class="btn-sm-mv btn-danger-mv"
                                                onclick="return confirm('Lock account for <?= htmlspecialchars(addslashes($u['name']), ENT_QUOTES, 'UTF-8') ?>? This will prevent them from logging in.')"
                                                title="Lock this account"
                                            >
                                                🔒 Lock
                                            </button>
                                        </form>
                                    <?php endif; ?>

                                    <!-- ----------------------------------------
                                         ACTION C — RESET ATTEMPTS
                                         Allowed on any account including self
                                    ---------------------------------------- -->
                                    <form method="POST" action="users.php" style="display:inline;">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                        <input type="hidden" name="action" value="reset_attempts">
                                        <input type="hidden" name="target_id" value="<?= (int)$u['id'] ?>">
                                        <button
                                            type="submit"
                                            class="btn-sm-mv btn-warning-mv"
                                            onclick="return confirm('Reset failed login attempts for <?= htmlspecialchars(addslashes($u['name']), ENT_QUOTES, 'UTF-8') ?>?')"
                                            title="Reset failed login attempts to 0"
                                            <?= ((int)$u['failed_attempts'] === 0) ? 'style="opacity:0.5; cursor:default;"' : '' ?>
                                        >
                                            🔄 Reset
                                        </button>
                                    </form>

                                    <!-- ----------------------------------------
                                         ACTION D — SEND PASSWORD RESET LINK
                                         Available for all users including self
                                    ---------------------------------------- -->
                                    <form method="POST" action="users.php" style="display:inline;">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                        <input type="hidden" name="action" value="send_reset_link">
                                        <input type="hidden" name="target_id" value="<?= (int)$u['id'] ?>">
                                        <button
                                            type="submit"
                                            class="btn-sm-mv btn-role-mv"
                                            onclick="return confirm('Send a password reset link to <?= htmlspecialchars(addslashes($u['name']), ENT_QUOTES, 'UTF-8') ?>?\n\nThey will receive an email with a link that expires in 15 minutes.')"
                                            title="Send password reset link to this user"
                                        >
                                            📧 Reset Link
                                        </button>
                                    </form>

                                    <!-- ----------------------------------------
                                         ACTION E — EDIT USER INFO
                                         Disabled for admin's own row
                                    ---------------------------------------- -->
                                    <?php if ($isSelf): ?>
                                        <div class="tooltip-wrapper">
                                            <span class="btn-disabled-mv">✏️ Edit</span>
                                            <span class="tooltip-text">You cannot modify your own account</span>
                                        </div>
                                    <?php else: ?>
                                        <button
                                            type="button"
                                            class="btn-sm-mv btn-edit-mv"
                                            onclick="openEditModal(<?= (int)$u['id'] ?>, '<?= htmlspecialchars(addslashes($u['name']), ENT_QUOTES, 'UTF-8') ?>', '<?= htmlspecialchars(addslashes($u['email']), ENT_QUOTES, 'UTF-8') ?>')"
                                            title="Edit name and email"
                                        >
                                            ✏️ Edit
                                        </button>
                                    <?php endif; ?>

                                </div>
                                <!-- End actions-cell -->
                            </td>

                        </tr>
                        <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <!-- End table-responsive -->

        </div>
    </div>
    <!-- End Section 2 -->

    <!-- ============================================================
         SECTION 3 — DELETED USERS TRASH (Admin only)
    ============================================================ -->
    <div style="background:#fff; border-radius:12px; box-shadow:0 1px 4px rgba(0,0,0,0.07); padding:28px 32px; margin-top:28px;">

        <!-- Section header -->
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:6px;">
            <span style="font-size:20px;">🗑️</span>
            <h2 style="margin:0; font-size:17px; font-weight:600; color:#1E293B;">Deleted Users</h2>
            <span style="
                background:#FEF2F2; color:#EF4444; font-size:12px; font-weight:600;
                padding:2px 10px; border-radius:20px; border:1px solid #FECACA;
            ">
                <?= count($deletedUsers) ?> in trash
            </span>
        </div>
        <p style="margin:0 0 20px; font-size:13px; color:#94A3B8;">Soft-deleted accounts — restore to re-activate. These users cannot log in.</p>

        <?php if (empty($deletedUsers)): ?>
            <div style="
                text-align:center; padding:40px 20px;
                background:#F8FAFC; border-radius:10px;
                border:1px dashed #E2E8F0; color:#94A3B8; font-size:14px;
            ">
                <div style="font-size:32px; margin-bottom:8px;">✅</div>
                No deleted users — trash is empty
            </div>

        <?php else: ?>
            <div class="table-responsive">
                <table class="table-mv" style="width:100%; border-collapse:collapse;">
                    <thead>
                        <tr>
                            <th style="padding:8px 10px; text-align:left; font-size:11px; font-weight:600; color:#64748B; text-transform:uppercase; letter-spacing:.04em; border-bottom:2px solid #E2E8F0;">Name</th>
                            <th style="padding:8px 10px; text-align:left; font-size:11px; font-weight:600; color:#64748B; text-transform:uppercase; letter-spacing:.04em; border-bottom:2px solid #E2E8F0;">Email</th>
                            <th style="padding:8px 10px; text-align:left; font-size:11px; font-weight:600; color:#64748B; text-transform:uppercase; letter-spacing:.04em; border-bottom:2px solid #E2E8F0;">Role</th>
                            <th style="padding:8px 10px; text-align:left; font-size:11px; font-weight:600; color:#64748B; text-transform:uppercase; letter-spacing:.04em; border-bottom:2px solid #E2E8F0;">Deleted</th>
                            <th style="padding:8px 10px; text-align:left; font-size:11px; font-weight:600; color:#64748B; text-transform:uppercase; letter-spacing:.04em; border-bottom:2px solid #E2E8F0;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($deletedUsers as $du): ?>
                        <tr style="border-bottom:1px solid #F1F5F9;">

                            <!-- Name -->
                            <td style="padding:7px 10px; font-size:13px; font-weight:500; color:#1E293B;">
                                <?= htmlspecialchars($du['name'], ENT_QUOTES, 'UTF-8') ?>
                            </td>

                            <!-- Email -->
                            <td style="padding:7px 10px; font-size:12px; color:#64748B;">
                                <?= htmlspecialchars($du['email'], ENT_QUOTES, 'UTF-8') ?>
                            </td>

                            <!-- Role badge -->
                            <td style="padding:7px 10px;">
                                <?php
                                $trashRoleColors = [
                                    'admin'        => ['bg' => '#EFF6FF', 'color' => '#1D4ED8', 'border' => '#BFDBFE'],
                                    'doctor'       => ['bg' => '#F0FDF4', 'color' => '#15803D', 'border' => '#BBF7D0'],
                                    'nurse'        => ['bg' => '#FFF7ED', 'color' => '#C2410C', 'border' => '#FED7AA'],
                                    'receptionist' => ['bg' => '#FAF5FF', 'color' => '#7E22CE', 'border' => '#E9D5FF'],
                                ];
                                $tc = $trashRoleColors[$du['role']] ?? ['bg' => '#F1F5F9', 'color' => '#475569', 'border' => '#E2E8F0'];
                                ?>
                                <span style="
                                    background:<?= $tc['bg'] ?>; color:<?= $tc['color'] ?>;
                                    border:1px solid <?= $tc['border'] ?>;
                                    padding:3px 10px; border-radius:20px;
                                    font-size:12px; font-weight:600;
                                ">
                                    <?= htmlspecialchars(ucfirst($du['role']), ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>

                            <!-- Deleted date -->
                            <td style="padding:7px 10px; font-size:12px; color:#94A3B8;">
                                <?= date('M j, Y g:i A', strtotime($du['deleted_at'])) ?>
                            </td>

                            <!-- Restore button -->
                            <td style="padding:7px 10px;">
                                <form method="POST" action="users.php" style="display:inline;">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="action" value="restore_user">
                                    <input type="hidden" name="target_id" value="<?= (int)$du['id'] ?>">
                                    <button
                                        type="submit"
                                        onclick="return confirm('Restore <?= htmlspecialchars(addslashes($du['name']), ENT_QUOTES, 'UTF-8') ?>?\n\nThis will re-activate their account and allow them to log in.')"
                                        style="
                                            padding:6px 14px; border:none; border-radius:7px;
                                            background:linear-gradient(135deg,#16A34A,#22C55E);
                                            color:#fff; font-size:12px; font-weight:600;
                                            font-family:inherit; cursor:pointer;
                                        "
                                        title="Restore this user account"
                                    >
                                        ♻️ Restore
                                    </button>
                                </form>
                            </td>

                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

    </div>
    <!-- End Section 3 -->

</main>
<!-- End Main Content -->

<!-- ============================================================
     SCRIPTS — Bootstrap CDN last, then page-specific JS
============================================================ -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    // ============================================================
    // MOBILE HAMBURGER SIDEBAR TOGGLE
    // ============================================================
    const hamburger = document.getElementById('hamburger');
    const sidebar   = document.getElementById('sidebar');
    const overlay   = document.getElementById('overlay');

    if (hamburger) {
        hamburger.addEventListener('click', function () {
            sidebar.classList.toggle('open');
            overlay.classList.toggle('show');
        });
    }

    if (overlay) {
        overlay.addEventListener('click', function () {
            sidebar.classList.remove('open');
            overlay.classList.remove('show');
        });
    }

    // ============================================================
    // SESSION TIMEOUT WARNING — exact spec JS (§5.4)
    // 9 minutes → alert
    // 10 minutes → auto redirect to logout
    // ============================================================
    setTimeout(function () {
        alert(
            '⚠️ Warning: Your session will expire in 1 minute due to inactivity.\n' +
            'Please save your work.'
        );
    }, 540000);

    setTimeout(function () {
        window.location.href = 'logout.php?reason=timeout';
    }, 600000);

    // ============================================================
    // SEARCH + ROLE FILTER
    // ============================================================
    let activeRole = 'all';

    function filterUsers() {
        const search = document.getElementById('userSearch').value.toLowerCase().trim();
        const rows   = document.querySelectorAll('.table-mv tbody tr');
        let visible  = 0;

        rows.forEach(function (row) {
            const nameEl  = row.querySelector('.user-name-cell');
            const emailEl = row.querySelector('.user-email-cell');
            const roleEl  = row.querySelector('[data-role]');

            if (!nameEl) return; // skip empty-state row

            const name  = nameEl.textContent.toLowerCase();
            const email = emailEl ? emailEl.textContent.toLowerCase() : '';
            const role  = roleEl ? roleEl.dataset.role : '';

            const matchSearch = (name.includes(search) || email.includes(search));
            const matchRole   = (activeRole === 'all' || role === activeRole);

            if (matchSearch && matchRole) {
                row.style.display = '';
                visible++;
            } else {
                row.style.display = 'none';
            }
        });

        const countEl = document.getElementById('userCount');
        if (countEl) countEl.textContent = visible;
    }

    function setRoleFilter(role, btn) {
        activeRole = role;
        document.querySelectorAll('.role-filter-btn').forEach(function (b) {
            b.classList.remove('active');
        });
        btn.classList.add('active');
        filterUsers();
    }

    // ============================================================
    // ROLE CHANGE — confirm before submitting dropdown
    // Fires on the select's onchange, gives user a chance to cancel
    // ============================================================
    document.querySelectorAll('.role-select-inline').forEach(function (select) {
        // Store the original value so we can revert on cancel
        select.dataset.original = select.value;

        select.addEventListener('change', function () {
            const name      = this.closest('tr').querySelector('.user-name-cell').textContent.trim();
            const newRole   = this.options[this.selectedIndex].text;
            const confirmed = confirm(
                'Change role for ' + name + ' to ' + newRole + '?\n\n' +
                'This will immediately update their access permissions.'
            );
            if (!confirmed) {
                // Revert to original value — do NOT submit
                this.value = this.dataset.original;
                return;
            }
            this.form.submit();
        });

        // Remove the onchange attribute — JS handler above handles it
        select.removeAttribute('onchange');
    });
</script>

<!-- ============================================================
     EDIT USER MODAL
============================================================ -->
<div id="editUserModal" style="
    display:none; position:fixed; inset:0; z-index:9999;
    background:rgba(0,0,0,0.45); align-items:center; justify-content:center;
">
    <div style="
        background:#fff; border-radius:12px; padding:32px 36px;
        width:100%; max-width:440px; box-shadow:0 8px 32px rgba(0,0,0,0.18);
        position:relative;
    ">
        <h3 style="margin:0 0 6px; color:#1E293B; font-size:18px; font-weight:600;">✏️ Edit User Info</h3>
        <p style="margin:0 0 24px; color:#94A3B8; font-size:13px;">Update name and email for this account.</p>

        <form method="POST" action="users.php" id="editUserForm">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="action" value="edit_user">
            <input type="hidden" name="target_id" id="editTargetId" value="">

            <div style="margin-bottom:16px;">
                <label style="display:block; font-size:13px; font-weight:500; color:#1E293B; margin-bottom:6px;">Full Name</label>
                <input
                    type="text"
                    name="new_name"
                    id="editName"
                    maxlength="100"
                    required
                    style="width:100%; border:1px solid #E2E8F0; border-radius:8px;
                           padding:10px 14px; font-size:14px; font-family:inherit;
                           color:#1E293B; background:#F8FAFC; box-sizing:border-box;"
                >
            </div>

            <div style="margin-bottom:24px;">
                <label style="display:block; font-size:13px; font-weight:500; color:#1E293B; margin-bottom:6px;">Email Address</label>
                <input
                    type="email"
                    name="new_email"
                    id="editEmail"
                    maxlength="150"
                    required
                    style="width:100%; border:1px solid #E2E8F0; border-radius:8px;
                           padding:10px 14px; font-size:14px; font-family:inherit;
                           color:#1E293B; background:#F8FAFC; box-sizing:border-box;"
                >
            </div>

            <div style="display:flex; gap:10px; justify-content:flex-end;">
                <button
                    type="button"
                    onclick="closeEditModal()"
                    style="padding:10px 20px; border:1px solid #E2E8F0; border-radius:8px;
                           background:#F8FAFC; color:#475569; font-size:14px;
                           font-family:inherit; cursor:pointer;"
                >
                    Cancel
                </button>
                <button
                    type="submit"
                    style="padding:10px 24px; border:none; border-radius:8px;
                           background:linear-gradient(135deg,#1E40AF,#2563EB);
                           color:#fff; font-size:14px; font-weight:600;
                           font-family:inherit; cursor:pointer;"
                >
                    Save Changes
                </button>
            </div>
        </form>

        <!-- Delete User — separate form, shown only when target is not the logged-in admin -->
        <form method="POST" action="users.php" id="deleteUserForm" style="margin-top:16px; padding-top:16px; border-top:1px solid #F1F5F9;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="action" value="soft_delete_user">
            <input type="hidden" name="target_id" id="deleteTargetId" value="">
            <button
                type="submit"
                id="deleteUserBtn"
                onclick="return confirm('Delete this user?\n\nThey will be moved to trash and cannot log in. You can restore them later.')"
                style="
                    width:100%; padding:10px; border:none; border-radius:8px;
                    background:#EF4444; color:#fff; font-size:14px; font-weight:600;
                    font-family:inherit; cursor:pointer;
                "
                title="Soft-delete this user account"
            >
                🗑️ Delete User
            </button>
        </form>

        <!-- Close X -->
        <button
            onclick="closeEditModal()"
            style="position:absolute; top:14px; right:16px; background:none;
                   border:none; font-size:20px; color:#94A3B8; cursor:pointer; line-height:1;"
            title="Close"
        >&#x2715;</button>
    </div>
</div>

<script>
    // Session user id — used to hide Delete button on own row
    const SESSION_USER_ID = <?= (int)$userId ?>;

    function openEditModal(id, name, email) {
        document.getElementById('editTargetId').value  = id;
        document.getElementById('deleteTargetId').value = id;
        document.getElementById('editName').value      = name;
        document.getElementById('editEmail').value     = email;

        // Hide Delete button if admin is editing their own account
        const deleteForm = document.getElementById('deleteUserForm');
        if (parseInt(id) === SESSION_USER_ID) {
            deleteForm.style.display = 'none';
        } else {
            deleteForm.style.display = 'block';
        }

        document.getElementById('editUserModal').style.display = 'flex';
    }

    function closeEditModal() {
        document.getElementById('editUserModal').style.display = 'none';
    }

    // Close modal if clicking the dark backdrop
    document.getElementById('editUserModal').addEventListener('click', function (e) {
        if (e.target === this) closeEditModal();
    });
</script>

</body>
</html>