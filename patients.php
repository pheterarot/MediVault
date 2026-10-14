<?php
// ============================================================
// MEDIVAULT — patients.php
// Purpose:  Patient records management — view, add, edit,
//           delete, print — with full role-based enforcement
// Layout:   Full sidebar (identical to dashboard.php)
// Access:   All 4 roles (different permissions per role)
//
// Role matrix:
//   Admin + Doctor  → view table, add, edit, delete, print
//   Nurse           → view table only (POST blocked server-side)
//   Receptionist    → add form only (table hidden + blocked)
//
// Security:
//   CSRF on every POST (verifyCsrf())
//   Server-side role checks on every action (not just UI hiding)
//   Prepared statements throughout (no SQL concatenation)
//   XSS prevention via clean() on all input/output
//   Rapid access detection (10+ in 60s → log + alert admin)
//   All actions logged to activity_logs
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';
require 'includes/mailer.php'; // needed so sendSuspiciousAlert() is
                                // available for auth.php IP mismatch check

// ============================================================
// ACCESS CONTROL — all 4 roles allowed (enforced per-action below)
// ============================================================
requireRole(['admin', 'doctor', 'nurse', 'receptionist']);

$userId   = $_SESSION['user_id'];
$userName = $_SESSION['user_name'];
$userRole = $_SESSION['user_role'];
$ip       = getUserIP();

// ============================================================
// PRINT MODE — early exit, render clean print view
// Triggered by: patients.php?print=1&id={id}
// Session and role still validated (requireRole ran above)
// ============================================================
if (isset($_GET['print']) && $_GET['print'] == '1' && isset($_GET['id'])) {

    // Only Admin and Doctor may print
    if (!in_array($userRole, ['admin', 'doctor'])) {
        header('Location: patients.php');
        exit;
    }

    $printId = (int)$_GET['id'];

    $stmt = $conn->prepare(
        "SELECT p.*, u.name AS added_by_name
         FROM patients p
         LEFT JOIN users u ON u.id = p.created_by
         WHERE p.id = ? AND p.deleted_at IS NULL"
    );
    $stmt->bind_param("i", $printId);
    $stmt->execute();
    $printPatient = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$printPatient) {
        header('Location: patients.php');
        exit;
    }

    // Log print action
    logActivity(
        $conn,
        $userId,
        "Printed patient record: " . $printPatient['name'],
        $ip
    );
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MediVault — Patient Record: <?= htmlspecialchars($printPatient['name'], ENT_QUOTES, 'UTF-8') ?></title>
        <link rel="icon" href="assets/images/favicon.ico">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Poppins', sans-serif;
                background: #F8FAFC;
                color: #1E293B;
                font-size: 14px;
                padding: 40px;
            }
            .print-wrapper {
                max-width: 680px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                overflow: hidden;
            }
            .print-header {
                background: linear-gradient(135deg, #1E40AF, #2563EB);
                padding: 28px 32px;
                display: flex;
                align-items: center;
                gap: 14px;
            }
            .print-header h1 {
                color: #ffffff;
                font-size: 22px;
                font-weight: 700;
                margin: 0;
                letter-spacing: 1px;
            }
            .print-header p {
                color: #BAE6FD;
                font-size: 12px;
                margin: 4px 0 0;
            }
            .print-body {
                padding: 32px;
            }
            .print-title {
                font-size: 18px;
                font-weight: 700;
                color: #1E293B;
                margin-bottom: 6px;
            }
            .print-subtitle {
                font-size: 12px;
                color: #94A3B8;
                margin-bottom: 28px;
                padding-bottom: 16px;
                border-bottom: 1px solid #E2E8F0;
            }
            .print-field {
                margin-bottom: 20px;
            }
            .print-field label {
                display: block;
                font-size: 11px;
                font-weight: 600;
                color: #94A3B8;
                text-transform: uppercase;
                letter-spacing: 0.6px;
                margin-bottom: 5px;
            }
            .print-field .value {
                font-size: 14px;
                color: #1E293B;
                font-weight: 500;
                background: #F8FAFC;
                border: 1px solid #E2E8F0;
                border-radius: 8px;
                padding: 10px 14px;
                line-height: 1.5;
            }
            .print-grid {
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 16px;
                margin-bottom: 20px;
            }
            .gender-badge {
                display: inline-block;
                padding: 4px 14px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                background: #EFF6FF;
                color: #2563EB;
            }
            .print-footer {
                background: #F1F5F9;
                padding: 16px 32px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                font-size: 11px;
                color: #94A3B8;
            }
            .no-print-btn {
                margin: 20px auto;
                max-width: 680px;
                text-align: center;
            }
            .no-print-btn button {
                background: #2563EB;
                color: white;
                border: none;
                padding: 10px 28px;
                border-radius: 8px;
                font-family: 'Poppins', sans-serif;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                margin-right: 8px;
                transition: background 0.2s;
            }
            .no-print-btn button:hover { background: #1E40AF; }
            .no-print-btn a {
                color: #94A3B8;
                font-size: 13px;
                text-decoration: none;
                font-weight: 500;
            }
            .no-print-btn a:hover { color: #1E293B; }
            @media print {
                body { background: white; padding: 0; }
                .print-wrapper { box-shadow: none; border-radius: 0; }
                .no-print-btn { display: none; }
            }
        </style>
    </head>
    <body>

        <div class="no-print-btn">
            <button onclick="window.print()">🖨️ Print / Save PDF</button>
            <a href="patients.php">← Back to Patients</a>
        </div>

        <div class="print-wrapper">
            <div class="print-header">
                <div>
                    <h1>🏥 MediVault</h1>
                    <p>Securing Patient Records. Protecting Lives.</p>
                </div>
            </div>

            <div class="print-body">
                <p class="print-title">Patient Medical Record</p>
                <p class="print-subtitle">
                    Record ID: #<?= (int)$printPatient['id'] ?> &nbsp;|&nbsp;
                    Printed by: <?= htmlspecialchars($userName, ENT_QUOTES, 'UTF-8') ?> (<?= htmlspecialchars($userRole, ENT_QUOTES, 'UTF-8') ?>) &nbsp;|&nbsp;
                    <?= date('F j, Y \a\t h:i A') ?>
                </p>

                <div class="print-grid">
                    <div class="print-field">
                        <label>Patient Name</label>
                        <div class="value"><?= htmlspecialchars($printPatient['name'], ENT_QUOTES, 'UTF-8') ?></div>
                    </div>
                    <div class="print-field">
                        <label>Age</label>
                        <div class="value"><?= (int)$printPatient['age'] ?> years old</div>
                    </div>
                    <div class="print-field">
                        <label>Gender</label>
                        <div class="value">
                            <span class="gender-badge"><?= htmlspecialchars($printPatient['gender'], ENT_QUOTES, 'UTF-8') ?></span>
                        </div>
                    </div>
                </div>

                <div class="print-field">
                    <label>Diagnosis / Medical Notes</label>
                    <div class="value" style="min-height:80px;">
                        <?= nl2br(htmlspecialchars($printPatient['diagnosis'], ENT_QUOTES, 'UTF-8')) ?>
                    </div>
                </div>

                <div class="print-grid" style="margin-top:8px;">
                    <div class="print-field">
                        <label>Added By</label>
                        <div class="value"><?= htmlspecialchars($printPatient['added_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?></div>
                    </div>
                    <div class="print-field">
                        <label>Date Added</label>
                        <div class="value"><?= date('M j, Y', strtotime($printPatient['created_at'])) ?></div>
                    </div>
                    <div class="print-field">
                        <label>Last Updated</label>
                        <div class="value"><?= date('M j, Y', strtotime($printPatient['updated_at'])) ?></div>
                    </div>
                </div>
            </div>

            <div class="print-footer">
                <span>MediVault Hospital Patient Records Security System</span>
                <span>CONFIDENTIAL — Authorized Personnel Only</span>
            </div>
        </div>

        <script>
            // Auto-trigger print dialog on load
            window.addEventListener('load', function() {
                window.print();
            });
        </script>
    </body>
    </html>
    <?php
    exit;
}
// ============================================================
// END PRINT MODE
// ============================================================


// ============================================================
// POST HANDLER — process all form submissions
// Order: CSRF → role check → validate → DB → log → redirect
// ============================================================
$successMsg = '';
$errorMsg   = '';

// Carry flash messages across redirect
if (isset($_GET['success'])) $successMsg = htmlspecialchars($_GET['success'], ENT_QUOTES, 'UTF-8');
if (isset($_GET['error']))   $errorMsg   = htmlspecialchars($_GET['error'],   ENT_QUOTES, 'UTF-8');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // --- CSRF check — must pass before anything else ---
    verifyCsrf();

    $action = $_POST['action'] ?? '';

    // --------------------------------------------------------
    // ACTION: ADD PATIENT
    // Allowed: Admin, Doctor, Receptionist
    // Blocked: Nurse (server-side)
    // --------------------------------------------------------
    if ($action === 'add_patient') {

        // Server-side role enforcement
        if ($userRole === 'nurse') {
            http_response_code(403);
            logSuspicious(
                $conn, $userId,
                "Unauthorized POST attempt on patients.php",
                $ip,
                "Nurse role attempted add_patient action"
            );
            header('Location: patients.php?error=Access+denied');
            exit;
        }

        // Sanitize and validate inputs
        $name      = sanitizeForDb($_POST['name']      ?? '');
        $age       = (int)($_POST['age']               ?? 0);
        $gender    = sanitizeForDb($_POST['gender']    ?? '');
        $diagnosis = sanitizeForDb($_POST['diagnosis'] ?? '');

        $validGenders = ['Male', 'Female', 'Other'];

        if ($name === '') {
            header('Location: patients.php?error=Patient+name+is+required');
            exit;
        }
        if ($age < 0 || $age > 150) {
            header('Location: patients.php?error=Please+enter+a+valid+age');
            exit;
        }
        if (!in_array($gender, $validGenders)) {
            header('Location: patients.php?error=Please+select+a+valid+gender');
            exit;
        }
        if ($diagnosis === '') {
            header('Location: patients.php?error=Diagnosis+is+required');
            exit;
        }

        // Insert using prepared statement — no raw SQL concatenation
        $stmt = $conn->prepare(
            "INSERT INTO patients (name, age, gender, diagnosis, created_by)
             VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->bind_param("sissi", $name, $age, $gender, $diagnosis, $userId);
        $stmt->execute();
        $stmt->close();

        // Log the action
        logActivity($conn, $userId, "Added patient: " . $name, $ip);

        header('Location: patients.php?success=Patient+added+successfully');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: EDIT PATIENT
    // Allowed: Admin, Doctor
    // Blocked: Nurse, Receptionist (server-side)
    // --------------------------------------------------------
    if ($action === 'edit_patient') {

        // Server-side role enforcement
        if (!in_array($userRole, ['admin', 'doctor'])) {
            http_response_code(403);
            logSuspicious(
                $conn, $userId,
                "Unauthorized POST attempt on patients.php",
                $ip,
                "Role '{$userRole}' attempted edit_patient action"
            );
            header('Location: patients.php?error=Access+denied');
            exit;
        }

        $patientId = (int)($_POST['patient_id'] ?? 0);
        $name      = sanitizeForDb($_POST['name']        ?? '');
        $age       = (int)($_POST['age']                 ?? 0);
        $gender    = sanitizeForDb($_POST['gender']      ?? '');
        $diagnosis = sanitizeForDb($_POST['diagnosis']   ?? '');

        $validGenders = ['Male', 'Female', 'Other'];

        if ($patientId <= 0) {
            header('Location: patients.php?error=Invalid+patient+ID');
            exit;
        }
        if ($name === '') {
            header('Location: patients.php?error=Patient+name+is+required');
            exit;
        }
        if ($age < 0 || $age > 150) {
            header('Location: patients.php?error=Please+enter+a+valid+age');
            exit;
        }
        if (!in_array($gender, $validGenders)) {
            header('Location: patients.php?error=Please+select+a+valid+gender');
            exit;
        }
        if ($diagnosis === '') {
            header('Location: patients.php?error=Diagnosis+is+required');
            exit;
        }

        // Verify patient exists and is not soft-deleted
        $check = $conn->prepare(
            "SELECT id FROM patients WHERE id = ? AND deleted_at IS NULL"
        );
        $check->bind_param("i", $patientId);
        $check->execute();
        $exists = $check->get_result()->fetch_assoc();
        $check->close();

        if (!$exists) {
            header('Location: patients.php?error=Patient+not+found');
            exit;
        }

        $stmt = $conn->prepare(
            "UPDATE patients
             SET name = ?, age = ?, gender = ?, diagnosis = ?, updated_by = ?
             WHERE id = ?"
        );
        $stmt->bind_param("sisisi", $name, $age, $gender, $diagnosis, $userId, $patientId);
        $stmt->execute();
        $stmt->close();

        logActivity($conn, $userId, "Edited patient: " . $name, $ip);

        header('Location: patients.php?success=Patient+updated+successfully');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: DELETE PATIENT
    // Allowed: Admin, Doctor
    // Blocked: Nurse, Receptionist (server-side)
    // --------------------------------------------------------
    if ($action === 'delete_patient') {

        // Server-side role enforcement
        if (!in_array($userRole, ['admin', 'doctor'])) {
            http_response_code(403);
            logSuspicious(
                $conn, $userId,
                "Unauthorized POST attempt on patients.php",
                $ip,
                "Role '{$userRole}' attempted delete_patient action"
            );
            header('Location: patients.php?error=Access+denied');
            exit;
        }

        $patientId = (int)($_POST['patient_id'] ?? 0);

        if ($patientId <= 0) {
            header('Location: patients.php?error=Invalid+patient+ID');
            exit;
        }

        // Fetch name for log message — only active (non-trashed) records
        $stmt = $conn->prepare(
            "SELECT name FROM patients WHERE id = ? AND deleted_at IS NULL"
        );
        $stmt->bind_param("i", $patientId);
        $stmt->execute();
        $toDelete = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$toDelete) {
            header('Location: patients.php?error=Patient+not+found');
            exit;
        }

        $deletedName = $toDelete['name'];

        // Soft delete — never hard-delete; set deleted_at + deleted_by for audit trail
        $stmt = $conn->prepare(
            "UPDATE patients SET deleted_at = NOW(), deleted_by = ? WHERE id = ?"
        );
        $stmt->bind_param("ii", $userId, $patientId);
        $stmt->execute();
        $stmt->close();

        logActivity($conn, $userId, "Soft-deleted patient: " . $deletedName, $ip);

        header('Location: patients.php?success=Patient+moved+to+trash+successfully');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: RESTORE PATIENT (undo soft delete)
    // Allowed: Admin ONLY
    // --------------------------------------------------------
    if ($action === 'restore_patient') {

        // Server-side role enforcement — Admin only
        if ($userRole !== 'admin') {
            http_response_code(403);
            logSuspicious(
                $conn, $userId,
                "Unauthorized POST attempt on patients.php",
                $ip,
                "Role '{$userRole}' attempted restore_patient action"
            );
            header('Location: patients.php?error=Access+denied');
            exit;
        }

        $patientId = (int)($_POST['patient_id'] ?? 0);

        if ($patientId <= 0) {
            header('Location: patients.php?error=Invalid+patient+ID');
            exit;
        }

        // Fetch name for log message — must be a currently-deleted record
        $stmt = $conn->prepare(
            "SELECT name FROM patients WHERE id = ? AND deleted_at IS NOT NULL"
        );
        $stmt->bind_param("i", $patientId);
        $stmt->execute();
        $toRestore = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$toRestore) {
            header('Location: patients.php?error=Patient+not+found+in+trash');
            exit;
        }

        $restoredName = $toRestore['name'];

        // Clear soft-delete flags — row becomes active again
        $stmt = $conn->prepare(
            "UPDATE patients SET deleted_at = NULL, deleted_by = NULL WHERE id = ?"
        );
        $stmt->bind_param("i", $patientId);
        $stmt->execute();
        $stmt->close();

        logActivity($conn, $userId, "Restored patient from trash: " . $restoredName, $ip);

        header('Location: patients.php?success=Patient+restored+successfully');
        exit;
    }

    // Unknown action — reject silently
    header('Location: patients.php');
    exit;
}
// ============================================================
// END POST HANDLER
// ============================================================


// ============================================================
// DATA FETCH — patients table with JOIN to users for "Added By"
// Receptionist sees NO table — skip fetch entirely
// ============================================================
$patients     = [];
$totalPatients = 0;
$totalPages    = 1;
$currentPage   = max(1, (int)($_GET['page'] ?? 1));
$perPage       = 10;
$offset        = ($currentPage - 1) * $perPage;

if ($userRole !== 'receptionist') {

    // Total count for pagination — exclude soft-deleted rows
    $stmt = $conn->prepare("SELECT COUNT(*) AS total FROM patients WHERE deleted_at IS NULL");
    $stmt->execute();
    $totalPatients = (int)$stmt->get_result()->fetch_assoc()['total'];
    $stmt->close();

    $totalPages = max(1, (int)ceil($totalPatients / $perPage));
    if ($currentPage > $totalPages) $currentPage = $totalPages;
    $offset = ($currentPage - 1) * $perPage;

    // Fetch paginated patients with added_by name — exclude soft-deleted rows
    $stmt = $conn->prepare(
        "SELECT p.id, p.name, p.age, p.gender, p.diagnosis,
                p.created_at, u.name AS added_by_name
         FROM patients p
         LEFT JOIN users u ON u.id = p.created_by
         WHERE p.deleted_at IS NULL
         ORDER BY p.created_at DESC
         LIMIT ? OFFSET ?"
    );
    $stmt->bind_param("ii", $perPage, $offset);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $patients[] = $row;
    }
    $stmt->close();
}

// ============================================================
// TRASH FETCH — deleted patients for Admin trash section
// Only fetched for Admin; all other roles skip entirely
// ============================================================
$trashedPatients = [];
if ($userRole === 'admin') {
    $stmt = $conn->prepare(
        "SELECT p.id, p.name, p.age, p.gender, p.diagnosis,
                p.deleted_at, del.name AS deleted_by_name
         FROM patients p
         LEFT JOIN users del ON del.id = p.deleted_by
         WHERE p.deleted_at IS NOT NULL
         ORDER BY p.deleted_at DESC"
    );
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $trashedPatients[] = $row;
    }
    $stmt->close();
}

// ============================================================
// LOG PAGE VIEW — must happen before rapid access check
// so this visit is counted in the 60-second window
// ============================================================
logActivity($conn, $userId, "Viewed patient records", $ip);

// ============================================================
// RAPID ACCESS CHECK — spec §5.4
// Count "patient record" logs for this user in last 60 seconds
// If 10+: log suspicious + alert admin
// Only meaningful for roles that actually view records
// ============================================================
if ($userRole !== 'receptionist') {
    $stmt = $conn->prepare(
        "SELECT COUNT(*) AS count
         FROM activity_logs
         WHERE user_id = ?
         AND action LIKE '%patient record%'
         AND timestamp > DATE_SUB(NOW(), INTERVAL 1 MINUTE)"
    );
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $rapidCount = (int)$stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();

    if ($rapidCount >= 10) {
        // Only log once per minute — check if we already flagged recently
        $flagCheck = $conn->prepare(
            "SELECT COUNT(*) AS already_flagged
             FROM activity_logs
             WHERE user_id = ?
             AND action = 'Rapid patient record access detected'
             AND timestamp > DATE_SUB(NOW(), INTERVAL 1 MINUTE)"
        );
        $flagCheck->bind_param("i", $userId);
        $flagCheck->execute();
        $alreadyFlagged = (int)$flagCheck->get_result()->fetch_assoc()['already_flagged'];
        $flagCheck->close();

        if ($alreadyFlagged === 0) {
            logSuspicious(
                $conn,
                $userId,
                "Rapid patient record access detected",
                $ip,
                "Accessed {$rapidCount} records in under 60 seconds"
            );

            // Alert admin via email
            if (function_exists('sendSuspiciousAlert')) {
                $adminEmail = getAdminEmail($conn);
                if ($adminEmail) {
                    sendSuspiciousAlert(
                        $adminEmail,
                        $userName,
                        "Rapid record access: {$rapidCount} records in 60 seconds",
                        $ip,
                        date('Y-m-d H:i:s')
                    );
                }
            }
        }
    }
}
// ============================================================
// END PHP LOGIC — begin HTML output
// ============================================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Patients</title>
    <link rel="icon" href="assets/images/favicon.ico">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* ======================================================
           BASE RESET — identical to dashboard.php
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
           SIDEBAR — exact copy from dashboard.php
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
           TOPBAR — identical to dashboard.php
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
           MAIN CONTENT AREA — identical to dashboard.php
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
           CARDS — identical base to dashboard.php
        ====================================================== */
        .section-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            background: #ffffff;
            margin-bottom: 24px;
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

        .section-card .card-header-mv .header-actions {
            margin-left: auto;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-card .card-body-mv {
            padding: 20px;
        }

        /* ======================================================
           FLASH MESSAGES
        ====================================================== */
        .alert-mv {
            padding: 12px 18px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .alert-success {
            background: #F0FDF4;
            border: 1px solid #86EFAC;
            color: #166534;
        }

        .alert-error {
            background: #FEF2F2;
            border: 1px solid #FECACA;
            color: #991B1B;
        }

        /* ======================================================
           VIEW-ONLY NOTICE — Nurse role
        ====================================================== */
        .view-only-notice {
            background: #EFF6FF;
            border: 1px solid #BFDBFE;
            border-radius: 8px;
            padding: 12px 18px;
            font-size: 13px;
            color: #1E40AF;
            font-weight: 500;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* ======================================================
           SEARCH BAR
        ====================================================== */
        .search-bar-wrapper {
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .search-input {
            width: 100%;
            max-width: 340px;
            padding: 9px 14px 9px 36px;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-size: 13px;
            font-family: 'Poppins', sans-serif;
            color: #1E293B;
            background: #F8FAFC url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='%2394A3B8' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.099zm-5.242 1.656a5.5 5.5 0 1 1 0-11 5.5 5.5 0 0 1 0 11z'/%3E%3C/svg%3E") no-repeat 12px center;
            outline: none;
            transition: border-color 0.2s;
        }

        .search-input:focus {
            border-color: #2563EB;
            background-color: #ffffff;
        }

        .search-count {
            font-size: 12px;
            color: #94A3B8;
            white-space: nowrap;
        }

        /* ======================================================
           PATIENTS TABLE
        ====================================================== */
        .patients-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .patients-table thead th {
            background: #F8FAFC;
            color: #64748B;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 10px 14px;
            border-bottom: 2px solid #E2E8F0;
            white-space: nowrap;
        }

        .patients-table tbody tr {
            border-bottom: 1px solid #F1F5F9;
            transition: background 0.15s;
        }

        .patients-table tbody tr:hover {
            background: #F8FAFC;
        }

        .patients-table tbody tr:last-child {
            border-bottom: none;
        }

        .patients-table tbody td {
            padding: 11px 14px;
            color: #1E293B;
            vertical-align: middle;
        }

        .patient-name {
            font-weight: 600;
            color: #1E293B;
        }

        .patient-diagnosis {
            color: #475569;
            max-width: 220px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .gender-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }

        .gender-male   { background: #EFF6FF; color: #2563EB; }
        .gender-female { background: #FDF4FF; color: #9333EA; }
        .gender-other  { background: #F0FDF4; color: #16A34A; }

        .id-badge {
            display: inline-block;
            background: #F1F5F9;
            color: #64748B;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            font-family: monospace;
        }

        /* ======================================================
           ACTION BUTTONS in table
        ====================================================== */
        .btn-action {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 5px 11px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            font-family: 'Poppins', sans-serif;
            text-decoration: none;
            border: none;
            cursor: pointer;
            transition: all 0.15s;
            white-space: nowrap;
        }

        .btn-edit {
            background: #EFF6FF;
            color: #2563EB;
        }
        .btn-edit:hover {
            background: #2563EB;
            color: #ffffff;
        }

        .btn-delete {
            background: #FEF2F2;
            color: #EF4444;
        }
        .btn-delete:hover {
            background: #EF4444;
            color: #ffffff;
        }

        .btn-print {
            background: #F0FDF4;
            color: #16A34A;
        }
        .btn-print:hover {
            background: #22C55E;
            color: #ffffff;
        }

        .actions-cell {
            display: flex;
            align-items: center;
            gap: 5px;
            flex-wrap: nowrap;
        }

        /* ======================================================
           NO RECORDS STATE
        ====================================================== */
        .no-records {
            text-align: center;
            padding: 40px 20px;
            color: #94A3B8;
        }

        .no-records-icon {
            font-size: 36px;
            display: block;
            margin-bottom: 10px;
        }

        .no-records p {
            font-size: 13px;
            margin: 0;
        }

        /* ======================================================
           PAGINATION
        ====================================================== */
        .pagination-wrapper {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-top: 16px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .pagination-info {
            font-size: 12px;
            color: #94A3B8;
        }

        .pagination-links {
            display: flex;
            gap: 4px;
            flex-wrap: wrap;
        }

        .page-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 32px;
            height: 32px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            border: 1px solid #E2E8F0;
            color: #64748B;
            background: #ffffff;
            transition: all 0.15s;
        }

        .page-btn:hover {
            background: #EFF6FF;
            border-color: #2563EB;
            color: #2563EB;
        }

        .page-btn.active {
            background: #2563EB;
            border-color: #2563EB;
            color: #ffffff;
        }

        .page-btn.disabled {
            opacity: 0.4;
            pointer-events: none;
        }

        /* ======================================================
           ADD PATIENT FORM CARD
        ====================================================== */
        .form-label-mv {
            font-size: 12px;
            font-weight: 600;
            color: #475569;
            margin-bottom: 5px;
            display: block;
        }

        .form-control-mv {
            width: 100%;
            padding: 9px 13px;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-size: 13px;
            font-family: 'Poppins', sans-serif;
            color: #1E293B;
            background: #ffffff;
            transition: border-color 0.2s, box-shadow 0.2s;
            outline: none;
        }

        .form-control-mv:focus {
            border-color: #2563EB;
            box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
        }

        textarea.form-control-mv {
            resize: vertical;
            min-height: 80px;
        }

        .btn-submit {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 10px 24px;
            font-size: 13px;
            font-weight: 600;
            font-family: 'Poppins', sans-serif;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-submit:hover {
            background: linear-gradient(135deg, #1E3A8A, #1E40AF);
            transform: translateY(-1px);
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 16px;
            margin-bottom: 16px;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .required-star {
            color: #EF4444;
            margin-left: 2px;
        }

        /* ======================================================
           MODAL — Edit Patient (Bootstrap 5)
        ====================================================== */
        .modal-header-mv {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            padding: 16px 20px;
        }

        .modal-header-mv .modal-title {
            font-size: 15px;
            font-weight: 600;
            margin: 0;
        }

        .modal-header-mv .btn-close {
            filter: invert(1);
            opacity: 0.8;
        }

        .modal-body-mv {
            padding: 24px;
        }

        .modal-footer-mv {
            padding: 14px 24px;
            border-top: 1px solid #E2E8F0;
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }

        .btn-cancel-mv {
            background: #F1F5F9;
            color: #64748B;
            border: none;
            border-radius: 8px;
            padding: 9px 20px;
            font-size: 13px;
            font-weight: 500;
            font-family: 'Poppins', sans-serif;
            cursor: pointer;
            transition: background 0.15s;
        }

        .btn-cancel-mv:hover {
            background: #E2E8F0;
        }

        /* ======================================================
           MOBILE OVERLAY
        ====================================================== */
        #overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
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

            .form-row {
                grid-template-columns: 1fr;
            }

            .patients-table {
                font-size: 12px;
            }

            .patients-table thead th,
            .patients-table tbody td {
                padding: 8px 10px;
            }

            .patient-diagnosis {
                max-width: 120px;
            }

            .actions-cell {
                flex-direction: column;
                align-items: flex-start;
                gap: 3px;
            }
        }

        @media (min-width: 769px) {
            .hamburger {
                display: none !important;
            }
        }

        /* ======================================================
           SECTION SPACING
        ====================================================== */
        .section-gap {
            margin-bottom: 24px;
        }

        /* ======================================================
           HIDDEN DELETE FORMS — invisible, just submit targets
        ====================================================== */
        .delete-form {
            display: none;
        }

        /* ======================================================
           TABLE RESPONSIVE WRAPPER
        ====================================================== */
        .table-scroll {
            overflow-x: auto;
        }

        /* ======================================================
           TRASH SECTION — soft-deleted records (Admin only)
        ====================================================== */
        .trash-card .card-header-mv {
            background: linear-gradient(135deg, #991B1B, #EF4444);
        }

        .trash-empty {
            text-align: center;
            padding: 30px 20px;
            color: #94A3B8;
        }

        .trash-empty-icon {
            font-size: 30px;
            display: block;
            margin-bottom: 8px;
        }

        .trash-empty p {
            font-size: 13px;
            margin: 0;
        }

        .btn-restore {
            background: #F0FDF4;
            color: #16A34A;
        }

        .btn-restore:hover {
            background: #22C55E;
            color: #ffffff;
        }

        .deleted-date {
            color: #EF4444;
            font-size: 12px;
            white-space: nowrap;
        }

        .deleted-by-text {
            color: #94A3B8;
            font-size: 12px;
        }
    </style>
</head>
<body>

<!-- ============================================================
     MOBILE OVERLAY
============================================================ -->
<div id="overlay"></div>

<!-- ============================================================
     SIDEBAR — identical to dashboard.php, active on patients
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

        <!-- Patients — all roles — ACTIVE on this page -->
        <a href="patients.php" class="active">
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

        <!-- Users — ADMIN ONLY -->
        <?php if ($userRole === 'admin'): ?>
        <a href="users.php">
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
     TOPBAR — 60px fixed white bar
============================================================ -->
<div class="topbar">
    <button class="hamburger" id="hamburger" aria-label="Toggle navigation">&#9776;</button>
    <span class="topbar-title">👤 Patients</span>
    <div class="topbar-right">
        <span class="topbar-user">Welcome back, <?= htmlspecialchars($userName, ENT_QUOTES, 'UTF-8') ?></span>
        <span class="topbar-role-badge"><?= htmlspecialchars($userRole, ENT_QUOTES, 'UTF-8') ?></span>
    </div>
</div>

<!-- ============================================================
     MAIN CONTENT
============================================================ -->
<main class="main-content">

    <!-- Page Header -->
    <div class="page-header">
        <h2>Patient Records</h2>
        <p>
            <?php if ($userRole === 'nurse'): ?>
                View-only access — you can browse patient records
            <?php elseif ($userRole === 'receptionist'): ?>
                Register new patients into the system
            <?php else: ?>
                Manage and monitor all patient records — <?= date('l, F j, Y') ?>
            <?php endif; ?>
        </p>
    </div>

    <!-- ============================================================
         FLASH MESSAGES
    ============================================================ -->
    <?php if ($successMsg): ?>
    <div class="alert-mv alert-success">
        <span>✅</span> <?= $successMsg ?>
    </div>
    <?php endif; ?>

    <?php if ($errorMsg): ?>
    <div class="alert-mv alert-error">
        <span>❌</span> <?= $errorMsg ?>
    </div>
    <?php endif; ?>

    <!-- ============================================================
         NURSE VIEW-ONLY NOTICE
         Shown only to nurses, above the table
    ============================================================ -->
    <?php if ($userRole === 'nurse'): ?>
    <div class="view-only-notice">
        <span style="font-size:18px;">👁️</span>
        <span><strong>View Only Access</strong> — As a nurse, you can view all patient records but cannot add, edit, or delete entries.</span>
    </div>
    <?php endif; ?>


    <!-- ============================================================
         SECTION 1: PATIENT RECORDS TABLE
         Shown to: Admin, Doctor, Nurse
         Hidden from: Receptionist (not rendered in HTML at all)
    ============================================================ -->
    <?php if ($userRole !== 'receptionist'): ?>

    <div class="section-card section-gap">
        <div class="card-header-mv">
            <span>📋</span> All Patients
            <div class="header-actions">
                <span style="font-size:12px; font-weight:400; opacity:0.85;">
                    <?= number_format($totalPatients) ?> total record<?= $totalPatients !== 1 ? 's' : '' ?>
                </span>
            </div>
        </div>

        <div class="card-body-mv">

            <!-- Search Bar — filters rows live via JS -->
            <div class="search-bar-wrapper">
                <input
                    type="text"
                    id="patientSearch"
                    class="search-input"
                    placeholder="Search by name or diagnosis..."
                    oninput="filterPatients()"
                    autocomplete="off"
                >
                <span class="search-count" id="searchCount">
                    <?= count($patients) ?> of <?= number_format($totalPatients) ?> shown
                </span>
            </div>

            <!-- Table -->
            <div class="table-scroll">
                <table class="patients-table" id="patientsTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Age</th>
                            <th>Gender</th>
                            <th>Diagnosis</th>
                            <th>Added By</th>
                            <th>Date Added</th>
                            <?php if (in_array($userRole, ['admin', 'doctor'])): ?>
                            <th>Actions</th>
                            <?php endif; ?>
                        </tr>
                    </thead>
                    <tbody id="patientsTbody">
                        <?php if (empty($patients)): ?>
                        <tr id="noRecordsRow">
                            <td colspan="<?= in_array($userRole, ['admin', 'doctor']) ? '8' : '7' ?>">
                                <div class="no-records">
                                    <span class="no-records-icon">🏥</span>
                                    <p>No patient records found. <?= in_array($userRole, ['admin', 'doctor']) ? 'Add the first patient below.' : '' ?></p>
                                </div>
                            </td>
                        </tr>
                        <?php else: ?>
                        <?php foreach ($patients as $p): ?>
                        <tr
                            data-name="<?= htmlspecialchars(strtolower($p['name']), ENT_QUOTES, 'UTF-8') ?>"
                            data-diagnosis="<?= htmlspecialchars(strtolower($p['diagnosis']), ENT_QUOTES, 'UTF-8') ?>"
                        >
                            <td><span class="id-badge">#<?= (int)$p['id'] ?></span></td>
                            <td><span class="patient-name"><?= htmlspecialchars($p['name'], ENT_QUOTES, 'UTF-8') ?></span></td>
                            <td><?= (int)$p['age'] ?></td>
                            <td>
                                <?php
                                $genderClass = match($p['gender']) {
                                    'Male'   => 'gender-male',
                                    'Female' => 'gender-female',
                                    default  => 'gender-other',
                                };
                                ?>
                                <span class="gender-badge <?= $genderClass ?>">
                                    <?= htmlspecialchars($p['gender'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="patient-diagnosis" title="<?= htmlspecialchars($p['diagnosis'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= htmlspecialchars($p['diagnosis'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td style="color:#64748B; font-size:12px;">
                                <?= htmlspecialchars($p['added_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td style="color:#64748B; font-size:12px; white-space:nowrap;">
                                <?= date('M j, Y', strtotime($p['created_at'])) ?>
                            </td>

                            <?php if (in_array($userRole, ['admin', 'doctor'])): ?>
                            <td>
                                <div class="actions-cell">
                                    <!-- Edit button — triggers modal -->
                                    <button
                                        class="btn-action btn-edit"
                                        onclick="openEditModal(
                                            <?= (int)$p['id'] ?>,
                                            '<?= addslashes(htmlspecialchars($p['name'],      ENT_QUOTES, 'UTF-8')) ?>',
                                            <?= (int)$p['age'] ?>,
                                            '<?= addslashes(htmlspecialchars($p['gender'],    ENT_QUOTES, 'UTF-8')) ?>',
                                            '<?= addslashes(htmlspecialchars($p['diagnosis'], ENT_QUOTES, 'UTF-8')) ?>'
                                        )"
                                    >
                                        ✏️ Edit
                                    </button>

                                    <!-- Delete button — calls confirmDelete() -->
                                    <button
                                        class="btn-action btn-delete"
                                        onclick="confirmDelete(<?= (int)$p['id'] ?>, '<?= addslashes(htmlspecialchars($p['name'], ENT_QUOTES, 'UTF-8')) ?>')"
                                    >
                                        🗑️ Delete
                                    </button>

                                    <!-- Print button — opens new tab -->
                                    <a
                                        href="patients.php?print=1&id=<?= (int)$p['id'] ?>"
                                        target="_blank"
                                        class="btn-action btn-print"
                                    >
                                        🖨️ Print
                                    </a>

                                    <!-- Hidden delete form — submitted by confirmDelete() -->
                                    <form
                                        id="deleteForm_<?= (int)$p['id'] ?>"
                                        method="POST"
                                        action="patients.php"
                                        class="delete-form"
                                    >
                                        <input type="hidden" name="action"     value="delete_patient">
                                        <input type="hidden" name="patient_id" value="<?= (int)$p['id'] ?>">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                    </form>
                                </div>
                            </td>
                            <?php endif; ?>
                        </tr>
                        <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <!-- End Table -->

            <!-- No search results row (hidden by default, shown by JS) -->
            <div id="noSearchResults" style="display:none; text-align:center; padding:30px 20px; color:#94A3B8;">
                <span style="font-size:28px; display:block; margin-bottom:8px;">🔍</span>
                <p style="font-size:13px; margin:0;">No patients match your search. Try a different name or diagnosis.</p>
            </div>

            <!-- Pagination -->
            <?php if ($totalPatients > $perPage): ?>
            <div class="pagination-wrapper">
                <span class="pagination-info">
                    Showing <?= number_format(($offset + 1)) ?>–<?= number_format(min($offset + $perPage, $totalPatients)) ?> of <?= number_format($totalPatients) ?> patients
                </span>
                <div class="pagination-links">
                    <!-- Previous -->
                    <a href="patients.php?page=<?= max(1, $currentPage - 1) ?>"
                       class="page-btn <?= $currentPage <= 1 ? 'disabled' : '' ?>">‹</a>

                    <?php
                    // Show page buttons — max 7 visible at a time with ellipsis
                    $start = max(1, min($currentPage - 3, $totalPages - 6));
                    $end   = min($totalPages, max($currentPage + 3, 7));
                    for ($i = $start; $i <= $end; $i++):
                    ?>
                    <a href="patients.php?page=<?= $i ?>"
                       class="page-btn <?= $i === $currentPage ? 'active' : '' ?>"><?= $i ?></a>
                    <?php endfor; ?>

                    <!-- Next -->
                    <a href="patients.php?page=<?= min($totalPages, $currentPage + 1) ?>"
                       class="page-btn <?= $currentPage >= $totalPages ? 'disabled' : '' ?>">›</a>
                </div>
            </div>
            <?php endif; ?>

        </div>
        <!-- End card-body-mv -->
    </div>
    <!-- End Patients Table Card -->

    <?php endif; ?>
    <!-- End: Table shown to Admin/Doctor/Nurse -->


    <!-- ============================================================
         SECTION 2: ADD PATIENT FORM
         Shown to: Admin, Doctor, Receptionist
         Hidden from: Nurse (not rendered in HTML at all)
    ============================================================ -->
    <?php if ($userRole !== 'nurse'): ?>

    <div class="section-card section-gap">
        <div class="card-header-mv">
            <span>➕</span>
            <?= $userRole === 'receptionist' ? 'Register New Patient' : 'Add New Patient' ?>
        </div>

        <div class="card-body-mv">
            <form method="POST" action="patients.php" id="addPatientForm" novalidate>
                <input type="hidden" name="action"     value="add_patient">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                <!-- Row 1: Name / Age / Gender -->
                <div class="form-row">
                    <div>
                        <label class="form-label-mv" for="add_name">
                            Patient Name <span class="required-star">*</span>
                        </label>
                        <input
                            type="text"
                            id="add_name"
                            name="name"
                            class="form-control-mv"
                            placeholder="Full name"
                            maxlength="100"
                            required
                        >
                    </div>
                    <div>
                        <label class="form-label-mv" for="add_age">
                            Age <span class="required-star">*</span>
                        </label>
                        <input
                            type="number"
                            id="add_age"
                            name="age"
                            class="form-control-mv"
                            placeholder="e.g. 35"
                            min="0"
                            max="150"
                            required
                        >
                    </div>
                    <div>
                        <label class="form-label-mv" for="add_gender">
                            Gender <span class="required-star">*</span>
                        </label>
                        <select id="add_gender" name="gender" class="form-control-mv" required>
                            <option value="" disabled selected>Select gender</option>
                            <option value="Male">Male</option>
                            <option value="Female">Female</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>
                </div>

                <!-- Row 2: Diagnosis -->
                <div class="form-group">
                    <label class="form-label-mv" for="add_diagnosis">
                        Diagnosis / Medical Notes <span class="required-star">*</span>
                    </label>
                    <textarea
                        id="add_diagnosis"
                        name="diagnosis"
                        class="form-control-mv"
                        placeholder="Enter diagnosis, symptoms, or relevant medical notes..."
                        rows="3"
                        required
                    ></textarea>
                </div>

                <!-- Submit -->
                <div style="display:flex; align-items:center; gap:12px;">
                    <button type="submit" class="btn-submit">
                        ➕ Add Patient
                    </button>
                    <button type="reset" style="
                        background:none; border:none; color:#94A3B8;
                        font-size:13px; cursor:pointer; font-family:'Poppins',sans-serif;
                        font-weight:500; padding:0;
                    ">
                        Clear form
                    </button>
                </div>
            </form>
        </div>
    </div>
    <!-- End Add Patient Form -->

    <?php endif; ?>
    <!-- End: Form shown to Admin/Doctor/Receptionist -->


    <!-- ============================================================
         SECTION 3: TRASH — Soft-Deleted Patients
         Shown to: Admin ONLY
         Hidden from: Doctor, Nurse, Receptionist
    ============================================================ -->
    <?php if ($userRole === 'admin'): ?>

    <div class="section-card section-gap trash-card">
        <div class="card-header-mv">
            <span>🗑️</span> Patient Trash
            <div class="header-actions">
                <span style="font-size:12px; font-weight:400; opacity:0.85;">
                    <?= count($trashedPatients) ?> deleted record<?= count($trashedPatients) !== 1 ? 's' : '' ?>
                </span>
            </div>
        </div>

        <div class="card-body-mv">

            <?php if (empty($trashedPatients)): ?>
            <div class="trash-empty">
                <span class="trash-empty-icon">✅</span>
                <p>No deleted patients. The trash is empty.</p>
            </div>

            <?php else: ?>

            <div class="table-scroll">
                <table class="patients-table" id="trashTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Age</th>
                            <th>Gender</th>
                            <th>Diagnosis</th>
                            <th>Deleted By</th>
                            <th>Deleted Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($trashedPatients as $t): ?>
                        <tr>
                            <td><span class="id-badge">#<?= (int)$t['id'] ?></span></td>
                            <td>
                                <span class="patient-name" style="color:#94A3B8; text-decoration:line-through;">
                                    <?= htmlspecialchars($t['name'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td style="color:#94A3B8;"><?= (int)$t['age'] ?></td>
                            <td>
                                <?php
                                $genderClass = match($t['gender']) {
                                    'Male'   => 'gender-male',
                                    'Female' => 'gender-female',
                                    default  => 'gender-other',
                                };
                                ?>
                                <span class="gender-badge <?= $genderClass ?>" style="opacity:0.6;">
                                    <?= htmlspecialchars($t['gender'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="patient-diagnosis" style="color:#94A3B8;" title="<?= htmlspecialchars($t['diagnosis'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= htmlspecialchars($t['diagnosis'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td class="deleted-by-text">
                                <?= htmlspecialchars($t['deleted_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td class="deleted-date">
                                <?= date('M j, Y g:i A', strtotime($t['deleted_at'])) ?>
                            </td>
                            <td>
                                <div class="actions-cell">
                                    <!-- Restore button — calls confirmRestore() -->
                                    <button
                                        class="btn-action btn-restore"
                                        onclick="confirmRestore(<?= (int)$t['id'] ?>, '<?= addslashes(htmlspecialchars($t['name'], ENT_QUOTES, 'UTF-8')) ?>')"
                                    >
                                        ♻️ Restore
                                    </button>

                                    <!-- Hidden restore form — submitted by confirmRestore() -->
                                    <form
                                        id="restoreForm_<?= (int)$t['id'] ?>"
                                        method="POST"
                                        action="patients.php"
                                        class="delete-form"
                                    >
                                        <input type="hidden" name="action"     value="restore_patient">
                                        <input type="hidden" name="patient_id" value="<?= (int)$t['id'] ?>">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                    </form>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <?php endif; ?>

        </div>
        <!-- End card-body-mv -->
    </div>
    <!-- End Trash Section -->

    <?php endif; ?>
    <!-- End: Trash shown to Admin only -->

</main>
<!-- End Main Content -->


<!-- ============================================================
     EDIT PATIENT MODAL — Bootstrap 5
     Only rendered for Admin and Doctor
============================================================ -->
<?php if (in_array($userRole, ['admin', 'doctor'])): ?>

<div class="modal fade" id="editPatientModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content" style="border:none; border-radius:12px; overflow:hidden;">

            <div class="modal-header-mv d-flex align-items-center justify-content-between">
                <span class="modal-title" id="editModalLabel">✏️ Edit Patient</span>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close" style="filter:invert(1); opacity:0.8;"></button>
            </div>

            <form method="POST" action="patients.php" id="editPatientForm" novalidate>
                <input type="hidden" name="action"     value="edit_patient">
                <input type="hidden" name="patient_id" id="edit_patient_id" value="">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                <div class="modal-body-mv">

                    <div class="form-row" style="margin-bottom:16px;">
                        <div>
                            <label class="form-label-mv" for="edit_name">
                                Patient Name <span class="required-star">*</span>
                            </label>
                            <input
                                type="text"
                                id="edit_name"
                                name="name"
                                class="form-control-mv"
                                maxlength="100"
                                required
                            >
                        </div>
                        <div>
                            <label class="form-label-mv" for="edit_age">
                                Age <span class="required-star">*</span>
                            </label>
                            <input
                                type="number"
                                id="edit_age"
                                name="age"
                                class="form-control-mv"
                                min="0"
                                max="150"
                                required
                            >
                        </div>
                        <div>
                            <label class="form-label-mv" for="edit_gender">
                                Gender <span class="required-star">*</span>
                            </label>
                            <select id="edit_gender" name="gender" class="form-control-mv" required>
                                <option value="Male">Male</option>
                                <option value="Female">Female</option>
                                <option value="Other">Other</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label-mv" for="edit_diagnosis">
                            Diagnosis / Medical Notes <span class="required-star">*</span>
                        </label>
                        <textarea
                            id="edit_diagnosis"
                            name="diagnosis"
                            class="form-control-mv"
                            rows="3"
                            required
                        ></textarea>
                    </div>

                </div>

                <div class="modal-footer-mv">
                    <button type="button" class="btn-cancel-mv" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn-submit">💾 Save Changes</button>
                </div>
            </form>

        </div>
    </div>
</div>

<?php endif; ?>
<!-- End Edit Modal -->


<!-- ============================================================
     SCRIPTS
============================================================ -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    // ============================================================
    // MOBILE HAMBURGER SIDEBAR TOGGLE — identical to dashboard.php
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
    // confirmDelete() — spec names this function explicitly
    // Shows confirmation dialog, submits the hidden form if confirmed
    // Now performs SOFT DELETE (moved to Trash, not permanently removed)
    // ============================================================
    function confirmDelete(patientId, patientName) {
        if (confirm(
            '🗑️ Move to Trash\n\n' +
            'Are you sure you want to move this patient record to the trash?\n' +
            '"' + patientName + '"\n\n' +
            'The record can be restored by an Admin from the Trash section.'
        )) {
            var form = document.getElementById('deleteForm_' + patientId);
            if (form) {
                form.submit();
            }
        }
    }

    // ============================================================
    // confirmRestore() — Admin only
    // Confirms before restoring a soft-deleted patient record
    // ============================================================
    function confirmRestore(patientId, patientName) {
        if (confirm(
            '♻️ Restore Patient Record\n\n' +
            'Restore this patient back to the active records?\n' +
            '"' + patientName + '"'
        )) {
            var form = document.getElementById('restoreForm_' + patientId);
            if (form) {
                form.submit();
            }
        }
    }

    // ============================================================
    // openEditModal() — populates edit modal with row data
    // Called from each row's Edit button
    // ============================================================
    function openEditModal(id, name, age, gender, diagnosis) {
        document.getElementById('edit_patient_id').value = id;
        document.getElementById('edit_name').value       = name;
        document.getElementById('edit_age').value        = age;
        document.getElementById('edit_gender').value     = gender;
        document.getElementById('edit_diagnosis').value  = diagnosis;

        // Show Bootstrap modal
        var modal = new bootstrap.Modal(document.getElementById('editPatientModal'));
        modal.show();
    }

    // ============================================================
    // filterPatients() — live JS search on existing rows
    // Filters by name OR diagnosis columns
    // Updates the visible count text
    // Pagination rows are in DOM — only current page rows filtered
    // ============================================================
    function filterPatients() {
        var query  = document.getElementById('patientSearch').value.toLowerCase().trim();
        var tbody  = document.getElementById('patientsTbody');
        var rows   = tbody ? tbody.querySelectorAll('tr[data-name]') : [];
        var visible = 0;

        rows.forEach(function(row) {
            var name      = row.getAttribute('data-name')      || '';
            var diagnosis = row.getAttribute('data-diagnosis') || '';

            if (name.indexOf(query) !== -1 || diagnosis.indexOf(query) !== -1) {
                row.style.display = '';
                visible++;
            } else {
                row.style.display = 'none';
            }
        });

        // Update count text
        var countEl = document.getElementById('searchCount');
        if (countEl) {
            if (query === '') {
                countEl.textContent = rows.length + ' of <?= number_format($totalPatients) ?> shown';
            } else {
                countEl.textContent = visible + ' result' + (visible !== 1 ? 's' : '') + ' found';
            }
        }

        // Show/hide no-results message
        var noResults = document.getElementById('noSearchResults');
        if (noResults) {
            noResults.style.display = (visible === 0 && query !== '' && rows.length > 0) ? 'block' : 'none';
        }
    }

    // ============================================================
    // CLIENT-SIDE FORM VALIDATION — add patient form
    // Runs before submit; PHP validates again server-side
    // ============================================================
    var addForm = document.getElementById('addPatientForm');
    if (addForm) {
        addForm.addEventListener('submit', function(e) {
            var name      = document.getElementById('add_name').value.trim();
            var age       = parseInt(document.getElementById('add_age').value, 10);
            var gender    = document.getElementById('add_gender').value;
            var diagnosis = document.getElementById('add_diagnosis').value.trim();

            if (!name) {
                alert('Please enter the patient name.');
                e.preventDefault(); return;
            }
            if (isNaN(age) || age < 0 || age > 150) {
                alert('Please enter a valid age (0–150).');
                e.preventDefault(); return;
            }
            if (!gender) {
                alert('Please select a gender.');
                e.preventDefault(); return;
            }
            if (!diagnosis) {
                alert('Please enter a diagnosis or medical notes.');
                e.preventDefault(); return;
            }
        });
    }

    // ============================================================
    // CLIENT-SIDE FORM VALIDATION — edit patient modal form
    // ============================================================
    var editForm = document.getElementById('editPatientForm');
    if (editForm) {
        editForm.addEventListener('submit', function(e) {
            var name      = document.getElementById('edit_name').value.trim();
            var age       = parseInt(document.getElementById('edit_age').value, 10);
            var gender    = document.getElementById('edit_gender').value;
            var diagnosis = document.getElementById('edit_diagnosis').value.trim();

            if (!name) {
                alert('Please enter the patient name.');
                e.preventDefault(); return;
            }
            if (isNaN(age) || age < 0 || age > 150) {
                alert('Please enter a valid age (0–150).');
                e.preventDefault(); return;
            }
            if (!gender) {
                alert('Please select a gender.');
                e.preventDefault(); return;
            }
            if (!diagnosis) {
                alert('Please enter a diagnosis or medical notes.');
                e.preventDefault(); return;
            }
        });
    }

    // ============================================================
    // AUTO-DISMISS flash messages after 5 seconds
    // ============================================================
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert-mv');
        alerts.forEach(function(el) {
            el.style.transition = 'opacity 0.5s';
            el.style.opacity    = '0';
            setTimeout(function() { el.style.display = 'none'; }, 500);
        });
    }, 5000);

</script>

</body>
</html>