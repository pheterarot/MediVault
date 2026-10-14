<?php
// ============================================================
// MEDIVAULT — assets.php
// Purpose:  Hospital asset registry — add, edit, delete assets
//           with CIA classification badges and full audit trail
// Layout:   Full sidebar
// Access:   Admin only
//
// Security:
//   CSRF on every POST (verifyCsrf())
//   requireRole(['admin']) — server-side, not just UI hiding
//   Prepared statements throughout — no SQL concatenation
//   XSS prevention via clean() / htmlspecialchars() everywhere
//   All actions logged to activity_logs
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';
require 'includes/mailer.php'; // needed so sendSuspiciousAlert()
                                // is available for auth.php IP mismatch check

// ============================================================
// ACCESS CONTROL — Admin only
// ============================================================
requireRole(['admin']);

$userId   = $_SESSION['user_id'];
$userName = $_SESSION['user_name'];
$userRole = $_SESSION['user_role'];
$ip       = getUserIP();

// ============================================================
// POST HANDLER — process all form submissions
// Order: CSRF → validate → DB → log → redirect
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
    // ACTION: ADD ASSET
    // --------------------------------------------------------
    if ($action === 'add_asset') {

        $name           = sanitizeForDb($_POST['name']           ?? '');
        $classification = sanitizeForDb($_POST['classification'] ?? '');
        $description    = sanitizeForDb($_POST['description']    ?? '');

        $validClassifications = ['Confidential', 'Internal', 'Public'];

        if ($name === '') {
            header('Location: assets.php?error=Asset+name+is+required');
            exit;
        }
        if (!in_array($classification, $validClassifications)) {
            header('Location: assets.php?error=Please+select+a+valid+classification');
            exit;
        }
        if ($description === '') {
            header('Location: assets.php?error=Description+is+required');
            exit;
        }

        $stmt = $conn->prepare(
            "INSERT INTO assets (name, classification, description, created_by)
             VALUES (?, ?, ?, ?)"
        );
        $stmt->bind_param("sssi", $name, $classification, $description, $userId);
        $stmt->execute();
        $stmt->close();

        logActivity($conn, $userId, "Added asset: " . $name, $ip);

        header('Location: assets.php?success=Asset+added+successfully');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: EDIT ASSET
    // --------------------------------------------------------
    if ($action === 'edit_asset') {

        $assetId        = (int)($_POST['asset_id']       ?? 0);
        $name           = sanitizeForDb($_POST['name']           ?? '');
        $classification = sanitizeForDb($_POST['classification'] ?? '');
        $description    = sanitizeForDb($_POST['description']    ?? '');

        $validClassifications = ['Confidential', 'Internal', 'Public'];

        if ($assetId <= 0) {
            header('Location: assets.php?error=Invalid+asset+ID');
            exit;
        }
        if ($name === '') {
            header('Location: assets.php?error=Asset+name+is+required');
            exit;
        }
        if (!in_array($classification, $validClassifications)) {
            header('Location: assets.php?error=Please+select+a+valid+classification');
            exit;
        }
        if ($description === '') {
            header('Location: assets.php?error=Description+is+required');
            exit;
        }

        // Verify asset exists and is not soft-deleted before updating
        $check = $conn->prepare("SELECT id FROM assets WHERE id = ? AND deleted_at IS NULL");
        $check->bind_param("i", $assetId);
        $check->execute();
        $exists = $check->get_result()->fetch_assoc();
        $check->close();

        if (!$exists) {
            header('Location: assets.php?error=Asset+not+found');
            exit;
        }

        $stmt = $conn->prepare(
            "UPDATE assets
             SET name = ?, classification = ?, description = ?, updated_by = ?
             WHERE id = ?"
        );
        $stmt->bind_param("sssii", $name, $classification, $description, $userId, $assetId);
        $stmt->execute();
        $stmt->close();

        logActivity($conn, $userId, "Edited asset: " . $name, $ip);

        header('Location: assets.php?success=Asset+updated+successfully');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: DELETE ASSET
    // --------------------------------------------------------
    if ($action === 'delete_asset') {

        $assetId = (int)($_POST['asset_id'] ?? 0);

        if ($assetId <= 0) {
            header('Location: assets.php?error=Invalid+asset+ID');
            exit;
        }

        // Fetch name for log — only match active (non-deleted) assets
        $stmt = $conn->prepare("SELECT name FROM assets WHERE id = ? AND deleted_at IS NULL");
        $stmt->bind_param("i", $assetId);
        $stmt->execute();
        $toDelete = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$toDelete) {
            header('Location: assets.php?error=Asset+not+found');
            exit;
        }

        $deletedName = $toDelete['name'];

        // Soft-delete all linked active risks first (cascade)
        $stmtRisks = $conn->prepare(
            "UPDATE risks
             SET deleted_at = NOW(), deleted_by = ?
             WHERE asset_id = ? AND deleted_at IS NULL"
        );
        $stmtRisks->bind_param("ii", $userId, $assetId);
        $stmtRisks->execute();
        $risksSoftDeleted = $stmtRisks->affected_rows;
        $stmtRisks->close();

        // Soft-delete the asset
        $stmt = $conn->prepare(
            "UPDATE assets
             SET deleted_at = NOW(), deleted_by = ?
             WHERE id = ?"
        );
        $stmt->bind_param("ii", $userId, $assetId);
        $stmt->execute();
        $stmt->close();

        $logMsg = "Soft-deleted asset: " . $deletedName;
        if ($risksSoftDeleted > 0) {
            $logMsg .= " (cascaded to " . $risksSoftDeleted . " linked risk(s))";
        }
        logActivity($conn, $userId, $logMsg, $ip);

        header('Location: assets.php?success=Asset+moved+to+trash+successfully');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: RESTORE ASSET (Admin only — moves out of Trash)
    // --------------------------------------------------------
    if ($action === 'restore_asset') {

        $assetId = (int)($_POST['asset_id'] ?? 0);

        if ($assetId <= 0) {
            header('Location: assets.php?error=Invalid+asset+ID');
            exit;
        }

        // Verify the asset is actually in the trash
        $check = $conn->prepare("SELECT name FROM assets WHERE id = ? AND deleted_at IS NOT NULL");
        $check->bind_param("i", $assetId);
        $check->execute();
        $toRestore = $check->get_result()->fetch_assoc();
        $check->close();

        if (!$toRestore) {
            header('Location: assets.php?error=Asset+not+found+in+trash');
            exit;
        }

        $stmt = $conn->prepare(
            "UPDATE assets
             SET deleted_at = NULL, deleted_by = NULL
             WHERE id = ?"
        );
        $stmt->bind_param("i", $assetId);
        $stmt->execute();
        $stmt->close();

        logActivity($conn, $userId, "Restored asset: " . $toRestore['name'], $ip);

        header('Location: assets.php?success=Asset+restored+successfully');
        exit;
    }

    // Unknown action — reject silently
    header('Location: assets.php');
    exit;
}
// ============================================================
// END POST HANDLER
// ============================================================


// ============================================================
// DATA FETCH — all assets with JOIN to users for "Added By"
// ============================================================
$assets      = [];
$totalAssets = 0;

$stmt = $conn->prepare(
    "SELECT a.id, a.name, a.classification, a.description,
            a.created_at, u.name AS added_by_name
     FROM assets a
     LEFT JOIN users u ON u.id = a.created_by
     WHERE a.deleted_at IS NULL
     ORDER BY a.id DESC, a.created_at DESC"
);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $assets[] = $row;
}
$totalAssets = count($assets);
$stmt->close();

// ============================================================
// DATA FETCH — soft-deleted (trashed) assets
// ============================================================
$trashedAssets = [];
$totalTrashed  = 0;

$stmt = $conn->prepare(
    "SELECT a.id, a.name, a.classification, a.description,
            a.created_at, a.deleted_at, u.name AS added_by_name,
            d.name AS deleted_by_name
     FROM assets a
     LEFT JOIN users u ON u.id = a.created_by
     LEFT JOIN users d ON d.id = a.deleted_by
     WHERE a.deleted_at IS NOT NULL
     ORDER BY a.deleted_at DESC"
);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $trashedAssets[] = $row;
}
$totalTrashed = count($trashedAssets);
$stmt->close();

// ============================================================
// LOG PAGE VIEW
// ============================================================
logActivity($conn, $userId, "Viewed asset registry", $ip);

// ============================================================
// END PHP LOGIC — begin HTML output
// ============================================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Assets</title>
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
           SECTION CARDS — identical to dashboard.php / patients.php
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
           FLASH MESSAGES — identical to patients.php
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
           FORM ELEMENTS — identical to patients.php
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

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
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

        /* ======================================================
           ASSETS TABLE — spec columns
        ====================================================== */
        .assets-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .assets-table thead th {
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

        .assets-table tbody tr {
            border-bottom: 1px solid #F1F5F9;
            transition: background 0.15s;
        }

        .assets-table tbody tr:hover {
            background: #F8FAFC;
        }

        .assets-table tbody tr:last-child {
            border-bottom: none;
        }

        .assets-table tbody td {
            padding: 11px 14px;
            color: #1E293B;
            vertical-align: middle;
        }

        .asset-name {
            font-weight: 600;
            color: #1E293B;
        }

        .asset-description {
            color: #475569;
            max-width: 260px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

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
           CIA CLASSIFICATION BADGES — exact spec colors
           Confidential: #EF4444 red
           Internal:     #F59E0B yellow
           Public:       #22C55E green
        ====================================================== */
        .badge-classification {
            display: inline-block;
            padding: 3px 11px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }

        .badge-confidential {
            background: #EF4444;
            color: #ffffff;
        }

        .badge-internal {
            background: #F59E0B;
            color: #ffffff;
        }

        .badge-public {
            background: #22C55E;
            color: #ffffff;
        }

        /* ======================================================
           ACTION BUTTONS in table — identical to patients.php
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
           MODAL — Edit Asset (Bootstrap 5)
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

            .assets-table {
                font-size: 12px;
            }

            .assets-table thead th,
            .assets-table tbody td {
                padding: 8px 10px;
            }

            .asset-description {
                max-width: 130px;
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
           TRASH SECTION — soft-deleted records
        ====================================================== */
        .card-header-trash {
            background: linear-gradient(135deg, #7F1D1D, #B91C1C);
            color: #ffffff;
            font-weight: 600;
            font-size: 15px;
            padding: 15px 20px;
            border: none;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .card-header-trash .header-actions {
            margin-left: auto;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-restore {
            background: #F0FDF4;
            color: #166534;
        }
        .btn-restore:hover {
            background: #22C55E;
            color: #ffffff;
        }

        .deleted-at-cell {
            color: #B91C1C;
            font-size: 12px;
            white-space: nowrap;
        }

        .deleted-by-cell {
            color: #64748B;
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
     SIDEBAR — identical to dashboard.php, active on assets
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

        <!-- Assets — ADMIN ONLY — ACTIVE on this page -->
        <?php if ($userRole === 'admin'): ?>
        <a href="assets.php" class="active">
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
    <span class="topbar-title">🏗️ Assets</span>
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
        <h2>Asset Registry</h2>
        <p>Manage and classify hospital information assets — <?= date('l, F j, Y') ?></p>
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
         SECTION 1: ASSET REGISTRY TABLE
    ============================================================ -->
    <div class="section-card section-gap">
        <div class="card-header-mv">
            <span>📋</span> All Assets
            <div class="header-actions">
                <span style="font-size:12px; font-weight:400; opacity:0.85;">
                    <?= $totalAssets ?> total asset<?= $totalAssets !== 1 ? 's' : '' ?>
                </span>
            </div>
        </div>

        <div class="card-body-mv">

            <!-- Table -->
            <div class="table-scroll">
                <table class="assets-table" id="assetsTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Classification</th>
                            <th>Description</th>
                            <th>Added By</th>
                            <th>Date Added</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="assetsTbody">
                        <?php if (empty($assets)): ?>
                        <tr>
                            <td colspan="7">
                                <div class="no-records">
                                    <span class="no-records-icon">🏗️</span>
                                    <p>No assets registered yet. Add your first asset below.</p>
                                </div>
                            </td>
                        </tr>
                        <?php else: ?>
                        <?php foreach ($assets as $a):

                            // Determine classification badge class
                            $badgeClass = match($a['classification']) {
                                'Confidential' => 'badge-confidential',
                                'Internal'     => 'badge-internal',
                                'Public'       => 'badge-public',
                                default        => 'badge-internal',
                            };

                        ?>
                        <tr>
                            <td>
                                <span class="id-badge">#<?= (int)$a['id'] ?></span>
                            </td>
                            <td>
                                <span class="asset-name">
                                    <?= htmlspecialchars($a['name'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="badge-classification <?= $badgeClass ?>">
                                    <?= htmlspecialchars($a['classification'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="asset-description"
                                      title="<?= htmlspecialchars($a['description'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= htmlspecialchars($a['description'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td style="color:#64748B; font-size:12px;">
                                <?= htmlspecialchars($a['added_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td style="color:#64748B; font-size:12px; white-space:nowrap;">
                                <?= date('M j, Y', strtotime($a['created_at'])) ?>
                            </td>
                            <td>
                                <div class="actions-cell">

                                    <!-- Edit button — triggers modal -->
                                    <button
                                        class="btn-action btn-edit"
                                        onclick="openEditModal(
                                            <?= (int)$a['id'] ?>,
                                            '<?= addslashes(htmlspecialchars($a['name'],           ENT_QUOTES, 'UTF-8')) ?>',
                                            '<?= addslashes(htmlspecialchars($a['classification'], ENT_QUOTES, 'UTF-8')) ?>',
                                            '<?= addslashes(htmlspecialchars($a['description'],    ENT_QUOTES, 'UTF-8')) ?>'
                                        )"
                                    >
                                        ✏️ Edit
                                    </button>

                                    <!-- Delete button — calls confirmDelete() -->
                                    <button
                                        class="btn-action btn-delete"
                                        onclick="confirmDelete(<?= (int)$a['id'] ?>, '<?= addslashes(htmlspecialchars($a['name'], ENT_QUOTES, 'UTF-8')) ?>')"
                                    >
                                        🗑️ Delete
                                    </button>

                                    <!-- Hidden delete form — submitted by confirmDelete() -->
                                    <form
                                        id="deleteForm_<?= (int)$a['id'] ?>"
                                        method="POST"
                                        action="assets.php"
                                        class="delete-form"
                                    >
                                        <input type="hidden" name="action"     value="delete_asset">
                                        <input type="hidden" name="asset_id"   value="<?= (int)$a['id'] ?>">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                    </form>

                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <!-- End Table -->

        </div>
        <!-- End card-body-mv -->
    </div>
    <!-- End Assets Table Card -->


    <!-- ============================================================
         SECTION 2: ADD ASSET FORM
    ============================================================ -->
    <div class="section-card section-gap">
        <div class="card-header-mv">
            <span>➕</span> Add New Asset
        </div>

        <div class="card-body-mv">
            <form method="POST" action="assets.php" id="addAssetForm" novalidate>
                <input type="hidden" name="action"     value="add_asset">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                <!-- Row 1: Name / Classification -->
                <div class="form-row">
                    <div>
                        <label class="form-label-mv" for="add_name">
                            Asset Name <span class="required-star">*</span>
                        </label>
                        <input
                            type="text"
                            id="add_name"
                            name="name"
                            class="form-control-mv"
                            placeholder="e.g. Patient Records Database"
                            maxlength="100"
                            required
                        >
                    </div>
                    <div>
                        <label class="form-label-mv" for="add_classification">
                            Classification <span class="required-star">*</span>
                        </label>
                        <select id="add_classification" name="classification" class="form-control-mv" required>
                            <option value="" disabled selected>Select classification</option>
                            <option value="Confidential">Confidential</option>
                            <option value="Internal">Internal</option>
                            <option value="Public">Public</option>
                        </select>
                    </div>
                </div>

                <!-- Row 2: Description -->
                <div class="form-group">
                    <label class="form-label-mv" for="add_description">
                        Description <span class="required-star">*</span>
                    </label>
                    <textarea
                        id="add_description"
                        name="description"
                        class="form-control-mv"
                        placeholder="Describe the asset, its purpose, and why it is classified this way..."
                        rows="3"
                        required
                    ></textarea>
                </div>

                <!-- Classification legend for reference -->
                <div style="
                    background: #F8FAFC;
                    border: 1px solid #E2E8F0;
                    border-radius: 8px;
                    padding: 12px 16px;
                    margin-bottom: 16px;
                    font-size: 12px;
                    color: #64748B;
                    display: flex;
                    align-items: center;
                    gap: 16px;
                    flex-wrap: wrap;
                ">
                    <span style="font-weight:600; color:#475569;">Classification guide:</span>
                    <span><span style="display:inline-block;width:10px;height:10px;background:#EF4444;border-radius:50%;margin-right:4px;"></span><strong>Confidential</strong> — patient data, credentials, private records</span>
                    <span><span style="display:inline-block;width:10px;height:10px;background:#F59E0B;border-radius:50%;margin-right:4px;"></span><strong>Internal</strong> — systems and infrastructure visible only to staff</span>
                    <span><span style="display:inline-block;width:10px;height:10px;background:#22C55E;border-radius:50%;margin-right:4px;"></span><strong>Public</strong> — information freely accessible to the public</span>
                </div>

                <!-- Submit -->
                <div style="display:flex; align-items:center; gap:12px;">
                    <button type="submit" class="btn-submit">
                        ➕ Add Asset
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
    <!-- End Add Asset Form -->

    <!-- ============================================================
         SECTION 3: TRASH — soft-deleted assets (Admin only)
    ============================================================ -->
    <?php if ($userRole === 'admin'): ?>
    <div class="section-card section-gap">
        <div class="card-header-trash">
            <span>🗑️</span> Trash — Deleted Assets
            <div class="header-actions">
                <span style="font-size:12px; font-weight:400; opacity:0.85;">
                    <?= $totalTrashed ?> deleted asset<?= $totalTrashed !== 1 ? 's' : '' ?>
                </span>
            </div>
        </div>

        <div class="card-body-mv">

            <?php if (empty($trashedAssets)): ?>
            <div class="no-records">
                <span class="no-records-icon">✅</span>
                <p>No deleted assets. Trash is empty.</p>
            </div>
            <?php else: ?>

            <p style="font-size:12px; color:#94A3B8; margin-bottom:14px;">
                🔒 Soft-deleted assets are hidden from all views but remain in the database.
                Restoring an asset does <strong>not</strong> automatically restore its linked risks.
            </p>

            <div class="table-scroll">
                <table class="assets-table" id="trashTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Classification</th>
                            <th>Description</th>
                            <th>Added By</th>
                            <th>Deleted At</th>
                            <th>Deleted By</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($trashedAssets as $t):
                            $badgeClass = match($t['classification']) {
                                'Confidential' => 'badge-confidential',
                                'Internal'     => 'badge-internal',
                                'Public'       => 'badge-public',
                                default        => 'badge-internal',
                            };
                        ?>
                        <tr style="opacity:0.75;">
                            <td>
                                <span class="id-badge">#<?= (int)$t['id'] ?></span>
                            </td>
                            <td>
                                <span class="asset-name" style="text-decoration:line-through; color:#94A3B8;">
                                    <?= htmlspecialchars($t['name'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="badge-classification <?= $badgeClass ?>" style="opacity:0.6;">
                                    <?= htmlspecialchars($t['classification'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="asset-description"
                                      title="<?= htmlspecialchars($t['description'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= htmlspecialchars($t['description'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td style="color:#64748B; font-size:12px;">
                                <?= htmlspecialchars($t['added_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td class="deleted-at-cell">
                                <?= date('M j, Y g:i A', strtotime($t['deleted_at'])) ?>
                            </td>
                            <td class="deleted-by-cell">
                                <?= htmlspecialchars($t['deleted_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td>
                                <div class="actions-cell">

                                    <!-- Restore button -->
                                    <button
                                        class="btn-action btn-restore"
                                        onclick="confirmRestore(<?= (int)$t['id'] ?>, '<?= addslashes(htmlspecialchars($t['name'], ENT_QUOTES, 'UTF-8')) ?>')"
                                    >
                                        ♻️ Restore
                                    </button>

                                    <!-- Hidden restore form -->
                                    <form
                                        id="restoreForm_<?= (int)$t['id'] ?>"
                                        method="POST"
                                        action="assets.php"
                                        class="delete-form"
                                    >
                                        <input type="hidden" name="action"     value="restore_asset">
                                        <input type="hidden" name="asset_id"   value="<?= (int)$t['id'] ?>">
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
    </div>
    <?php endif; ?>
    <!-- End Trash Section -->

</main>
<!-- End Main Content -->


<!-- ============================================================
     EDIT ASSET MODAL — Bootstrap 5
============================================================ -->
<div class="modal fade" id="editAssetModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content" style="border:none; border-radius:12px; overflow:hidden;">

            <div class="modal-header-mv d-flex align-items-center justify-content-between">
                <span class="modal-title" id="editModalLabel">✏️ Edit Asset</span>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close" style="filter:invert(1); opacity:0.8;"></button>
            </div>

            <form method="POST" action="assets.php" id="editAssetForm" novalidate>
                <input type="hidden" name="action"     value="edit_asset">
                <input type="hidden" name="asset_id"   id="edit_asset_id" value="">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                <div class="modal-body-mv">

                    <!-- Name -->
                    <div class="form-group">
                        <label class="form-label-mv" for="edit_name">
                            Asset Name <span class="required-star">*</span>
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

                    <!-- Classification -->
                    <div class="form-group">
                        <label class="form-label-mv" for="edit_classification">
                            Classification <span class="required-star">*</span>
                        </label>
                        <select id="edit_classification" name="classification" class="form-control-mv" required>
                            <option value="Confidential">Confidential</option>
                            <option value="Internal">Internal</option>
                            <option value="Public">Public</option>
                        </select>
                    </div>

                    <!-- Description -->
                    <div class="form-group" style="margin-bottom:0;">
                        <label class="form-label-mv" for="edit_description">
                            Description <span class="required-star">*</span>
                        </label>
                        <textarea
                            id="edit_description"
                            name="description"
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
<!-- End Edit Modal -->


<!-- ============================================================
     SCRIPTS — Bootstrap CDN last, then page-specific JS
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
    // Shows native confirmation dialog, submits the hidden form
    // ============================================================
    function confirmDelete(assetId, assetName) {
        if (confirm(
            '🗑️ Move Asset to Trash\n\n' +
            'Are you sure you want to delete:\n' +
            '"' + assetName + '"\n\n' +
            '⚠️ All linked risks will also be soft-deleted.\n' +
            'You can restore this asset from the Trash section.'
        )) {
            var form = document.getElementById('deleteForm_' + assetId);
            if (form) {
                form.submit();
            }
        }
    }

    // ============================================================
    // confirmRestore() — confirms before restoring an asset
    // ============================================================
    function confirmRestore(assetId, assetName) {
        if (confirm(
            '♻️ Restore Asset\n\n' +
            'Restore "' + assetName + '" from Trash?\n\n' +
            'Note: Linked risks that were also soft-deleted will NOT be\n' +
            'automatically restored. Restore them separately in Risks.'
        )) {
            var form = document.getElementById('restoreForm_' + assetId);
            if (form) {
                form.submit();
            }
        }
    }

    // ============================================================
    // openEditModal() — populates edit modal with row data
    // Called from each row's Edit button via data- attributes
    // ============================================================
    function openEditModal(id, name, classification, description) {
        document.getElementById('edit_asset_id').value         = id;
        document.getElementById('edit_name').value             = name;
        document.getElementById('edit_classification').value   = classification;
        document.getElementById('edit_description').value      = description;

        // Show Bootstrap modal
        var modal = new bootstrap.Modal(document.getElementById('editAssetModal'));
        modal.show();
    }

    // ============================================================
    // CLIENT-SIDE FORM VALIDATION — add asset form
    // PHP validates again server-side — this is a UX shortcut only
    // ============================================================
    var addForm = document.getElementById('addAssetForm');
    if (addForm) {
        addForm.addEventListener('submit', function(e) {
            var name           = document.getElementById('add_name').value.trim();
            var classification = document.getElementById('add_classification').value;
            var description    = document.getElementById('add_description').value.trim();

            if (!name) {
                alert('Please enter an asset name.');
                e.preventDefault(); return;
            }
            if (!classification) {
                alert('Please select a classification.');
                e.preventDefault(); return;
            }
            if (!description) {
                alert('Please enter a description.');
                e.preventDefault(); return;
            }
        });
    }

    // ============================================================
    // CLIENT-SIDE FORM VALIDATION — edit asset modal form
    // ============================================================
    var editForm = document.getElementById('editAssetForm');
    if (editForm) {
        editForm.addEventListener('submit', function(e) {
            var name           = document.getElementById('edit_name').value.trim();
            var classification = document.getElementById('edit_classification').value;
            var description    = document.getElementById('edit_description').value.trim();

            if (!name) {
                alert('Please enter an asset name.');
                e.preventDefault(); return;
            }
            if (!classification) {
                alert('Please select a classification.');
                e.preventDefault(); return;
            }
            if (!description) {
                alert('Please enter a description.');
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