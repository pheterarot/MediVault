<?php
// ============================================================
// MEDIVAULT — risks.php
// Purpose:  Risk assessment and threat logging — add, edit,
//           delete risks with likelihood × impact scoring,
//           color-coded rows, summary cards, asset filter,
//           and full audit trail
// Layout:   Full sidebar
// Access:   Admin only
//
// Security:
//   CSRF on every POST (verifyCsrf())
//   requireRole(['admin']) — server-side, not just UI hiding
//   Prepared statements throughout — no SQL concatenation
//   XSS prevention via clean() / htmlspecialchars() everywhere
//   All actions logged to activity_logs
//
// Note on risk_score:
//   risk_score is a GENERATED ALWAYS AS (likelihood * impact)
//   STORED column — never included in INSERT or UPDATE
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
// HELPER: getRiskLevel()
// Returns level string from score
// ============================================================
function getRiskLevel(int $score): string {
    if ($score <= 4)  return 'Low';
    if ($score <= 12) return 'Medium';
    return 'High';
}

// ============================================================
// HELPER: getLikelihoodLabel()
// ============================================================
function getLikelihoodLabel(int $val): string {
    return match($val) {
        1 => 'Very Unlikely',
        2 => 'Unlikely',
        3 => 'Possible',
        4 => 'Likely',
        5 => 'Very Likely',
        default => (string)$val,
    };
}

// ============================================================
// HELPER: getImpactLabel()
// ============================================================
function getImpactLabel(int $val): string {
    return match($val) {
        1 => 'Negligible',
        2 => 'Minor',
        3 => 'Moderate',
        4 => 'Major',
        5 => 'Critical',
        default => (string)$val,
    };
}

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
    // ACTION: ADD RISK
    // --------------------------------------------------------
    if ($action === 'add_risk') {

        $assetId    = (int)($_POST['asset_id']    ?? 0);
        $threat     = sanitizeForDb($_POST['threat']      ?? '');
        $likelihood = (int)($_POST['likelihood']  ?? 0);
        $impact     = (int)($_POST['impact']      ?? 0);

        // Validation
        if ($assetId <= 0) {
            header('Location: risks.php?error=Please+select+an+asset');
            exit;
        }
        if ($threat === '') {
            header('Location: risks.php?error=Threat+name+is+required');
            exit;
        }
        if ($likelihood < 1 || $likelihood > 5) {
            header('Location: risks.php?error=Please+select+a+valid+likelihood+value');
            exit;
        }
        if ($impact < 1 || $impact > 5) {
            header('Location: risks.php?error=Please+select+a+valid+impact+value');
            exit;
        }

        // Verify asset exists
        $check = $conn->prepare("SELECT id, name FROM assets WHERE id = ? AND deleted_at IS NULL");
        $check->bind_param("i", $assetId);
        $check->execute();
        $assetRow = $check->get_result()->fetch_assoc();
        $check->close();

        if (!$assetRow) {
            header('Location: risks.php?error=Selected+asset+not+found');
            exit;
        }

        // INSERT — risk_score is GENERATED, never included
        // Bind types: asset_id=i, threat=s, likelihood=i, impact=i, created_by=i
        $stmt = $conn->prepare(
            "INSERT INTO risks (asset_id, threat, likelihood, impact, created_by)
             VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->bind_param("isiii", $assetId, $threat, $likelihood, $impact, $userId);
        $stmt->execute();
        $stmt->close();

        logActivity(
            $conn,
            $userId,
            "Added risk: " . $threat . " on " . $assetRow['name'],
            $ip
        );

        header('Location: risks.php?success=Risk+added+successfully');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: EDIT RISK
    // --------------------------------------------------------
    if ($action === 'edit_risk') {

        $riskId     = (int)($_POST['risk_id']     ?? 0);
        $assetId    = (int)($_POST['asset_id']    ?? 0);
        $threat     = sanitizeForDb($_POST['threat']      ?? '');
        $likelihood = (int)($_POST['likelihood']  ?? 0);
        $impact     = (int)($_POST['impact']      ?? 0);

        // Validation
        if ($riskId <= 0) {
            header('Location: risks.php?error=Invalid+risk+ID');
            exit;
        }
        if ($assetId <= 0) {
            header('Location: risks.php?error=Please+select+an+asset');
            exit;
        }
        if ($threat === '') {
            header('Location: risks.php?error=Threat+name+is+required');
            exit;
        }
        if ($likelihood < 1 || $likelihood > 5) {
            header('Location: risks.php?error=Please+select+a+valid+likelihood+value');
            exit;
        }
        if ($impact < 1 || $impact > 5) {
            header('Location: risks.php?error=Please+select+a+valid+impact+value');
            exit;
        }

        // Verify risk exists
        $check = $conn->prepare("SELECT r.id, r.threat, a.name AS asset_name FROM risks r JOIN assets a ON r.asset_id = a.id WHERE r.id = ? AND r.deleted_at IS NULL");
        $check->bind_param("i", $riskId);
        $check->execute();
        $existing = $check->get_result()->fetch_assoc();
        $check->close();

        if (!$existing) {
            header('Location: risks.php?error=Risk+not+found');
            exit;
        }

        // Verify asset exists
        $checkAsset = $conn->prepare("SELECT id, name FROM assets WHERE id = ? AND deleted_at IS NULL");
        $checkAsset->bind_param("i", $assetId);
        $checkAsset->execute();
        $assetRow = $checkAsset->get_result()->fetch_assoc();
        $checkAsset->close();

        if (!$assetRow) {
            header('Location: risks.php?error=Selected+asset+not+found');
            exit;
        }

        // UPDATE — risk_score is GENERATED, never included
        $stmt = $conn->prepare(
            "UPDATE risks
             SET asset_id = ?, threat = ?, likelihood = ?, impact = ?, updated_by = ?
             WHERE id = ?"
        );
        $stmt->bind_param("isiiii", $assetId, $threat, $likelihood, $impact, $userId, $riskId);
        $stmt->execute();
        $stmt->close();

        logActivity(
            $conn,
            $userId,
            "Edited risk: " . $threat . " on " . $assetRow['name'],
            $ip
        );

        header('Location: risks.php?success=Risk+updated+successfully');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: DELETE RISK (soft delete)
    // --------------------------------------------------------
    if ($action === 'delete_risk') {

        $riskId = (int)($_POST['risk_id'] ?? 0);

        if ($riskId <= 0) {
            header('Location: risks.php?error=Invalid+risk+ID');
            exit;
        }

        // Fetch threat + asset name for log before soft-deleting
        $stmt = $conn->prepare(
            "SELECT r.threat, a.name AS asset_name
             FROM risks r
             JOIN assets a ON r.asset_id = a.id
             WHERE r.id = ? AND r.deleted_at IS NULL"
        );
        $stmt->bind_param("i", $riskId);
        $stmt->execute();
        $toDelete = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$toDelete) {
            header('Location: risks.php?error=Risk+not+found');
            exit;
        }

        $deletedThreat = $toDelete['threat'];
        $deletedAsset  = $toDelete['asset_name'];

        // Soft delete — set deleted_at and deleted_by
        $stmt = $conn->prepare(
            "UPDATE risks SET deleted_at = NOW(), deleted_by = ? WHERE id = ?"
        );
        $stmt->bind_param("ii", $userId, $riskId);
        $stmt->execute();
        $stmt->close();

        logActivity(
            $conn,
            $userId,
            "Soft deleted risk: " . $deletedThreat . " on " . $deletedAsset,
            $ip
        );

        header('Location: risks.php?success=Risk+moved+to+trash');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: RESTORE RISK (undo soft delete)
    // Admin only — already enforced at top of file
    // --------------------------------------------------------
    if ($action === 'restore_risk') {

        $riskId = (int)($_POST['risk_id'] ?? 0);

        if ($riskId <= 0) {
            header('Location: risks.php?error=Invalid+risk+ID');
            exit;
        }

        // Fetch threat + asset name for log
        $stmt = $conn->prepare(
            "SELECT r.threat, a.name AS asset_name
             FROM risks r
             JOIN assets a ON r.asset_id = a.id
             WHERE r.id = ? AND r.deleted_at IS NOT NULL"
        );
        $stmt->bind_param("i", $riskId);
        $stmt->execute();
        $toRestore = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$toRestore) {
            header('Location: risks.php?error=Risk+not+found+in+trash');
            exit;
        }

        // Restore — clear deleted_at and deleted_by
        $stmt = $conn->prepare(
            "UPDATE risks SET deleted_at = NULL, deleted_by = NULL WHERE id = ?"
        );
        $stmt->bind_param("i", $riskId);
        $stmt->execute();
        $stmt->close();

        logActivity(
            $conn,
            $userId,
            "Restored risk: " . $toRestore['threat'] . " on " . $toRestore['asset_name'],
            $ip
        );

        header('Location: risks.php?success=Risk+restored+successfully');
        exit;
    }

    // Unknown action — reject silently
    header('Location: risks.php');
    exit;
}
// ============================================================
// END POST HANDLER
// ============================================================


// ============================================================
// ASSET FILTER — from GET parameter
// ============================================================
$filterAssetId = isset($_GET['filter_asset']) ? (int)$_GET['filter_asset'] : 0;


// ============================================================
// DATA FETCH 1 — all assets for dropdowns
// ============================================================
$allAssets = [];
$stmtA = $conn->prepare("SELECT id, name FROM assets WHERE deleted_at IS NULL ORDER BY name ASC");
$stmtA->execute();
$resA = $stmtA->get_result();
while ($row = $resA->fetch_assoc()) {
    $allAssets[] = $row;
}
$stmtA->close();


// ============================================================
// DATA FETCH 2 — risks with JOINs, optional asset filter
// Columns: id, asset_name, threat, likelihood, impact,
//          risk_score, created_at, added_by_name
// ============================================================
$risks = [];

if ($filterAssetId > 0) {
    $stmtR = $conn->prepare(
        "SELECT r.id, a.name AS asset_name, r.threat,
                r.likelihood, r.impact, r.risk_score,
                r.asset_id, r.created_at,
                u.name AS added_by_name
         FROM risks r
         JOIN assets a ON r.asset_id = a.id
         LEFT JOIN users u ON u.id = r.created_by
         WHERE r.asset_id = ? AND r.deleted_at IS NULL
         ORDER BY r.id DESC, r.created_at DESC"
    );
    $stmtR->bind_param("i", $filterAssetId);
} else {
    $stmtR = $conn->prepare(
        "SELECT r.id, a.name AS asset_name, r.threat,
                r.likelihood, r.impact, r.risk_score,
                r.asset_id, r.created_at,
                u.name AS added_by_name
         FROM risks r
         JOIN assets a ON r.asset_id = a.id
         LEFT JOIN users u ON u.id = r.created_by
         WHERE r.deleted_at IS NULL
         ORDER BY r.id DESC, r.created_at DESC"
    );
}
$stmtR->execute();
$resR = $stmtR->get_result();
while ($row = $resR->fetch_assoc()) {
    $risks[] = $row;
}
$stmtR->close();


// ============================================================
// SUMMARY COUNTS — 4 cards
// These always count ALL risks regardless of filter
// ============================================================

// Total risks (active only)
$stmtT = $conn->prepare("SELECT COUNT(*) AS total FROM risks WHERE deleted_at IS NULL");
$stmtT->execute();
$totalRisks = (int)$stmtT->get_result()->fetch_assoc()['total'];
$stmtT->close();

// High risks (score 13-25)
$stmtH = $conn->prepare("SELECT COUNT(*) AS total FROM risks WHERE risk_score >= 13 AND deleted_at IS NULL");
$stmtH->execute();
$highCount = (int)$stmtH->get_result()->fetch_assoc()['total'];
$stmtH->close();

// Medium risks (score 5-12)
$stmtM = $conn->prepare("SELECT COUNT(*) AS total FROM risks WHERE risk_score BETWEEN 5 AND 12 AND deleted_at IS NULL");
$stmtM->execute();
$mediumCount = (int)$stmtM->get_result()->fetch_assoc()['total'];
$stmtM->close();

// Low risks (score 1-4)
$stmtL = $conn->prepare("SELECT COUNT(*) AS total FROM risks WHERE risk_score BETWEEN 1 AND 4 AND deleted_at IS NULL");
$stmtL->execute();
$lowCount = (int)$stmtL->get_result()->fetch_assoc()['total'];
$stmtL->close();

// ============================================================
// DATA FETCH 3 — trashed risks (deleted_at IS NOT NULL)
// Admin only — for Trash section
// ============================================================
$trashedRisks = [];
$stmtTrashed = $conn->prepare(
    "SELECT r.id, a.name AS asset_name, r.threat,
            r.likelihood, r.impact, r.risk_score,
            r.deleted_at,
            del_user.name AS deleted_by_name
     FROM risks r
     JOIN assets a ON r.asset_id = a.id
     LEFT JOIN users del_user ON del_user.id = r.deleted_by
     WHERE r.deleted_at IS NOT NULL
     ORDER BY r.deleted_at DESC"
);
$stmtTrashed->execute();
$resTrashed = $stmtTrashed->get_result();
while ($row = $resTrashed->fetch_assoc()) {
    $trashedRisks[] = $row;
}
$stmtTrashed->close();

// ============================================================
// LOG PAGE VIEW
// ============================================================
logActivity($conn, $userId, "Viewed risk assessment", $ip);

// ============================================================
// END PHP LOGIC — begin HTML output
// ============================================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Risks</title>
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
           SIDEBAR — exact copy from assets.php / dashboard.php
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
           TOPBAR — identical to assets.php / dashboard.php
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
           MAIN CONTENT AREA — identical to assets.php
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
           SUMMARY CARDS — 4 cards (Total/High/Medium/Low)
        ====================================================== */
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }

        .summary-card {
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .summary-card .card-icon {
            width: 46px;
            height: 46px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            flex-shrink: 0;
        }

        .summary-card .card-info {
            flex: 1;
            min-width: 0;
        }

        .summary-card .card-value {
            font-size: 26px;
            font-weight: 700;
            line-height: 1.1;
            color: #1E293B;
        }

        .summary-card .card-label {
            font-size: 11px;
            color: #94A3B8;
            font-weight: 500;
            margin-top: 2px;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        .icon-total   { background: #EFF6FF; }
        .icon-high    { background: #FEF2F2; }
        .icon-medium  { background: #FFFBEB; }
        .icon-low     { background: #F0FDF4; }

        /* ======================================================
           SECTION CARDS — identical to assets.php
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
           FLASH MESSAGES — identical to assets.php
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
           ASSET FILTER BAR — above table
        ====================================================== */
        .filter-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }

        .filter-bar label {
            font-size: 12px;
            font-weight: 600;
            color: #475569;
            white-space: nowrap;
        }

        .filter-bar select {
            padding: 7px 12px;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-size: 13px;
            font-family: 'Poppins', sans-serif;
            color: #1E293B;
            background: #ffffff;
            cursor: pointer;
            outline: none;
            transition: border-color 0.2s;
        }

        .filter-bar select:focus {
            border-color: #2563EB;
            box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
        }

        .filter-bar .btn-filter {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 8px 18px;
            font-size: 12px;
            font-weight: 600;
            font-family: 'Poppins', sans-serif;
            cursor: pointer;
            transition: all 0.2s;
        }

        .filter-bar .btn-filter:hover {
            background: linear-gradient(135deg, #1E3A8A, #1E40AF);
        }

        .filter-bar .btn-clear {
            background: #F1F5F9;
            color: #64748B;
            border: none;
            border-radius: 8px;
            padding: 8px 16px;
            font-size: 12px;
            font-weight: 500;
            font-family: 'Poppins', sans-serif;
            cursor: pointer;
            text-decoration: none;
            transition: background 0.15s;
        }

        .filter-bar .btn-clear:hover {
            background: #E2E8F0;
            color: #475569;
        }

        /* ======================================================
           RISKS TABLE — spec columns with row color coding
        ====================================================== */
        .risks-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .risks-table thead th {
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

        .risks-table tbody tr {
            border-bottom: 1px solid #F1F5F9;
            transition: filter 0.15s;
        }

        .risks-table tbody tr:last-child {
            border-bottom: none;
        }

        .risks-table tbody td {
            padding: 11px 14px;
            color: #1E293B;
            vertical-align: middle;
        }

        /* Row color coding — spec exact values */
        .risk-row-low    { background: #F0FDF4; }
        .risk-row-medium { background: #FFFBEB; }
        .risk-row-high   { background: #FEF2F2; }

        .risk-row-low:hover    { filter: brightness(0.97); }
        .risk-row-medium:hover { filter: brightness(0.97); }
        .risk-row-high:hover   { filter: brightness(0.97); }

        /* ======================================================
           ID BADGE — identical to assets.php
        ====================================================== */
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
           RISK LEVEL BADGES — spec exact colors
           Low:    #22C55E green
           Medium: #F59E0B yellow
           High:   #EF4444 red
        ====================================================== */
        .badge-risk {
            display: inline-block;
            padding: 3px 11px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
            color: #ffffff;
        }

        .badge-low    { background: #22C55E; }
        .badge-medium { background: #F59E0B; }
        .badge-high   { background: #EF4444; }

        /* ======================================================
           RISK SCORE PILL
        ====================================================== */
        .score-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            font-size: 13px;
            font-weight: 700;
            color: #ffffff;
        }

        .score-low    { background: #22C55E; }
        .score-medium { background: #F59E0B; }
        .score-high   { background: #EF4444; }

        /* ======================================================
           LIKELIHOOD / IMPACT DISPLAY
        ====================================================== */
        .value-pill {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 12px;
            font-weight: 600;
            color: #475569;
        }

        .value-pill .num {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 22px;
            height: 22px;
            background: #E2E8F0;
            border-radius: 50%;
            font-size: 11px;
            font-weight: 700;
            color: #1E293B;
        }

        /* ======================================================
           ACTION BUTTONS in table — identical to assets.php
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
           FORM ELEMENTS — identical to assets.php
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

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 16px;
        }

        .form-row-3 {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr;
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
           LIVE SCORE DISPLAY — in add form and edit modal
        ====================================================== */
        .score-display {
            background: #F8FAFC;
            border: 1px solid #E2E8F0;
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .score-display .score-big {
            width: 52px;
            height: 52px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            font-weight: 700;
            color: #ffffff;
            flex-shrink: 0;
            transition: background 0.3s;
        }

        .score-display .score-info {
            flex: 1;
        }

        .score-display .score-info .score-label {
            font-size: 11px;
            color: #94A3B8;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        .score-display .score-info .score-level {
            font-size: 16px;
            font-weight: 700;
            margin-top: 2px;
            transition: color 0.3s;
        }

        .score-display .score-info .score-formula {
            font-size: 11px;
            color: #94A3B8;
            margin-top: 2px;
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
           MODAL — Edit Risk (Bootstrap 5)
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

            .summary-cards {
                grid-template-columns: repeat(2, 1fr);
            }

            .form-row,
            .form-row-3 {
                grid-template-columns: 1fr;
            }

            .risks-table {
                font-size: 12px;
            }

            .risks-table thead th,
            .risks-table tbody td {
                padding: 8px 10px;
            }

            .actions-cell {
                flex-direction: column;
                align-items: flex-start;
                gap: 3px;
            }

            .filter-bar {
                flex-direction: column;
                align-items: flex-start;
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
           ASSET NAME in table
        ====================================================== */
        .asset-name-cell {
            font-weight: 600;
            color: #2563EB;
            font-size: 12px;
        }

        .threat-name-cell {
            font-weight: 600;
            color: #1E293B;
        }

        /* ======================================================
           TRASH SECTION STYLES
        ====================================================== */
        .btn-restore {
            background: #F0FDF4;
            color: #16A34A;
        }
        .btn-restore:hover {
            background: #16A34A;
            color: #ffffff;
        }

        .trash-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .trash-table thead th {
            background: #FEF2F2;
            color: #991B1B;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 10px 14px;
            border-bottom: 2px solid #FECACA;
            white-space: nowrap;
        }

        .trash-table tbody tr {
            border-bottom: 1px solid #FEF2F2;
            background: #FFFBFB;
        }

        .trash-table tbody tr:hover {
            background: #FEF2F2;
        }

        .trash-table tbody td {
            padding: 11px 14px;
            color: #64748B;
            vertical-align: middle;
            font-size: 12px;
        }

        .trash-card-header {
            background: linear-gradient(135deg, #991B1B, #EF4444);
        }
    </style>
</head>
<body>

<!-- ============================================================
     MOBILE OVERLAY
============================================================ -->
<div id="overlay"></div>

<!-- ============================================================
     SIDEBAR — identical to assets.php, active on Risks
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

        <!-- Risks — ADMIN ONLY — ACTIVE on this page -->
        <?php if ($userRole === 'admin'): ?>
        <a href="risks.php" class="active">
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
    <span class="topbar-title">⚠️ Risk Assessment</span>
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
        <h2>Risk Assessment</h2>
        <p>Identify, score, and manage threats to hospital information assets — <?= date('l, F j, Y') ?></p>
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
         SECTION 1: SUMMARY CARDS
    ============================================================ -->
    <div class="summary-cards section-gap">

        <!-- Total Risks -->
        <div class="summary-card">
            <div class="card-icon icon-total">📊</div>
            <div class="card-info">
                <div class="card-value"><?= $totalRisks ?></div>
                <div class="card-label">Total Risks</div>
            </div>
        </div>

        <!-- High Risks -->
        <div class="summary-card">
            <div class="card-icon icon-high">🔴</div>
            <div class="card-info">
                <div class="card-value" style="color:#EF4444;"><?= $highCount ?></div>
                <div class="card-label">High (Score 13–25)</div>
            </div>
        </div>

        <!-- Medium Risks -->
        <div class="summary-card">
            <div class="card-icon icon-medium">🟡</div>
            <div class="card-info">
                <div class="card-value" style="color:#F59E0B;"><?= $mediumCount ?></div>
                <div class="card-label">Medium (Score 5–12)</div>
            </div>
        </div>

        <!-- Low Risks -->
        <div class="summary-card">
            <div class="card-icon icon-low">🟢</div>
            <div class="card-info">
                <div class="card-value" style="color:#22C55E;"><?= $lowCount ?></div>
                <div class="card-label">Low (Score 1–4)</div>
            </div>
        </div>

    </div>
    <!-- End Summary Cards -->


    <!-- ============================================================
         SECTION 2: RISKS TABLE
    ============================================================ -->
    <div class="section-card section-gap">
        <div class="card-header-mv">
            <span>📋</span> Risk Register
            <div class="header-actions">
                <span style="font-size:12px; font-weight:400; opacity:0.85;">
                    <?= count($risks) ?> risk<?= count($risks) !== 1 ? 's' : '' ?>
                    <?= $filterAssetId > 0 ? '(filtered)' : '' ?>
                </span>
            </div>
        </div>

        <div class="card-body-mv">

            <!-- Asset Filter Bar -->
            <form method="GET" action="risks.php" class="filter-bar" id="filterForm">
                <label for="filter_asset">🔍 Filter by Asset:</label>
                <select name="filter_asset" id="filter_asset" onchange="this.form.submit()">
                    <option value="0" <?= $filterAssetId === 0 ? 'selected' : '' ?>>All Assets</option>
                    <?php foreach ($allAssets as $fa): ?>
                    <option value="<?= (int)$fa['id'] ?>"
                        <?= $filterAssetId === (int)$fa['id'] ? 'selected' : '' ?>>
                        <?= htmlspecialchars($fa['name'], ENT_QUOTES, 'UTF-8') ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <?php if ($filterAssetId > 0): ?>
                <a href="risks.php" class="btn-clear">✕ Clear Filter</a>
                <?php endif; ?>
            </form>

            <!-- Risks Table -->
            <div class="table-scroll">
                <table class="risks-table" id="risksTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Asset</th>
                            <th>Threat</th>
                            <th>Likelihood</th>
                            <th>Impact</th>
                            <th>Score</th>
                            <th>Level</th>
                            <th>Added By</th>
                            <th>Date Added</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($risks)): ?>
                        <tr>
                            <td colspan="10">
                                <div class="no-records">
                                    <span class="no-records-icon">⚠️</span>
                                    <p>
                                        <?php if ($filterAssetId > 0): ?>
                                            No risks found for the selected asset.
                                            <a href="risks.php" style="color:#2563EB;">Show all risks</a>
                                        <?php else: ?>
                                            No risks logged yet. Add your first risk below.
                                        <?php endif; ?>
                                    </p>
                                </div>
                            </td>
                        </tr>
                        <?php else: ?>
                        <?php foreach ($risks as $r):

                            $score = (int)$r['risk_score'];
                            $level = getRiskLevel($score);

                            // Row CSS class
                            $rowClass = match($level) {
                                'Low'    => 'risk-row-low',
                                'Medium' => 'risk-row-medium',
                                'High'   => 'risk-row-high',
                                default  => '',
                            };

                            // Badge CSS class
                            $badgeClass = match($level) {
                                'Low'    => 'badge-low',
                                'Medium' => 'badge-medium',
                                'High'   => 'badge-high',
                                default  => 'badge-low',
                            };

                            // Score pill CSS class
                            $scoreClass = match($level) {
                                'Low'    => 'score-low',
                                'Medium' => 'score-medium',
                                'High'   => 'score-high',
                                default  => 'score-low',
                            };

                        ?>
                        <tr class="<?= $rowClass ?>">
                            <td>
                                <span class="id-badge">#<?= (int)$r['id'] ?></span>
                            </td>
                            <td>
                                <span class="asset-name-cell">
                                    <?= htmlspecialchars($r['asset_name'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="threat-name-cell">
                                    <?= htmlspecialchars($r['threat'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="value-pill">
                                    <span class="num"><?= (int)$r['likelihood'] ?></span>
                                    <?= htmlspecialchars(getLikelihoodLabel((int)$r['likelihood']), ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="value-pill">
                                    <span class="num"><?= (int)$r['impact'] ?></span>
                                    <?= htmlspecialchars(getImpactLabel((int)$r['impact']), ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </td>
                            <td>
                                <span class="score-pill <?= $scoreClass ?>">
                                    <?= $score ?>
                                </span>
                            </td>
                            <td>
                                <span class="badge-risk <?= $badgeClass ?>">
                                    <?= $level ?>
                                </span>
                            </td>
                            <td style="color:#64748B; font-size:12px;">
                                <?= htmlspecialchars($r['added_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td style="color:#64748B; font-size:12px; white-space:nowrap;">
                                <?= date('M j, Y', strtotime($r['created_at'])) ?>
                            </td>
                            <td>
                                <div class="actions-cell">

                                    <!-- Edit button — triggers modal -->
                                    <button
                                        class="btn-action btn-edit"
                                        onclick="openEditModal(
                                            <?= (int)$r['id'] ?>,
                                            <?= (int)$r['asset_id'] ?>,
                                            '<?= addslashes(htmlspecialchars($r['threat'], ENT_QUOTES, 'UTF-8')) ?>',
                                            <?= (int)$r['likelihood'] ?>,
                                            <?= (int)$r['impact'] ?>
                                        )"
                                    >
                                        ✏️ Edit
                                    </button>

                                    <!-- Delete button — calls confirmDelete() -->
                                    <button
                                        class="btn-action btn-delete"
                                        onclick="confirmDelete(<?= (int)$r['id'] ?>, '<?= addslashes(htmlspecialchars($r['threat'], ENT_QUOTES, 'UTF-8')) ?>')"
                                    >
                                        🗑️ Delete
                                    </button>

                                    <!-- Hidden delete form — submitted by confirmDelete() -->
                                    <form
                                        id="deleteForm_<?= (int)$r['id'] ?>"
                                        method="POST"
                                        action="risks.php"
                                        class="delete-form"
                                    >
                                        <input type="hidden" name="action"     value="delete_risk">
                                        <input type="hidden" name="risk_id"    value="<?= (int)$r['id'] ?>">
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
            <!-- End Risks Table -->

        </div>
        <!-- End card-body-mv -->
    </div>
    <!-- End Risks Table Card -->


    <!-- ============================================================
         SECTION 3: ADD RISK FORM
    ============================================================ -->
    <div class="section-card section-gap">
        <div class="card-header-mv">
            <span>➕</span> Add New Risk
        </div>

        <div class="card-body-mv">
            <form method="POST" action="risks.php" id="addRiskForm" novalidate>
                <input type="hidden" name="action"     value="add_risk">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                <!-- Row 1: Asset / Threat -->
                <div class="form-row">
                    <div>
                        <label class="form-label-mv" for="add_asset_id">
                            Asset <span class="required-star">*</span>
                        </label>
                        <select id="add_asset_id" name="asset_id" class="form-control-mv" required>
                            <option value="" disabled selected>Select an asset</option>
                            <?php foreach ($allAssets as $asset): ?>
                            <option value="<?= (int)$asset['id'] ?>">
                                <?= htmlspecialchars($asset['name'], ENT_QUOTES, 'UTF-8') ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                        <?php if (empty($allAssets)): ?>
                        <p style="font-size:11px; color:#F59E0B; margin-top:5px;">
                            ⚠️ No assets found. <a href="assets.php" style="color:#2563EB;">Add an asset first.</a>
                        </p>
                        <?php endif; ?>
                    </div>
                    <div>
                        <label class="form-label-mv" for="add_threat">
                            Threat Name <span class="required-star">*</span>
                        </label>
                        <input
                            type="text"
                            id="add_threat"
                            name="threat"
                            class="form-control-mv"
                            placeholder="e.g. Unauthorized access to patient records"
                            maxlength="200"
                            required
                        >
                    </div>
                </div>

                <!-- Row 2: Likelihood / Impact -->
                <div class="form-row">
                    <div>
                        <label class="form-label-mv" for="add_likelihood">
                            Likelihood <span class="required-star">*</span>
                        </label>
                        <select id="add_likelihood" name="likelihood" class="form-control-mv" required onchange="updateAddScore()">
                            <option value="" disabled selected>Select likelihood</option>
                            <option value="1">1 — Very Unlikely</option>
                            <option value="2">2 — Unlikely</option>
                            <option value="3">3 — Possible</option>
                            <option value="4">4 — Likely</option>
                            <option value="5">5 — Very Likely</option>
                        </select>
                    </div>
                    <div>
                        <label class="form-label-mv" for="add_impact">
                            Impact <span class="required-star">*</span>
                        </label>
                        <select id="add_impact" name="impact" class="form-control-mv" required onchange="updateAddScore()">
                            <option value="" disabled selected>Select impact</option>
                            <option value="1">1 — Negligible</option>
                            <option value="2">2 — Minor</option>
                            <option value="3">3 — Moderate</option>
                            <option value="4">4 — Major</option>
                            <option value="5">5 — Critical</option>
                        </select>
                    </div>
                </div>

                <!-- Live Risk Score Display -->
                <div class="score-display" id="addScoreDisplay">
                    <div class="score-big" id="addScoreBig" style="background:#CBD5E1;">—</div>
                    <div class="score-info">
                        <div class="score-label">Calculated Risk Score</div>
                        <div class="score-level" id="addScoreLevel" style="color:#94A3B8;">
                            Select likelihood and impact
                        </div>
                        <div class="score-formula" id="addScoreFormula">
                            Score = Likelihood × Impact
                        </div>
                    </div>
                </div>

                <!-- Submit -->
                <div style="display:flex; align-items:center; gap:12px;">
                    <button type="submit" class="btn-submit">
                        ➕ Add Risk
                    </button>
                    <button type="reset" onclick="resetAddScore()" style="
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
    <!-- End Add Risk Form -->

    <!-- ============================================================
         SECTION 4: TRASH — deleted risks (Admin only, always shown)
    ============================================================ -->
    <div class="section-card section-gap">
        <div class="card-header-mv trash-card-header">
            <span>🗑️</span> Trash — Deleted Risks
            <div class="header-actions">
                <span style="font-size:12px; font-weight:400; opacity:0.85;">
                    <?= count($trashedRisks) ?> deleted record<?= count($trashedRisks) !== 1 ? 's' : '' ?>
                </span>
            </div>
        </div>

        <div class="card-body-mv">

            <?php if (empty($trashedRisks)): ?>
            <div class="no-records">
                <span class="no-records-icon">🗑️</span>
                <p>No deleted risks. Trash is empty.</p>
            </div>

            <?php else: ?>
            <div class="table-scroll">
                <table class="trash-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Asset</th>
                            <th>Threat</th>
                            <th>Score</th>
                            <th>Level</th>
                            <th>Deleted By</th>
                            <th>Deleted At</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($trashedRisks as $tr):
                            $tScore = (int)$tr['risk_score'];
                            $tLevel = getRiskLevel($tScore);
                            $tBadge = match($tLevel) {
                                'Low'    => 'badge-low',
                                'Medium' => 'badge-medium',
                                'High'   => 'badge-high',
                                default  => 'badge-low',
                            };
                        ?>
                        <tr>
                            <td><span class="id-badge">#<?= (int)$tr['id'] ?></span></td>
                            <td style="color:#2563EB; font-weight:600;">
                                <?= htmlspecialchars($tr['asset_name'], ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td><?= htmlspecialchars($tr['threat'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td>
                                <span class="score-pill score-<?= strtolower($tLevel) ?>">
                                    <?= $tScore ?>
                                </span>
                            </td>
                            <td>
                                <span class="badge-risk <?= $tBadge ?>">
                                    <?= $tLevel ?>
                                </span>
                            </td>
                            <td><?= htmlspecialchars($tr['deleted_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?></td>
                            <td style="white-space:nowrap;">
                                <?= date('M j, Y g:i A', strtotime($tr['deleted_at'])) ?>
                            </td>
                            <td>
                                <div class="actions-cell">
                                    <!-- Restore button -->
                                    <button
                                        class="btn-action btn-restore"
                                        onclick="confirmRestore(<?= (int)$tr['id'] ?>, '<?= addslashes(htmlspecialchars($tr['threat'], ENT_QUOTES, 'UTF-8')) ?>')"
                                    >
                                        ♻️ Restore
                                    </button>

                                    <!-- Hidden restore form -->
                                    <form
                                        id="restoreForm_<?= (int)$tr['id'] ?>"
                                        method="POST"
                                        action="risks.php"
                                        class="delete-form"
                                    >
                                        <input type="hidden" name="action"     value="restore_risk">
                                        <input type="hidden" name="risk_id"    value="<?= (int)$tr['id'] ?>">
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
    <!-- End Trash Section -->

</main>
<!-- End Main Content -->


<!-- ============================================================
     EDIT RISK MODAL — Bootstrap 5
============================================================ -->
<div class="modal fade" id="editRiskModal" tabindex="-1" aria-labelledby="editRiskModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content" style="border:none; border-radius:12px; overflow:hidden;">

            <div class="modal-header-mv d-flex align-items-center justify-content-between">
                <span class="modal-title" id="editRiskModalLabel">✏️ Edit Risk</span>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close" style="filter:invert(1); opacity:0.8;"></button>
            </div>

            <form method="POST" action="risks.php" id="editRiskForm" novalidate>
                <input type="hidden" name="action"     value="edit_risk">
                <input type="hidden" name="risk_id"    id="edit_risk_id"  value="">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                <div class="modal-body-mv">

                    <!-- Asset -->
                    <div class="form-group">
                        <label class="form-label-mv" for="edit_asset_id">
                            Asset <span class="required-star">*</span>
                        </label>
                        <select id="edit_asset_id" name="asset_id" class="form-control-mv" required>
                            <option value="" disabled>Select an asset</option>
                            <?php foreach ($allAssets as $asset): ?>
                            <option value="<?= (int)$asset['id'] ?>">
                                <?= htmlspecialchars($asset['name'], ENT_QUOTES, 'UTF-8') ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- Threat -->
                    <div class="form-group">
                        <label class="form-label-mv" for="edit_threat">
                            Threat Name <span class="required-star">*</span>
                        </label>
                        <input
                            type="text"
                            id="edit_threat"
                            name="threat"
                            class="form-control-mv"
                            maxlength="200"
                            required
                        >
                    </div>

                    <!-- Likelihood / Impact -->
                    <div class="form-row" style="margin-bottom:16px;">
                        <div>
                            <label class="form-label-mv" for="edit_likelihood">
                                Likelihood <span class="required-star">*</span>
                            </label>
                            <select id="edit_likelihood" name="likelihood" class="form-control-mv" required onchange="updateEditScore()">
                                <option value="1">1 — Very Unlikely</option>
                                <option value="2">2 — Unlikely</option>
                                <option value="3">3 — Possible</option>
                                <option value="4">4 — Likely</option>
                                <option value="5">5 — Very Likely</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label-mv" for="edit_impact">
                                Impact <span class="required-star">*</span>
                            </label>
                            <select id="edit_impact" name="impact" class="form-control-mv" required onchange="updateEditScore()">
                                <option value="1">1 — Negligible</option>
                                <option value="2">2 — Minor</option>
                                <option value="3">3 — Moderate</option>
                                <option value="4">4 — Major</option>
                                <option value="5">5 — Critical</option>
                            </select>
                        </div>
                    </div>

                    <!-- Live Score Display (inside modal) -->
                    <div class="score-display" id="editScoreDisplay" style="margin-bottom:0;">
                        <div class="score-big" id="editScoreBig" style="background:#CBD5E1;">—</div>
                        <div class="score-info">
                            <div class="score-label">Calculated Risk Score</div>
                            <div class="score-level" id="editScoreLevel" style="color:#94A3B8;">
                                —
                            </div>
                            <div class="score-formula" id="editScoreFormula">
                                Score = Likelihood × Impact
                            </div>
                        </div>
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
<!-- End Edit Risk Modal -->


<!-- ============================================================
     SCRIPTS — Bootstrap CDN last, then page-specific JS
============================================================ -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    // ============================================================
    // MOBILE HAMBURGER SIDEBAR TOGGLE — identical to assets.php
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
    // SESSION TIMEOUT WARNING — exact spec JS
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
    // RISK SCORE CALCULATOR — shared logic
    // score = likelihood × impact
    // level: 1-4=Low, 5-12=Medium, 13-25=High
    // Returns { score, level, color, bg }
    // ============================================================
    function calcRisk(likelihood, impact) {
        var score = likelihood * impact;
        var level, color;

        if (score <= 4) {
            level = 'Low';
            color = '#22C55E';
        } else if (score <= 12) {
            level = 'Medium';
            color = '#F59E0B';
        } else {
            level = 'High';
            color = '#EF4444';
        }

        return { score: score, level: level, color: color };
    }

    // ============================================================
    // UPDATE SCORE DISPLAY — ADD FORM
    // Called onchange from likelihood and impact selects
    // ============================================================
    function updateAddScore() {
        var likelihood = parseInt(document.getElementById('add_likelihood').value) || 0;
        var impact     = parseInt(document.getElementById('add_impact').value)     || 0;

        var bigEl    = document.getElementById('addScoreBig');
        var levelEl  = document.getElementById('addScoreLevel');
        var formulaEl = document.getElementById('addScoreFormula');

        if (!likelihood || !impact) {
            bigEl.textContent    = '—';
            bigEl.style.background = '#CBD5E1';
            levelEl.textContent  = 'Select likelihood and impact';
            levelEl.style.color  = '#94A3B8';
            formulaEl.textContent = 'Score = Likelihood × Impact';
            return;
        }

        var result = calcRisk(likelihood, impact);

        bigEl.textContent      = result.score;
        bigEl.style.background = result.color;
        levelEl.textContent    = result.level + ' Risk';
        levelEl.style.color    = result.color;
        formulaEl.textContent  = likelihood + ' × ' + impact + ' = ' + result.score;
    }

    // ============================================================
    // RESET SCORE DISPLAY — ADD FORM (on "Clear form" click)
    // ============================================================
    function resetAddScore() {
        setTimeout(function() {
            updateAddScore();
        }, 10);
    }

    // ============================================================
    // UPDATE SCORE DISPLAY — EDIT MODAL
    // Called onchange from edit modal's selects
    // ============================================================
    function updateEditScore() {
        var likelihood = parseInt(document.getElementById('edit_likelihood').value) || 0;
        var impact     = parseInt(document.getElementById('edit_impact').value)     || 0;

        var bigEl     = document.getElementById('editScoreBig');
        var levelEl   = document.getElementById('editScoreLevel');
        var formulaEl = document.getElementById('editScoreFormula');

        if (!likelihood || !impact) {
            bigEl.textContent      = '—';
            bigEl.style.background = '#CBD5E1';
            levelEl.textContent    = '—';
            levelEl.style.color    = '#94A3B8';
            formulaEl.textContent  = 'Score = Likelihood × Impact';
            return;
        }

        var result = calcRisk(likelihood, impact);

        bigEl.textContent      = result.score;
        bigEl.style.background = result.color;
        levelEl.textContent    = result.level + ' Risk';
        levelEl.style.color    = result.color;
        formulaEl.textContent  = likelihood + ' × ' + impact + ' = ' + result.score;
    }

    // ============================================================
    // openEditModal() — populates edit modal with row data
    // Called from each row's Edit button via inline onclick
    // ============================================================
    function openEditModal(riskId, assetId, threat, likelihood, impact) {
        document.getElementById('edit_risk_id').value      = riskId;
        document.getElementById('edit_threat').value       = threat;
        document.getElementById('edit_likelihood').value   = likelihood;
        document.getElementById('edit_impact').value       = impact;
        document.getElementById('edit_asset_id').value     = assetId;

        // Trigger live score update so modal shows correct score on open
        updateEditScore();

        // Show Bootstrap modal
        var modal = new bootstrap.Modal(document.getElementById('editRiskModal'));
        modal.show();
    }

    // ============================================================
    // confirmDelete() — spec names this function explicitly
    // Shows native confirmation dialog, submits the hidden form
    // ============================================================
    function confirmDelete(riskId, threatName) {
        if (confirm(
            '🗑️ Move to Trash\n\n' +
            'Move this risk to trash?\n' +
            '"' + threatName + '"\n\n' +
            'You can restore it later from the Trash section.'
        )) {
            var form = document.getElementById('deleteForm_' + riskId);
            if (form) {
                form.submit();
            }
        }
    }

    // ============================================================
    // confirmRestore() — submits the hidden restore form
    // ============================================================
    function confirmRestore(riskId, threatName) {
        if (confirm(
            '♻️ Restore Risk\n\n' +
            'Restore this risk back to the active register?\n' +
            '"' + threatName + '"'
        )) {
            var form = document.getElementById('restoreForm_' + riskId);
            if (form) {
                form.submit();
            }
        }
    }

    // ============================================================
    // CLIENT-SIDE FORM VALIDATION — add risk form
    // PHP validates again server-side — this is a UX shortcut only
    // ============================================================
    var addForm = document.getElementById('addRiskForm');
    if (addForm) {
        addForm.addEventListener('submit', function(e) {
            var assetId    = document.getElementById('add_asset_id').value;
            var threat     = document.getElementById('add_threat').value.trim();
            var likelihood = document.getElementById('add_likelihood').value;
            var impact     = document.getElementById('add_impact').value;

            if (!assetId) {
                alert('Please select an asset.');
                e.preventDefault(); return;
            }
            if (!threat) {
                alert('Please enter a threat name.');
                e.preventDefault(); return;
            }
            if (!likelihood) {
                alert('Please select a likelihood value.');
                e.preventDefault(); return;
            }
            if (!impact) {
                alert('Please select an impact value.');
                e.preventDefault(); return;
            }
        });
    }

    // ============================================================
    // CLIENT-SIDE FORM VALIDATION — edit risk modal form
    // ============================================================
    var editForm = document.getElementById('editRiskForm');
    if (editForm) {
        editForm.addEventListener('submit', function(e) {
            var assetId    = document.getElementById('edit_asset_id').value;
            var threat     = document.getElementById('edit_threat').value.trim();
            var likelihood = document.getElementById('edit_likelihood').value;
            var impact     = document.getElementById('edit_impact').value;

            if (!assetId) {
                alert('Please select an asset.');
                e.preventDefault(); return;
            }
            if (!threat) {
                alert('Please enter a threat name.');
                e.preventDefault(); return;
            }
            if (!likelihood) {
                alert('Please select a likelihood value.');
                e.preventDefault(); return;
            }
            if (!impact) {
                alert('Please select an impact value.');
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