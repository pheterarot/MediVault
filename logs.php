<?php
// ============================================================
// MEDIVAULT — logs.php
// Purpose:  Activity log viewer — admin reviews all system
//           events, suspicious flags, and filtered searches
// Layout:   Full sidebar (identical to dashboard.php)
// Access:   Admin only
//
// Features:
//   View-only table — no add or edit
//   Soft-delete per log row (Admin only)
//   Restore from Trash (Admin only)
//   Columns: ID, User Name, Action, IP Address,
//            Suspicious, Flagged Reason, Timestamp, Actions
//   Suspicious rows: #FEF2F2 background, red badge
//   Filters via GET: date_from, date_to, user_id, suspicious_only
//   Pagination: 20 rows per page, newest first
//   Export modal: user dropdown shows deleted users as "Name (Deleted)"
//                 checkbox: "Include deleted log entries"
//   Export link → audit.php
//
// Security:
//   requireRole(['admin']) — hard block all others
//   Prepared statements with bound params for all filters
//   All inputs sanitized before use
//   Page access logged to activity_logs
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';
// ============================================================
// ACCESS CONTROL — Admin only
// ============================================================
requireRole(['admin']);

$userId   = $_SESSION['user_id'];
$userName = $_SESSION['user_name'];
$userRole = $_SESSION['user_role'];
$ip       = getUserIP();

// ============================================================
// POST HANDLER — soft_delete_log and restore_log
// ============================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CSRF check
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== ($_SESSION['csrf_token'] ?? '')) {
        header('Location: logs.php?error=Invalid+request');
        exit;
    }

    $action = $_POST['action'] ?? '';

    // --------------------------------------------------------
    // ACTION: SOFT DELETE LOG ENTRY
    // --------------------------------------------------------
    if ($action === 'soft_delete_log') {

        $logId = (int)($_POST['log_id'] ?? 0);

        if ($logId <= 0) {
            header('Location: logs.php?error=Invalid+log+ID');
            exit;
        }

        // Verify entry exists and is not already soft-deleted
        $check = $conn->prepare("SELECT id FROM activity_logs WHERE id = ? AND deleted_at IS NULL");
        $check->bind_param("i", $logId);
        $check->execute();
        $exists = $check->get_result()->fetch_assoc();
        $check->close();

        if (!$exists) {
            header('Location: logs.php?error=Log+entry+not+found');
            exit;
        }

        $stmt = $conn->prepare(
            "UPDATE activity_logs
             SET deleted_at = NOW(), deleted_by = ?
             WHERE id = ?"
        );
        $stmt->bind_param("ii", $userId, $logId);
        $stmt->execute();
        $stmt->close();

        logActivity($conn, $userId, "Soft deleted log entry ID: {$logId}", $ip);

        header('Location: logs.php?success=Log+entry+moved+to+trash');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: RESTORE LOG ENTRY
    // --------------------------------------------------------
    if ($action === 'restore_log') {

        $logId = (int)($_POST['log_id'] ?? 0);

        if ($logId <= 0) {
            header('Location: logs.php?error=Invalid+log+ID');
            exit;
        }

        // Verify entry is actually in trash
        $check = $conn->prepare("SELECT id FROM activity_logs WHERE id = ? AND deleted_at IS NOT NULL");
        $check->bind_param("i", $logId);
        $check->execute();
        $exists = $check->get_result()->fetch_assoc();
        $check->close();

        if (!$exists) {
            header('Location: logs.php?error=Log+entry+not+found+in+trash');
            exit;
        }

        $stmt = $conn->prepare(
            "UPDATE activity_logs
             SET deleted_at = NULL, deleted_by = NULL
             WHERE id = ?"
        );
        $stmt->bind_param("i", $logId);
        $stmt->execute();
        $stmt->close();

        logActivity($conn, $userId, "Restored log entry ID: {$logId}", $ip);

        header('Location: logs.php?success=Log+entry+restored+successfully');
        exit;
    }

    // Unknown action
    header('Location: logs.php');
    exit;
}
// ============================================================
// END POST HANDLER
// ============================================================

// ============================================================
// LOG PAGE ACCESS
// ============================================================
logActivity($conn, $userId, "Viewed activity logs", $ip);

// ============================================================
// PAGINATION CONFIG
// ============================================================
define('LOGS_PER_PAGE', 20);

$page    = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$offset  = ($page - 1) * LOGS_PER_PAGE;

// ============================================================
// FILTER INPUTS — all from GET, sanitized before use
// ============================================================
$filterDateFrom     = isset($_GET['date_from'])      ? clean($_GET['date_from'])      : '';
$filterDateTo       = isset($_GET['date_to'])        ? clean($_GET['date_to'])        : '';
$filterUserId       = isset($_GET['user_id'])        ? (int)$_GET['user_id']          : 0;
$filterSuspicious   = isset($_GET['suspicious_only']) && $_GET['suspicious_only'] === '1';

// ============================================================
// BUILD DYNAMIC WHERE CLAUSE
// Uses arrays to collect conditions and param bind values
// so no SQL string concatenation ever touches user input
// ============================================================
$conditions = [];
$bindTypes  = '';
$bindValues = [];

// Batch 7 — always exclude soft-deleted log entries by default
$conditions[] = "al.deleted_at IS NULL";

if (!empty($filterDateFrom)) {
    $conditions[] = "DATE(al.timestamp) >= ?";
    $bindTypes   .= 's';
    $bindValues[] = $filterDateFrom;
}

if (!empty($filterDateTo)) {
    $conditions[] = "DATE(al.timestamp) <= ?";
    $bindTypes   .= 's';
    $bindValues[] = $filterDateTo;
}

if ($filterUserId > 0) {
    $conditions[] = "al.user_id = ?";
    $bindTypes   .= 'i';
    $bindValues[] = $filterUserId;
}

if ($filterSuspicious) {
    $conditions[] = "al.is_suspicious = 1";
    // no bind param needed — literal value
}

$whereClause = '';
if (!empty($conditions)) {
    $whereClause = 'WHERE ' . implode(' AND ', $conditions);
}

// ============================================================
// COUNT TOTAL ROWS (for pagination)
// ============================================================
$countSql  = "SELECT COUNT(*) AS total
              FROM activity_logs al
              LEFT JOIN users u ON u.id = al.user_id
              {$whereClause}";

$stmtCount = $conn->prepare($countSql);

if (!empty($bindValues)) {
    $stmtCount->bind_param($bindTypes, ...$bindValues);
}

$stmtCount->execute();
$totalRows  = (int)$stmtCount->get_result()->fetch_assoc()['total'];
$stmtCount->close();

$totalPages = max(1, (int)ceil($totalRows / LOGS_PER_PAGE));
$page       = min($page, $totalPages); // clamp page to valid range

// ============================================================
// FETCH LOG ROWS — newest first, paginated
// ============================================================
$dataSql = "SELECT al.id,
                   u.name    AS user_name,
                   al.action,
                   al.ip_address,
                   al.is_suspicious,
                   al.flagged_reason,
                   al.timestamp
            FROM activity_logs al
            LEFT JOIN users u ON u.id = al.user_id
            {$whereClause}
            ORDER BY al.id DESC, al.timestamp DESC
            LIMIT ? OFFSET ?";

$stmtData = $conn->prepare($dataSql);

// Append pagination params to bind list
$dataTypes  = $bindTypes . 'ii';
$dataValues = array_merge($bindValues, [LOGS_PER_PAGE, $offset]);

$stmtData->bind_param($dataTypes, ...$dataValues);
$stmtData->execute();
$result = $stmtData->get_result();
$logs   = [];
while ($row = $result->fetch_assoc()) {
    $logs[] = $row;
}
$stmtData->close();

// ============================================================
// FETCH ALL USERS — for filter dropdown (non-deleted only)
// Batch 7: WHERE deleted_at IS NULL
// ============================================================
$allUsers = [];
$stmtU = $conn->prepare("SELECT id, name FROM users WHERE deleted_at IS NULL ORDER BY name ASC");
$stmtU->execute();
$resU = $stmtU->get_result();
while ($row = $resU->fetch_assoc()) {
    $allUsers[] = $row;
}
$stmtU->close();

// ============================================================
// FETCH USERS FOR EXPORT MODAL — includes deleted, labeled
// Batch 7: "Name (Deleted)" for soft-deleted users
// ============================================================
$exportUsers = [];
$stmtEU = $conn->prepare("SELECT id, name, deleted_at FROM users ORDER BY (deleted_at IS NULL) DESC, name ASC");
$stmtEU->execute();
$resEU = $stmtEU->get_result();
while ($row = $resEU->fetch_assoc()) {
    $exportUsers[] = $row;
}
$stmtEU->close();

// ============================================================
// FETCH SOFT-DELETED (TRASHED) LOG ENTRIES — Trash section
// ============================================================
$trashedLogs   = [];
$totalTrashed  = 0;
$stmtT = $conn->prepare(
    "SELECT al.id, u.name AS user_name, al.action, al.ip_address,
            al.is_suspicious, al.flagged_reason, al.timestamp,
            al.deleted_at,
            du.name AS deleted_by_name
     FROM activity_logs al
     LEFT JOIN users u  ON u.id  = al.user_id
     LEFT JOIN users du ON du.id = al.deleted_by
     WHERE al.deleted_at IS NOT NULL
     ORDER BY al.deleted_at DESC"
);
$stmtT->execute();
$resT = $stmtT->get_result();
while ($row = $resT->fetch_assoc()) {
    $trashedLogs[] = $row;
}
$stmtT->close();
$totalTrashed = count($trashedLogs);

// ============================================================
// BUILD QUERY STRING — preserves filters across pagination links
// ============================================================
function buildQueryString($overrides = []) {
    $params = [];

    if (!empty($_GET['date_from']))      $params['date_from']      = clean($_GET['date_from']);
    if (!empty($_GET['date_to']))        $params['date_to']        = clean($_GET['date_to']);
    if (!empty($_GET['user_id']))        $params['user_id']        = (int)$_GET['user_id'];
    if (!empty($_GET['suspicious_only'])) $params['suspicious_only'] = '1';

    foreach ($overrides as $k => $v) {
        if ($v === null) {
            unset($params[$k]);
        } else {
            $params[$k] = $v;
        }
    }

    return http_build_query($params);
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Activity Logs</title>
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
           SIDEBAR — exact match to dashboard.php
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
           MAIN CONTENT
        ====================================================== */
        .main-content {
            margin-left: 250px;
            padding: 30px;
            padding-top: 90px;
            min-height: 100vh;
        }

        .page-header {
            margin-bottom: 25px;
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }

        .page-header-text h2 {
            font-size: 24px;
            font-weight: 700;
            color: #1E293B;
            margin: 0;
        }

        .page-header-text p {
            color: #94A3B8;
            font-size: 13px;
            margin: 5px 0 0;
        }

        /* ======================================================
           EXPORT BUTTON
        ====================================================== */
        .btn-export {
            background: #22C55E;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 13px;
            font-weight: 600;
            padding: 9px 20px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: background 0.2s, transform 0.2s;
            white-space: nowrap;
        }

        .btn-export:hover {
            background: #16A34A;
            color: #ffffff;
            transform: translateY(-1px);
        }

        /* ======================================================
           FILTER CARD
        ====================================================== */
        .filter-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            background: #ffffff;
            margin-bottom: 24px;
            overflow: hidden;
        }

        .filter-card .filter-header {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            font-weight: 600;
            font-size: 14px;
            padding: 13px 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .filter-card .filter-body {
            padding: 20px;
        }

        .form-label {
            font-size: 12px;
            font-weight: 600;
            color: #475569;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        .form-control,
        .form-select {
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 13px;
            color: #1E293B;
            padding: 8px 12px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: #2563EB;
            box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
            outline: none;
        }

        .btn-filter {
            background: #2563EB;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 13px;
            font-weight: 600;
            padding: 8px 20px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .btn-filter:hover {
            background: #1E40AF;
        }

        .btn-reset {
            background: #F1F5F9;
            color: #475569;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 13px;
            font-weight: 600;
            padding: 8px 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            transition: background 0.2s;
        }

        .btn-reset:hover {
            background: #E2E8F0;
            color: #1E293B;
        }

        .suspicious-checkbox-label {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            font-weight: 500;
            color: #1E293B;
            cursor: pointer;
            margin-top: 6px;
        }

        .suspicious-checkbox-label input[type="checkbox"] {
            width: 16px;
            height: 16px;
            accent-color: #EF4444;
            cursor: pointer;
        }

        /* ======================================================
           RESULTS SUMMARY BAR
        ====================================================== */
        .results-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 16px;
            padding: 10px 14px;
            background: #ffffff;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-size: 13px;
            color: #475569;
        }

        .results-bar .results-count {
            font-weight: 600;
            color: #1E293B;
        }

        /* ======================================================
           LOGS TABLE
        ====================================================== */
        .section-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            background: #ffffff;
            overflow: hidden;
        }

        .section-card .card-header-mv {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            font-weight: 600;
            font-size: 15px;
            padding: 15px 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .table-mv {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .table-mv thead th {
            background: #F8FAFC;
            color: #475569;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 11px 14px;
            border-bottom: 2px solid #E2E8F0;
            white-space: nowrap;
        }

        .table-mv tbody tr {
            border-bottom: 1px solid #F1F5F9;
            transition: background 0.15s;
        }

        .table-mv tbody tr:last-child {
            border-bottom: none;
        }

        /* Normal row hover */
        .table-mv tbody tr:not(.row-suspicious):hover {
            background: #F8FAFC;
        }

        /* Suspicious row — spec color #FEF2F2 */
        .table-mv tbody tr.row-suspicious {
            background: #FEF2F2;
        }

        .table-mv tbody tr.row-suspicious:hover {
            background: #FEE2E2;
        }

        .table-mv tbody td {
            padding: 11px 14px;
            color: #1E293B;
            vertical-align: middle;
        }

        /* Action cell — truncate long strings */
        .action-cell {
            max-width: 220px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* Flagged reason cell */
        .reason-cell {
            max-width: 180px;
            font-size: 12px;
            color: #EF4444;
            font-weight: 500;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* ======================================================
           BADGES
        ====================================================== */
        .badge-suspicious {
            background: #EF4444;
            color: #ffffff;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }

        .badge-normal {
            background: #E2E8F0;
            color: #475569;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }

        /* ======================================================
           ACTION BUTTONS (inline per row)
        ====================================================== */
        .btn-action {
            border: none;
            border-radius: 6px;
            font-family: 'Poppins', sans-serif;
            font-size: 11px;
            font-weight: 600;
            padding: 5px 10px;
            cursor: pointer;
            transition: background 0.2s, color 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            white-space: nowrap;
        }

        .btn-soft-delete {
            background: #FEF2F2;
            color: #B91C1C;
        }

        .btn-soft-delete:hover {
            background: #EF4444;
            color: #ffffff;
        }

        /* ======================================================
           SECTION GAP
        ====================================================== */
        .section-gap {
            margin-top: 28px;
        }

        /* ======================================================
           TRASH SECTION — mirrors assets.php design
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

        .card-body-mv {
            padding: 20px;
        }

        /* ======================================================
           EMPTY STATE
        ====================================================== */
        .empty-state {
            text-align: center;
            padding: 50px 20px;
            color: #94A3B8;
        }

        .empty-state .empty-icon {
            font-size: 40px;
            display: block;
            margin-bottom: 10px;
        }

        .no-records {
            text-align: center;
            padding: 30px 20px;
            color: #94A3B8;
        }

        .no-records-icon {
            font-size: 32px;
            display: block;
            margin-bottom: 8px;
        }

        /* ======================================================
           PAGINATION
        ====================================================== */
        .pagination-wrapper {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            padding: 16px 20px;
            border-top: 1px solid #F1F5F9;
        }

        .pagination-info {
            font-size: 12px;
            color: #94A3B8;
        }

        .pagination-links {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .page-link-mv {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 34px;
            height: 34px;
            padding: 0 10px;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 500;
            color: #475569;
            text-decoration: none;
            transition: all 0.2s;
            font-family: 'Poppins', sans-serif;
            background: #ffffff;
        }

        .page-link-mv:hover {
            background: #EFF6FF;
            border-color: #2563EB;
            color: #2563EB;
        }

        .page-link-mv.active {
            background: #2563EB;
            border-color: #2563EB;
            color: #ffffff;
            font-weight: 600;
        }

        .page-link-mv.disabled {
            opacity: 0.4;
            pointer-events: none;
            cursor: default;
        }

        /* ======================================================
           ACTIVE FILTER PILLS
        ====================================================== */
        .filter-pills {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: 16px;
        }

        .filter-pill {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            background: #EFF6FF;
            border: 1px solid #BFDBFE;
            color: #1E40AF;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }

        .filter-pill.suspicious-pill {
            background: #FEF2F2;
            border-color: #FECACA;
            color: #991B1B;
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
           TOAST / ALERT BANNER
        ====================================================== */
        .alert-banner {
            border-radius: 10px;
            padding: 12px 18px;
            margin-bottom: 20px;
            font-size: 13px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
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
           RESPONSIVE
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

            .page-header {
                flex-direction: column;
                align-items: flex-start;
            }
        }

        @media (min-width: 769px) {
            .hamburger {
                display: none !important;
            }
        }
    </style>
</head>
<body>

<!-- MOBILE OVERLAY -->
<div id="overlay"></div>

<!-- ============================================================
     SIDEBAR — identical to dashboard.php, active on Logs
============================================================ -->
<aside class="sidebar" id="sidebar">

    <div class="sidebar-brand">
        <h4>🏥 MediVault</h4>
        <p>Securing Patient Records. Protecting Lives.</p>
    </div>

    <nav>
        <a href="dashboard.php">
            <span>📊</span> Dashboard
        </a>

        <a href="patients.php">
            <span>👤</span> Patients
        </a>

        <!-- Admin only links -->
        <a href="assets.php">
            <span>🏗️</span> Assets
        </a>

        <a href="risks.php">
            <span>⚠️</span> Risks
        </a>

        <a href="incidents.php">
            <span>🚨</span> Incidents
        </a>

        <a href="logs.php" class="active">
            <span>📋</span> Logs
        </a>

        <a href="users.php">
            <span>👥</span> Users
        </a>

        <a href="policy.php">
            <span>📄</span> Policy
        </a>

    </nav>

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

<!-- ============================================================
     TOPBAR
============================================================ -->
<div class="topbar">
    <button class="hamburger" id="hamburger" aria-label="Toggle navigation">&#9776;</button>
    <span class="topbar-title">📋 Activity Logs</span>
    <div class="topbar-right">
        <span class="topbar-user">Welcome back, <?= htmlspecialchars($userName, ENT_QUOTES, 'UTF-8') ?></span>
        <span class="topbar-role-badge"><?= htmlspecialchars($userRole, ENT_QUOTES, 'UTF-8') ?></span>
    </div>
</div>

<!-- ============================================================
     MAIN CONTENT
============================================================ -->
<main class="main-content">

    <!-- PAGE HEADER -->
    <div class="page-header">
        <div class="page-header-text">
            <h2>Activity Logs</h2>
            <p>Full audit trail of all system events — admins can soft-delete individual entries</p>
        </div>
        <button
            type="button"
            class="btn-export"
            data-bs-toggle="modal"
            data-bs-target="#exportAuditModal"
        >
            📄 Export PDF
        </button>
    </div>

    <!-- ========================================================
         FLASH MESSAGES
    ========================================================= -->
    <?php if (!empty($_GET['success'])): ?>
    <div class="alert-banner alert-success">
        ✅ <?= htmlspecialchars($_GET['success'], ENT_QUOTES, 'UTF-8') ?>
    </div>
    <?php endif; ?>
    <?php if (!empty($_GET['error'])): ?>
    <div class="alert-banner alert-error">
        ❌ <?= htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8') ?>
    </div>
    <?php endif; ?>

    <!-- ========================================================
         FILTER FORM — GET submission preserves state
    ========================================================= -->`
    <div class="filter-card">
        <div class="filter-header">
            🔍 Filter Logs
        </div>
        <div class="filter-body">
            <form method="GET" action="logs.php">

                <div class="row g-3 align-items-end">

                    <!-- Date From -->
                    <div class="col-12 col-md-3">
                        <label class="form-label" for="date_from">Date From</label>
                        <input
                            type="date"
                            class="form-control"
                            id="date_from"
                            name="date_from"
                            value="<?= htmlspecialchars($filterDateFrom, ENT_QUOTES, 'UTF-8') ?>"
                        >
                    </div>

                    <!-- Date To -->
                    <div class="col-12 col-md-3">
                        <label class="form-label" for="date_to">Date To</label>
                        <input
                            type="date"
                            class="form-control"
                            id="date_to"
                            name="date_to"
                            value="<?= htmlspecialchars($filterDateTo, ENT_QUOTES, 'UTF-8') ?>"
                        >
                    </div>

                    <!-- User Dropdown — non-deleted users only -->
                    <div class="col-12 col-md-3">
                        <label class="form-label" for="user_id">User</label>
                        <select class="form-select" id="user_id" name="user_id">
                            <option value="">— All Users —</option>
                            <?php foreach ($allUsers as $u): ?>
                                <option
                                    value="<?= (int)$u['id'] ?>"
                                    <?= $filterUserId === (int)$u['id'] ? 'selected' : '' ?>
                                >
                                    <?= htmlspecialchars($u['name'], ENT_QUOTES, 'UTF-8') ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- Suspicious Only checkbox + buttons -->
                    <div class="col-12 col-md-3">
                        <label class="form-label" style="display:block;">&nbsp;</label>
                        <label class="suspicious-checkbox-label" style="margin-bottom: 10px;">
                            <input
                                type="checkbox"
                                name="suspicious_only"
                                value="1"
                                <?= $filterSuspicious ? 'checked' : '' ?>
                            >
                            🚨 Suspicious only
                        </label>
                        <div style="display:flex; gap:8px;">
                            <button type="submit" class="btn-filter">Apply</button>
                            <a href="logs.php" class="btn-reset">✕ Reset</a>
                        </div>
                    </div>

                </div>

            </form>
        </div>
    </div>

    <!-- ========================================================
         ACTIVE FILTER PILLS — show what filters are applied
    ========================================================= -->
    <?php
    $hasFilters = $filterDateFrom || $filterDateTo || $filterUserId > 0 || $filterSuspicious;
    if ($hasFilters):
    ?>
    <div class="filter-pills">
        <?php if ($filterDateFrom): ?>
            <span class="filter-pill">📅 From: <?= htmlspecialchars($filterDateFrom, ENT_QUOTES, 'UTF-8') ?></span>
        <?php endif; ?>
        <?php if ($filterDateTo): ?>
            <span class="filter-pill">📅 To: <?= htmlspecialchars($filterDateTo, ENT_QUOTES, 'UTF-8') ?></span>
        <?php endif; ?>
        <?php if ($filterUserId > 0): ?>
            <?php
            $filteredUserName = '';
            foreach ($allUsers as $u) {
                if ((int)$u['id'] === $filterUserId) {
                    $filteredUserName = $u['name'];
                    break;
                }
            }
            ?>
            <span class="filter-pill">👤 User: <?= htmlspecialchars($filteredUserName, ENT_QUOTES, 'UTF-8') ?></span>
        <?php endif; ?>
        <?php if ($filterSuspicious): ?>
            <span class="filter-pill suspicious-pill">🚨 Suspicious Only</span>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <!-- RESULTS SUMMARY BAR -->
    <div class="results-bar">
        <span>
            Showing
            <span class="results-count">
                <?php
                $from = $totalRows > 0 ? $offset + 1 : 0;
                $to   = min($offset + LOGS_PER_PAGE, $totalRows);
                echo $from . '–' . $to;
                ?>
            </span>
            of
            <span class="results-count"><?= number_format($totalRows) ?></span>
            log <?= $totalRows === 1 ? 'entry' : 'entries' ?>
            <?= $hasFilters ? '(filtered)' : '' ?>
        </span>
        <span style="font-size:12px; color:#94A3B8;">
            Page <?= $page ?> of <?= $totalPages ?>
        </span>
    </div>

    <!-- ========================================================
         LOGS TABLE — Admin can soft-delete rows
    ========================================================= -->
    <div class="section-card">
        <div class="card-header-mv">
            📋 Log Entries
        </div>

        <?php if (empty($logs)): ?>
            <div class="empty-state">
                <span class="empty-icon">📭</span>
                No log entries found for the selected filters.
            </div>

        <?php else: ?>
            <div class="table-responsive">
                <table class="table-mv">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>IP Address</th>
                            <th>Suspicious</th>
                            <th>Flagged Reason</th>
                            <th>Timestamp</th>
                            <?php if ($userRole === 'admin'): ?>
                            <th>Actions</th>
                            <?php endif; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                        <?php $isSuspicious = (int)$log['is_suspicious'] === 1; ?>
                        <tr class="<?= $isSuspicious ? 'row-suspicious' : '' ?>"
                            data-id="<?= (int)$log['id'] ?>"
                            data-user="<?= htmlspecialchars($log['user_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>"
                            data-action="<?= htmlspecialchars($log['action'], ENT_QUOTES, 'UTF-8') ?>"
                            data-ip="<?= htmlspecialchars($log['ip_address'] ?? '—', ENT_QUOTES, 'UTF-8') ?>"
                            data-suspicious="<?= $isSuspicious ? 'Yes' : 'No' ?>"
                            data-reason="<?= htmlspecialchars($log['flagged_reason'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                            data-timestamp="<?= htmlspecialchars($log['timestamp'], ENT_QUOTES, 'UTF-8') ?>"
                        >

                            <!-- ID -->
                            <td style="color:#94A3B8; font-weight:600; white-space:nowrap; cursor:pointer;"
                                onclick="openLogDetail(this.closest('tr'))"
                            >
                                #<?= (int)$log['id'] ?>
                            </td>

                            <!-- User Name -->
                            <td style="font-weight:600; white-space:nowrap; cursor:pointer;"
                                onclick="openLogDetail(this.closest('tr'))"
                            >
                                <?= htmlspecialchars($log['user_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>

                            <!-- Action -->
                            <td style="cursor:pointer;" onclick="openLogDetail(this.closest('tr'))">
                                <div
                                    class="action-cell"
                                    title="<?= htmlspecialchars($log['action'], ENT_QUOTES, 'UTF-8') ?>"
                                >
                                    <?= htmlspecialchars($log['action'], ENT_QUOTES, 'UTF-8') ?>
                                </div>
                            </td>

                            <!-- IP Address -->
                            <td style="font-family:monospace; font-size:12px; white-space:nowrap; color:#475569; cursor:pointer;"
                                onclick="openLogDetail(this.closest('tr'))"
                            >
                                <?= htmlspecialchars($log['ip_address'] ?? '—', ENT_QUOTES, 'UTF-8') ?>
                            </td>

                            <!-- Suspicious Badge -->
                            <td style="cursor:pointer;" onclick="openLogDetail(this.closest('tr'))">
                                <?php if ($isSuspicious): ?>
                                    <span class="badge-suspicious">🚨 Yes</span>
                                <?php else: ?>
                                    <span class="badge-normal">Normal</span>
                                <?php endif; ?>
                            </td>

                            <!-- Flagged Reason -->
                            <td style="cursor:pointer;" onclick="openLogDetail(this.closest('tr'))">
                                <?php if (!empty($log['flagged_reason'])): ?>
                                    <div
                                        class="reason-cell"
                                        title="<?= htmlspecialchars($log['flagged_reason'], ENT_QUOTES, 'UTF-8') ?>"
                                    >
                                        <?= htmlspecialchars($log['flagged_reason'], ENT_QUOTES, 'UTF-8') ?>
                                    </div>
                                <?php else: ?>
                                    <span style="color:#CBD5E1; font-size:12px;">—</span>
                                <?php endif; ?>
                            </td>

                            <!-- Timestamp -->
                            <td style="white-space:nowrap; color:#475569; cursor:pointer;"
                                onclick="openLogDetail(this.closest('tr'))"
                            >
                                <?= date('M j, Y', strtotime($log['timestamp'])) ?>
                                <div style="font-size:11px; color:#94A3B8;">
                                    <?= date('g:i:s A', strtotime($log['timestamp'])) ?>
                                </div>
                            </td>

                            <!-- Actions (Admin only) -->
                            <?php if ($userRole === 'admin'): ?>
                            <td onclick="event.stopPropagation();">
                                <button
                                    class="btn-action btn-soft-delete"
                                    onclick="confirmSoftDeleteLog(<?= (int)$log['id'] ?>)"
                                    title="Move to trash"
                                >
                                    🗑️ Delete
                                </button>

                                <!-- Hidden soft-delete form -->
                                <form
                                    id="softDeleteLogForm_<?= (int)$log['id'] ?>"
                                    method="POST"
                                    action="logs.php"
                                    style="display:none;"
                                >
                                    <input type="hidden" name="action"     value="soft_delete_log">
                                    <input type="hidden" name="log_id"     value="<?= (int)$log['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                </form>
                            </td>
                            <?php endif; ?>

                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- ================================================
                 PAGINATION
            ================================================= -->
            <?php if ($totalPages > 1): ?>
            <div class="pagination-wrapper">

                <span class="pagination-info">
                    <?= number_format($totalRows) ?> total entries · <?= LOGS_PER_PAGE ?> per page
                </span>

                <div class="pagination-links">

                    <!-- Previous -->
                    <?php if ($page > 1): ?>
                        <a href="?<?= buildQueryString(['page' => $page - 1]) ?>" class="page-link-mv">&#8592;</a>
                    <?php else: ?>
                        <span class="page-link-mv disabled">&#8592;</span>
                    <?php endif; ?>

                    <!-- Page numbers — show up to 7, with ellipsis -->
                    <?php
                    $startPage = max(1, $page - 3);
                    $endPage   = min($totalPages, $page + 3);

                    // Always show page 1
                    if ($startPage > 1): ?>
                        <a href="?<?= buildQueryString(['page' => 1]) ?>" class="page-link-mv">1</a>
                        <?php if ($startPage > 2): ?>
                            <span class="page-link-mv disabled" style="border:none; background:none;">…</span>
                        <?php endif; ?>
                    <?php endif; ?>

                    <?php for ($p = $startPage; $p <= $endPage; $p++): ?>
                        <?php if ($p === $page): ?>
                            <span class="page-link-mv active"><?= $p ?></span>
                        <?php else: ?>
                            <a href="?<?= buildQueryString(['page' => $p]) ?>" class="page-link-mv"><?= $p ?></a>
                        <?php endif; ?>
                    <?php endfor; ?>

                    <!-- Always show last page -->
                    <?php if ($endPage < $totalPages): ?>
                        <?php if ($endPage < $totalPages - 1): ?>
                            <span class="page-link-mv disabled" style="border:none; background:none;">…</span>
                        <?php endif; ?>
                        <a href="?<?= buildQueryString(['page' => $totalPages]) ?>" class="page-link-mv"><?= $totalPages ?></a>
                    <?php endif; ?>

                    <!-- Next -->
                    <?php if ($page < $totalPages): ?>
                        <a href="?<?= buildQueryString(['page' => $page + 1]) ?>" class="page-link-mv">&#8594;</a>
                    <?php else: ?>
                        <span class="page-link-mv disabled">&#8594;</span>
                    <?php endif; ?>

                </div>

            </div>
            <?php endif; ?>

        <?php endif; ?>

    </div>
    <!-- End section card -->

    <!-- ============================================================
         TRASH SECTION — soft-deleted log entries (Admin only)
         Design mirrors assets.php trash section
    ============================================================ -->
    <?php if ($userRole === 'admin'): ?>
    <div class="section-card section-gap">
        <div class="card-header-trash">
            <span>🗑️</span> Trash — Deleted Log Entries
            <div class="header-actions">
                <span style="font-size:12px; font-weight:400; opacity:0.85;">
                    <?= $totalTrashed ?> deleted <?= $totalTrashed !== 1 ? 'entries' : 'entry' ?>
                </span>
            </div>
        </div>

        <div class="card-body-mv">

            <?php if (empty($trashedLogs)): ?>
            <div class="no-records">
                <span class="no-records-icon">✅</span>
                <p>No deleted log entries. Trash is empty.</p>
            </div>
            <?php else: ?>

            <p style="font-size:12px; color:#94A3B8; margin-bottom:14px;">
                🔒 Soft-deleted log entries are hidden from the main view but remain in the database.
                Only admins can restore them.
            </p>

            <div class="table-responsive">
                <table class="table-mv">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>IP Address</th>
                            <th>Suspicious</th>
                            <th>Timestamp</th>
                            <th>Deleted At</th>
                            <th>Deleted By</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($trashedLogs as $t): ?>
                        <?php $tSuspicious = (int)$t['is_suspicious'] === 1; ?>
                        <tr style="opacity:0.75;" class="<?= $tSuspicious ? 'row-suspicious' : '' ?>">
                            <td>
                                <span style="color:#94A3B8; font-weight:600;">#<?= (int)$t['id'] ?></span>
                            </td>
                            <td style="font-weight:600; white-space:nowrap; text-decoration:line-through; color:#94A3B8;">
                                <?= htmlspecialchars($t['user_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td>
                                <div class="action-cell" style="text-decoration:line-through; color:#94A3B8;"
                                     title="<?= htmlspecialchars($t['action'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= htmlspecialchars($t['action'], ENT_QUOTES, 'UTF-8') ?>
                                </div>
                            </td>
                            <td style="font-family:monospace; font-size:12px; white-space:nowrap; color:#94A3B8;">
                                <?= htmlspecialchars($t['ip_address'] ?? '—', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td>
                                <?php if ($tSuspicious): ?>
                                    <span class="badge-suspicious" style="opacity:0.6;">🚨 Yes</span>
                                <?php else: ?>
                                    <span class="badge-normal" style="opacity:0.6;">Normal</span>
                                <?php endif; ?>
                            </td>
                            <td style="white-space:nowrap; color:#94A3B8; font-size:12px;">
                                <?= date('M j, Y', strtotime($t['timestamp'])) ?>
                                <div style="font-size:11px;"><?= date('g:i:s A', strtotime($t['timestamp'])) ?></div>
                            </td>
                            <td class="deleted-at-cell">
                                <?= date('M j, Y g:i A', strtotime($t['deleted_at'])) ?>
                            </td>
                            <td class="deleted-by-cell">
                                <?= htmlspecialchars($t['deleted_by_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td>
                                <!-- Restore button -->
                                <button
                                    class="btn-action btn-restore"
                                    onclick="confirmRestoreLog(<?= (int)$t['id'] ?>)"
                                    title="Restore this log entry"
                                >
                                    ♻️ Restore
                                </button>

                                <!-- Hidden restore form -->
                                <form
                                    id="restoreLogForm_<?= (int)$t['id'] ?>"
                                    method="POST"
                                    action="logs.php"
                                    style="display:none;"
                                >
                                    <input type="hidden" name="action"     value="restore_log">
                                    <input type="hidden" name="log_id"     value="<?= (int)$t['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                </form>
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

<!-- ================================================
     EXPORT AUDIT MODAL
     Batch 7: user dropdown shows deleted users as "Name (Deleted)"
              checkbox: "Include deleted log entries"
================================================= -->
<div class="modal fade" id="exportAuditModal" tabindex="-1" aria-labelledby="exportAuditModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content" style="border:none; border-radius:14px; overflow:hidden; font-family:'Poppins',sans-serif;">

            <!-- Header -->
            <div class="modal-header" style="background:linear-gradient(135deg,#1E40AF,#2563EB); border:none; padding:16px 24px;">
                <h5 class="modal-title" id="exportAuditModalLabel" style="color:#fff; font-weight:700; font-size:15px; margin:0;">
                    📤 Export Audit Report
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>

            <!-- Body -->
            <div class="modal-body" style="padding:24px; background:#F8FAFC;">

                <p style="font-size:13px; color:#64748B; margin:0 0 20px;">
                    Generate a branded PDF of activity logs.
                    Apply filters below — leave blank to export everything.
                </p>

                <form method="GET" action="audit.php" target="_blank" id="exportAuditForm">

                    <!-- Date From -->
                    <div style="margin-bottom:14px;">
                        <label class="form-label" for="export_from">From Date</label>
                        <input
                            type="date"
                            class="form-control"
                            id="export_from"
                            name="from"
                        >
                    </div>

                    <!-- Date To -->
                    <div style="margin-bottom:14px;">
                        <label class="form-label" for="export_to">To Date</label>
                        <input
                            type="date"
                            class="form-control"
                            id="export_to"
                            name="to"
                        >
                    </div>

                    <!-- User Filter — Batch 7: includes deleted users labeled "(Deleted)" -->
                    <div style="margin-bottom:14px;">
                        <label class="form-label" for="export_user">Filter by User</label>
                        <select class="form-select" id="export_user" name="user_id">
                            <option value="0">All Users</option>
                            <?php foreach ($exportUsers as $eu): ?>
                                <?php $isDeleted = !empty($eu['deleted_at']); ?>
                                <option value="<?= (int)$eu['id'] ?>"
                                    <?= $isDeleted ? 'style="color:#94A3B8;"' : '' ?>
                                >
                                    <?= htmlspecialchars($eu['name'], ENT_QUOTES, 'UTF-8') ?>
                                    <?= $isDeleted ? ' (Deleted)' : '' ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- Suspicious Only -->
                    <div style="margin-bottom:12px;">
                        <label class="suspicious-checkbox-label">
                            <input
                                type="checkbox"
                                name="suspicious"
                                value="1"
                                id="export_suspicious"
                            >
                            🚨 Suspicious only
                        </label>
                    </div>

                    <!-- Entry scope — active only / all / deleted only -->
                    <div style="margin-bottom:6px;">
                        <label class="form-label" for="export_scope">Entry Scope</label>
                        <select class="form-select" id="export_scope" name="export_scope">
                            <option value="active" selected>Active entries only (default)</option>
                            <option value="all">All entries — active + deleted</option>
                            <option value="deleted_only">Deleted entries only</option>
                        </select>
                        <p style="font-size:11px; color:#94A3B8; margin:5px 0 0;">
                            "Deleted only" exports a report of soft-deleted log entries for review.
                        </p>
                    </div>

                </form>
            </div>

            <!-- Footer -->
            <div class="modal-footer" style="background:#fff; border-top:1px solid #F1F5F9; padding:12px 24px; gap:8px;">
                <button type="button" class="btn-reset" data-bs-dismiss="modal">✕ Cancel</button>
                <button
                    type="button"
                    onclick="document.getElementById('exportAuditForm').submit();"
                    style="padding:9px 22px; background:#1E40AF; color:#ffffff;
                           border:none; border-radius:8px; font-size:13px;
                           font-weight:600; cursor:pointer; display:inline-flex;
                           align-items:center; gap:6px; transition:background 0.15s;"
                    onmouseover="this.style.background='#1e3a8a'"
                    onmouseout="this.style.background='#1E40AF'"
                >
                    📄 Export PDF
                </button>
            </div>

        </div>
    </div>
</div>

<!-- ================================================
     LOG DETAIL MODAL
================================================= -->
<div class="modal fade" id="logDetailModal" tabindex="-1" aria-labelledby="logDetailModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content" style="border:none; border-radius:14px; overflow:hidden; font-family:'Poppins',sans-serif;">

            <!-- Header -->
            <div class="modal-header" style="background:linear-gradient(135deg,#1E40AF,#2563EB); border:none; padding:16px 24px;">
                <h5 class="modal-title" id="logDetailModalLabel" style="color:#fff; font-weight:700; font-size:15px; margin:0;">
                    📋 Log Entry Detail
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>

            <!-- Body -->
            <div class="modal-body" style="padding:24px; background:#F8FAFC;">
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px;">

                    <div style="background:#fff; border-radius:10px; padding:14px 18px; border:1px solid #E2E8F0;">
                        <div style="font-size:10px; font-weight:700; color:#94A3B8; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">Log ID</div>
                        <div id="modal-id" style="font-size:14px; font-weight:600; color:#94A3B8;"></div>
                    </div>

                    <div style="background:#fff; border-radius:10px; padding:14px 18px; border:1px solid #E2E8F0;">
                        <div style="font-size:10px; font-weight:700; color:#94A3B8; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">User</div>
                        <div id="modal-user" style="font-size:14px; font-weight:600; color:#1E293B;"></div>
                    </div>

                    <div style="background:#fff; border-radius:10px; padding:14px 18px; border:1px solid #E2E8F0; grid-column:1/-1;">
                        <div style="font-size:10px; font-weight:700; color:#94A3B8; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px;">Action</div>
                        <div id="modal-action" style="font-size:13px; color:#1E293B; line-height:1.6; word-break:break-word;"></div>
                    </div>

                    <div style="background:#fff; border-radius:10px; padding:14px 18px; border:1px solid #E2E8F0;">
                        <div style="font-size:10px; font-weight:700; color:#94A3B8; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">IP Address</div>
                        <div id="modal-ip" style="font-size:13px; font-family:monospace; color:#475569;"></div>
                    </div>

                    <div style="background:#fff; border-radius:10px; padding:14px 18px; border:1px solid #E2E8F0;">
                        <div style="font-size:10px; font-weight:700; color:#94A3B8; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">Suspicious</div>
                        <div id="modal-suspicious"></div>
                    </div>

                    <div id="modal-reason-wrapper" style="background:#FEF2F2; border-radius:10px; padding:14px 18px; border:1px solid #FECACA; grid-column:1/-1; display:none;">
                        <div style="font-size:10px; font-weight:700; color:#EF4444; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px;">🚨 Flagged Reason</div>
                        <div id="modal-reason" style="font-size:13px; color:#991B1B; font-weight:500; line-height:1.6; word-break:break-word;"></div>
                    </div>

                    <div style="background:#fff; border-radius:10px; padding:14px 18px; border:1px solid #E2E8F0; grid-column:1/-1;">
                        <div style="font-size:10px; font-weight:700; color:#94A3B8; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">Timestamp</div>
                        <div id="modal-timestamp" style="font-size:13px; color:#475569;"></div>
                    </div>

                </div>
            </div>

            <!-- Footer -->
            <div class="modal-footer" style="background:#fff; border-top:1px solid #F1F5F9; padding:12px 24px;">
                <button type="button" class="btn-reset" data-bs-dismiss="modal">Close</button>
            </div>

        </div>
    </div>
</div>

<!-- Bootstrap JS -->
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
    // SESSION TIMEOUT WARNING — 9 min alert, 10 min redirect
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
    // DATE RANGE VALIDATION — prevent date_to < date_from
    // ============================================================
    const dateFrom = document.getElementById('date_from');
    const dateTo   = document.getElementById('date_to');

    if (dateFrom && dateTo) {
        dateFrom.addEventListener('change', function () {
            if (dateTo.value && dateTo.value < dateFrom.value) {
                dateTo.value = dateFrom.value;
            }
            dateTo.setAttribute('min', dateFrom.value);
        });

        // Set initial min on page load if date_from is prefilled
        if (dateFrom.value) {
            dateTo.setAttribute('min', dateFrom.value);
        }
    }

    // ============================================================
    // LOG DETAIL MODAL — open on row cell click (not action cell)
    // ============================================================
    function openLogDetail(row) {
        document.getElementById('modal-id').textContent        = '#' + row.dataset.id;
        document.getElementById('modal-user').textContent      = row.dataset.user;
        document.getElementById('modal-action').textContent    = row.dataset.action;
        document.getElementById('modal-ip').textContent        = row.dataset.ip;
        document.getElementById('modal-timestamp').textContent = row.dataset.timestamp;

        const isSuspicious = row.dataset.suspicious === 'Yes';
        const suspiciousEl = document.getElementById('modal-suspicious');
        suspiciousEl.innerHTML = isSuspicious
            ? '<span class="badge-suspicious">🚨 Yes</span>'
            : '<span class="badge-normal">Normal</span>';

        const reasonWrapper = document.getElementById('modal-reason-wrapper');
        const reasonEl      = document.getElementById('modal-reason');
        if (row.dataset.reason) {
            reasonWrapper.style.display = 'block';
            reasonEl.textContent = row.dataset.reason;
        } else {
            reasonWrapper.style.display = 'none';
        }

        const modal = new bootstrap.Modal(document.getElementById('logDetailModal'));
        modal.show();
    }

    // ============================================================
    // SOFT DELETE LOG — confirm before form submit
    // ============================================================
    function confirmSoftDeleteLog(logId) {
        const confirmed = confirm(
            '🗑️ Move Log Entry to Trash\n\n' +
            'Log entry #' + logId + ' will be soft-deleted.\n' +
            'It will be hidden from the main view but can be restored from the Trash section below.'
        );
        if (confirmed) {
            document.getElementById('softDeleteLogForm_' + logId).submit();
        }
    }

    // ============================================================
    // RESTORE LOG — confirm before form submit
    // ============================================================
    function confirmRestoreLog(logId) {
        const confirmed = confirm(
            '♻️ Restore Log Entry\n\n' +
            'Restore log entry #' + logId + ' from Trash?\n\n' +
            'It will reappear in the main log table.'
        );
        if (confirmed) {
            document.getElementById('restoreLogForm_' + logId).submit();
        }
    }

    // ============================================================
    // AUTO-DISMISS FLASH ALERTS after 5 seconds
    // ============================================================
    const alerts = document.querySelectorAll('.alert-banner');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            alert.style.transition = 'opacity 0.5s';
            alert.style.opacity = '0';
            setTimeout(function() { alert.remove(); }, 500);
        }, 5000);
    });
</script>

</body>
</html>