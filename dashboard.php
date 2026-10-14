<?php
// ============================================================
// MEDIVAULT — dashboard.php
// Purpose:  Main overview after login — summary cards, CIA triad
//           status, Chart.js charts, suspicious activity widget,
//           compliance checklist, recent activity, recent incidents
// Layout:   Full sidebar
// Access:   All roles (admin/doctor/nurse/receptionist)
// Rules:    Always included AFTER db.php and auth.php
//           mailer.php included so sendSuspiciousAlert()
//           is available for auth.php IP mismatch check
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';
require 'includes/mailer.php';

// ============================================================
// ACCESS CONTROL — all 4 roles allowed
// ============================================================
requireRole(['admin', 'doctor', 'nurse', 'receptionist']);

$userId   = $_SESSION['user_id'];
$userName = $_SESSION['user_name'];
$userRole = $_SESSION['user_role'];
$ip       = getUserIP();

// ============================================================
// LOG DASHBOARD ACCESS
// ============================================================
logActivity($conn, $userId, "Viewed dashboard", $ip);

// ============================================================
// SUMMARY CARDS — 6 counts from database
// ============================================================

// 1. Total Patients
$stmt = $conn->prepare("SELECT COUNT(*) AS total FROM patients WHERE deleted_at IS NULL");
$stmt->execute();
$totalPatients = (int)$stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// 2. Total Assets
$stmt = $conn->prepare("SELECT COUNT(*) AS total FROM assets WHERE deleted_at IS NULL");
$stmt->execute();
$totalAssets = (int)$stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// 3. Total Risks
$stmt = $conn->prepare("SELECT COUNT(*) AS total FROM risks WHERE deleted_at IS NULL");
$stmt->execute();
$totalRisks = (int)$stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// 4. Open Incidents — status = 'Open' only
$stmt = $conn->prepare("SELECT COUNT(*) AS total FROM incidents WHERE status = 'Open' AND deleted_at IS NULL");
$stmt->execute();
$openIncidents = (int)$stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// 5. Total Users
$stmt = $conn->prepare("SELECT COUNT(*) AS total FROM users WHERE deleted_at IS NULL");
$stmt->execute();
$totalUsers = (int)$stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// 6. Suspicious Events — all-time is_suspicious = 1
$stmt = $conn->prepare("SELECT COUNT(*) AS total FROM activity_logs WHERE is_suspicious = 1");
$stmt->execute();
$suspiciousEvents = (int)$stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// ============================================================
// CIA TRIAD STATUS
// Exactly as defined in spec Part 4 dashboard section
// ============================================================

// --- Confidentiality ---
// Count high-risk rows (score >= 13) on Confidential assets
$stmt = $conn->prepare(
    "SELECT COUNT(*) AS count
     FROM risks r
     JOIN assets a ON r.asset_id = a.id
     WHERE a.classification = 'Confidential'
     AND r.risk_score >= 13
     AND r.deleted_at IS NULL
     AND a.deleted_at IS NULL"
);
$stmt->execute();
$highRisksOnConfidential = (int)$stmt->get_result()->fetch_assoc()['count'];
$stmt->close();

if ($highRisksOnConfidential === 0) {
    $ciaC = ['level' => 'green', 'status' => 'Secure',   'note' => 'No high risks on confidential assets',                         'color' => '#22C55E', 'bg' => '#F0FDF4'];
} elseif ($highRisksOnConfidential <= 2) {
    $ciaC = ['level' => 'yellow','status' => 'Warning',  'note' => $highRisksOnConfidential . ' high risk(s) on confidential assets','color' => '#F59E0B', 'bg' => '#FFFBEB'];
} else {
    $ciaC = ['level' => 'red',   'status' => 'Critical', 'note' => $highRisksOnConfidential . ' high risks on confidential assets',  'color' => '#EF4444', 'bg' => '#FEF2F2'];
}

// --- Integrity ---
// Based on open incidents count (already fetched above)
if ($openIncidents === 0) {
    $ciaI = ['level' => 'green', 'status' => 'Stable',   'note' => 'No open incidents',                                            'color' => '#22C55E', 'bg' => '#F0FDF4'];
} elseif ($openIncidents <= 3) {
    $ciaI = ['level' => 'yellow','status' => 'Warning',  'note' => $openIncidents . ' open incident(s) pending resolution',        'color' => '#F59E0B', 'bg' => '#FFFBEB'];
} else {
    $ciaI = ['level' => 'red',   'status' => 'Critical', 'note' => $openIncidents . ' open incidents — immediate attention needed','color' => '#EF4444', 'bg' => '#FEF2F2'];
}

// --- Availability ---
// Check if a backup asset exists and its max risk score
$stmt = $conn->prepare(
    "SELECT a.id, COALESCE(MAX(r.risk_score), 0) AS max_risk
     FROM assets a
     LEFT JOIN risks r ON r.asset_id = a.id
     WHERE LOWER(a.name) LIKE '%backup%'
     GROUP BY a.id
     LIMIT 1"
);
$stmt->execute();
$backupAsset = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$backupAsset) {
    $ciaA = ['level' => 'yellow','status' => 'Warning',     'note' => 'No backup asset registered in the system',                'color' => '#F59E0B', 'bg' => '#FFFBEB'];
} elseif ((int)$backupAsset['max_risk'] >= 13) {
    $ciaA = ['level' => 'red',   'status' => 'At Risk',     'note' => 'Backup asset has a high risk score — availability at risk','color' => '#EF4444', 'bg' => '#FEF2F2'];
} else {
    $ciaA = ['level' => 'green', 'status' => 'Operational', 'note' => 'Backup asset registered and adequately protected',        'color' => '#22C55E', 'bg' => '#F0FDF4'];
}

// ============================================================
// CHART DATA — Risk Distribution (Low / Medium / High)
// ============================================================
$stmt = $conn->prepare(
    "SELECT
        SUM(CASE WHEN risk_score BETWEEN 1  AND 4  THEN 1 ELSE 0 END) AS low_count,
        SUM(CASE WHEN risk_score BETWEEN 5  AND 12 THEN 1 ELSE 0 END) AS medium_count,
        SUM(CASE WHEN risk_score >= 13              THEN 1 ELSE 0 END) AS high_count
     FROM risks"
);
$stmt->execute();
$riskRow    = $stmt->get_result()->fetch_assoc();
$stmt->close();

$riskLow    = (int)($riskRow['low_count']    ?? 0);
$riskMedium = (int)($riskRow['medium_count'] ?? 0);
$riskHigh   = (int)($riskRow['high_count']   ?? 0);

// ============================================================
// CHART DATA — Incidents by Status
// ============================================================
$stmt = $conn->prepare(
    "SELECT
        SUM(CASE WHEN status = 'Open'          THEN 1 ELSE 0 END) AS open_count,
        SUM(CASE WHEN status = 'Investigating' THEN 1 ELSE 0 END) AS inv_count,
        SUM(CASE WHEN status = 'Resolved'      THEN 1 ELSE 0 END) AS res_count
     FROM incidents"
);
$stmt->execute();
$incRow = $stmt->get_result()->fetch_assoc();
$stmt->close();

$incOpen          = (int)($incRow['open_count'] ?? 0);
$incInvestigating = (int)($incRow['inv_count']  ?? 0);
$incResolved      = (int)($incRow['res_count']  ?? 0);

// ============================================================
// SUSPICIOUS ACTIVITY WIDGET — Today's count (Admin only)
// ============================================================
$todaySuspicious = 0;
if ($userRole === 'admin') {
    $stmt = $conn->prepare(
        "SELECT COUNT(*) AS count
         FROM activity_logs
         WHERE is_suspicious = 1
         AND DATE(timestamp) = CURDATE()"
    );
    $stmt->execute();
    $todaySuspicious = (int)$stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();
}

// ============================================================
// RECENT ACTIVITY — Last 5 logs (Admin only)
// ============================================================
$recentActivity = [];
if ($userRole === 'admin') {
    $stmt = $conn->prepare(
        "SELECT al.action, al.timestamp, al.is_suspicious, al.flagged_reason, u.name AS user_name
         FROM activity_logs al
         JOIN users u ON al.user_id = u.id
         ORDER BY al.timestamp DESC
         LIMIT 5"
    );
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $recentActivity[] = $row;
    }
    $stmt->close();
}

// ============================================================
// RECENT INCIDENTS — Last 3 open (All roles)
// ============================================================
$recentIncidents = [];
$stmt = $conn->prepare(
    "SELECT title, priority, status, created_at
     FROM incidents
     WHERE status = 'Open'
     ORDER BY created_at DESC
     LIMIT 3"
);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $recentIncidents[] = $row;
}
$stmt->close();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Dashboard</title>
    <link rel="icon" href="assets/images/favicon.ico">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Chart.js — dashboard only -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
           SIDEBAR — exact spec CSS
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
            padding-top: 90px; /* topbar height + spacing */
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
           STAT CARDS — summary cards
        ====================================================== */
        .stat-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            background: #ffffff;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
            height: 100%;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
        }

        .stat-card .stat-icon {
            font-size: 26px;
            margin-bottom: 10px;
            display: block;
        }

        .stat-card .stat-number {
            font-size: 32px;
            font-weight: 700;
            color: #2563EB;
            margin: 0;
            line-height: 1.1;
        }

        .stat-card .stat-number.danger {
            color: #EF4444;
        }

        .stat-card .stat-label {
            font-size: 13px;
            color: #94A3B8;
            margin: 5px 0 0;
            font-weight: 500;
        }

        .stat-card.danger-card {
            border: 2px solid #EF4444;
            background: #FEF2F2;
        }

        /* Clickable stat card wrapper */
        a.stat-card-link {
            display: block;
            text-decoration: none;
            color: inherit;
            height: 100%;
            border-radius: 12px;
        }

        a.stat-card-link:hover .stat-card {
            transform: translateY(-3px);
            box-shadow: 0 10px 24px rgba(37,99,235,0.15);
            outline: 2px solid #2563EB;
        }

        a.stat-card-link:hover .stat-card.danger-card {
            outline: 2px solid #EF4444;
        }

        a.stat-card-link .stat-card {
            cursor: pointer;
        }

        /* ======================================================
           GENERIC CARD — sections
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

        .section-card .card-body-mv {
            padding: 20px;
        }

        /* ======================================================
           CIA TRIAD CARDS
        ====================================================== */
        .cia-card {
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            padding: 20px;
            display: flex;
            align-items: flex-start;
            gap: 15px;
            transition: transform 0.2s;
            border: none;
        }

        .cia-card:hover {
            transform: translateY(-2px);
        }

        .cia-dot {
            width: 44px;
            height: 44px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            flex-shrink: 0;
            margin-top: 2px;
        }

        .cia-info h6 {
            font-size: 13px;
            font-weight: 600;
            color: #94A3B8;
            margin: 0 0 2px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .cia-info .cia-status {
            font-size: 18px;
            font-weight: 700;
            margin: 0 0 4px;
            line-height: 1.2;
        }

        .cia-info .cia-note {
            font-size: 12px;
            color: #94A3B8;
            margin: 0;
        }

        /* ======================================================
           CHART CONTAINERS
        ====================================================== */
        .chart-wrapper {
            position: relative;
            height: 260px;
            width: 100%;
        }

        /* ======================================================
           SUSPICIOUS ACTIVITY WIDGET
        ====================================================== */
        .suspicious-widget {
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            background: #ffffff;
            padding: 22px 20px;
            margin-bottom: 24px;
            border: 2px solid transparent;
            transition: border-color 0.2s;
        }

        .suspicious-widget.has-alerts {
            border-color: #EF4444;
            background: #FEF2F2;
        }

        .suspicious-widget .sw-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }

        .suspicious-widget .sw-label {
            font-size: 13px;
            font-weight: 600;
            color: #94A3B8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .suspicious-widget .sw-count {
            font-size: 42px;
            font-weight: 700;
            color: #22C55E;
            line-height: 1;
            margin-bottom: 4px;
        }

        .suspicious-widget .sw-count.alert {
            color: #EF4444;
        }

        .suspicious-widget .sw-subtext {
            font-size: 12px;
            color: #94A3B8;
            margin: 0 0 14px;
        }

        .suspicious-widget a.sw-link {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: #EF4444;
            color: #ffffff;
            text-decoration: none;
            font-size: 12px;
            font-weight: 600;
            padding: 7px 16px;
            border-radius: 8px;
            transition: background 0.2s;
        }

        .suspicious-widget a.sw-link:hover {
            background: #DC2626;
        }

        .suspicious-widget a.sw-link.safe {
            background: #22C55E;
        }

        .suspicious-widget a.sw-link.safe:hover {
            background: #16A34A;
        }

        /* ======================================================
           COMPLIANCE CHECKLIST
        ====================================================== */
        .checklist-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 9px 0;
            border-bottom: 1px solid #F1F5F9;
            font-size: 13px;
            color: #1E293B;
            font-weight: 500;
        }

        .checklist-item:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .checklist-item:first-child {
            padding-top: 0;
        }

        .checklist-icon {
            font-size: 16px;
            flex-shrink: 0;
        }

        /* ======================================================
           RECENT ACTIVITY TABLE
        ====================================================== */
        .activity-row {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid #F1F5F9;
            font-size: 13px;
        }

        .activity-row:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .activity-row:first-child {
            padding-top: 0;
        }

        .activity-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #2563EB;
            margin-top: 5px;
            flex-shrink: 0;
        }

        .activity-dot.suspicious {
            background: #EF4444;
        }

        .activity-info {
            flex: 1;
            min-width: 0;
        }

        .activity-user {
            font-weight: 600;
            color: #1E293B;
        }

        .activity-action {
            color: #475569;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 100%;
        }

        .activity-time {
            font-size: 11px;
            color: #94A3B8;
            white-space: nowrap;
            margin-top: 2px;
        }

        .activity-suspicious-badge {
            font-size: 10px;
            background: #FEF2F2;
            color: #EF4444;
            border: 1px solid #FECACA;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
            flex-shrink: 0;
            margin-top: 2px;
        }

        .view-all-link {
            display: inline-block;
            margin-top: 12px;
            font-size: 12px;
            color: #2563EB;
            text-decoration: none;
            font-weight: 600;
        }

        .view-all-link:hover {
            color: #1E40AF;
        }

        /* ======================================================
           RECENT INCIDENTS
        ====================================================== */
        .incident-item {
            padding: 10px 0;
            border-bottom: 1px solid #F1F5F9;
        }

        .incident-item:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .incident-item:first-child {
            padding-top: 0;
        }

        .incident-title {
            font-size: 13px;
            font-weight: 600;
            color: #1E293B;
            margin-bottom: 6px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .incident-meta {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }

        .no-data-msg {
            text-align: center;
            padding: 20px;
            color: #94A3B8;
            font-size: 13px;
        }

        .no-data-msg .no-data-icon {
            font-size: 28px;
            display: block;
            margin-bottom: 6px;
        }

        /* ======================================================
           BADGES — exact spec colors
        ====================================================== */
        .badge-open {
            background: #EF4444;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge-investigating {
            background: #F59E0B;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge-resolved {
            background: #22C55E;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge-priority-low {
            background: #38BDF8;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge-priority-medium {
            background: #F59E0B;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge-priority-high {
            background: #EF4444;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
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

            .stat-card .stat-number {
                font-size: 24px;
            }

            .chart-wrapper {
                height: 220px;
            }

            .topbar-user {
                display: none;
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
           BUTTONS — spec colors
        ====================================================== */
        .btn-primary {
            background: #2563EB;
            border: none;
            border-radius: 8px;
            font-weight: 500;
            font-size: 14px;
            padding: 8px 20px;
            transition: all 0.2s;
            font-family: 'Poppins', sans-serif;
        }

        .btn-primary:hover {
            background: #1E40AF;
            transform: translateY(-1px);
        }
    </style>
</head>
<body>

<!-- ============================================================
     MOBILE OVERLAY — closes sidebar on backdrop click
============================================================ -->
<div id="overlay"></div>

<!-- ============================================================
     SIDEBAR — identical across all protected pages, exact spec order
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
        <a href="dashboard.php" class="active">
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

    <span class="topbar-title">📊 Dashboard</span>

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
        <h2>Dashboard</h2>
        <p>System overview — <?= date('l, F j, Y') ?></p>
    </div>

    <!-- ========================================================
         ROW 1 — SUMMARY CARDS (6 cards)
    ========================================================= -->
    <div class="row g-3 section-gap">

        <!-- Total Patients — all roles can navigate -->
        <div class="col-6 col-md-4 col-lg-2">
            <a href="patients.php" class="stat-card-link">
                <div class="stat-card">
                    <span class="stat-icon">👤</span>
                    <p class="stat-number"><?= $totalPatients ?></p>
                    <p class="stat-label">Total Patients</p>
                </div>
            </a>
        </div>

        <!-- Total Assets — admin only link -->
        <div class="col-6 col-md-4 col-lg-2">
            <?php if ($userRole === 'admin'): ?>
            <a href="assets.php" class="stat-card-link">
            <?php endif; ?>
                <div class="stat-card">
                    <span class="stat-icon">🏗️</span>
                    <p class="stat-number"><?= $totalAssets ?></p>
                    <p class="stat-label">Total Assets</p>
                </div>
            <?php if ($userRole === 'admin'): ?>
            </a>
            <?php endif; ?>
        </div>

        <!-- Total Risks — admin only link -->
        <div class="col-6 col-md-4 col-lg-2">
            <?php if ($userRole === 'admin'): ?>
            <a href="risks.php" class="stat-card-link">
            <?php endif; ?>
                <div class="stat-card">
                    <span class="stat-icon">⚠️</span>
                    <p class="stat-number"><?= $totalRisks ?></p>
                    <p class="stat-label">Total Risks</p>
                </div>
            <?php if ($userRole === 'admin'): ?>
            </a>
            <?php endif; ?>
        </div>

        <!-- Open Incidents — all roles can navigate -->
        <div class="col-6 col-md-4 col-lg-2">
            <a href="incidents.php" class="stat-card-link">
                <div class="stat-card <?= $openIncidents > 0 ? 'danger-card' : '' ?>">
                    <span class="stat-icon">🚨</span>
                    <p class="stat-number <?= $openIncidents > 0 ? 'danger' : '' ?>"><?= $openIncidents ?></p>
                    <p class="stat-label">Open Incidents</p>
                </div>
            </a>
        </div>

        <!-- Total Users — admin only link -->
        <div class="col-6 col-md-4 col-lg-2">
            <?php if ($userRole === 'admin'): ?>
            <a href="users.php" class="stat-card-link">
            <?php endif; ?>
                <div class="stat-card">
                    <span class="stat-icon">👥</span>
                    <p class="stat-number"><?= $totalUsers ?></p>
                    <p class="stat-label">Total Users</p>
                </div>
            <?php if ($userRole === 'admin'): ?>
            </a>
            <?php endif; ?>
        </div>

        <!-- Suspicious Events — admin only link, red styling if count > 0 -->
        <div class="col-6 col-md-4 col-lg-2">
            <?php if ($userRole === 'admin'): ?>
            <a href="logs.php" class="stat-card-link">
            <?php endif; ?>
                <div class="stat-card <?= $suspiciousEvents > 0 ? 'danger-card' : '' ?>">
                    <span class="stat-icon">🔴</span>
                    <p class="stat-number <?= $suspiciousEvents > 0 ? 'danger' : '' ?>"><?= $suspiciousEvents ?></p>
                    <p class="stat-label">Suspicious Events</p>
                </div>
            <?php if ($userRole === 'admin'): ?>
            </a>
            <?php endif; ?>
        </div>

    </div>
    <!-- End Summary Cards -->

    <!-- ========================================================
         ROW 2 — CIA TRIAD STATUS SECTION
    ========================================================= -->
    <div class="section-gap">
        <div class="section-card">
            <div class="card-header-mv">
                🛡️ CIA Triad Status
            </div>
            <div class="card-body-mv">
                <div class="row g-3">

                    <!-- Confidentiality -->
                    <div class="col-12 col-md-4">
                        <div class="cia-card" style="background: <?= $ciaC['bg'] ?>;">
                            <div class="cia-dot" style="background: <?= $ciaC['color'] ?>; color: white;">
                                🔒
                            </div>
                            <div class="cia-info">
                                <h6>Confidentiality</h6>
                                <p class="cia-status" style="color: <?= $ciaC['color'] ?>;">
                                    <?= htmlspecialchars($ciaC['status'], ENT_QUOTES, 'UTF-8') ?>
                                </p>
                                <p class="cia-note"><?= htmlspecialchars($ciaC['note'], ENT_QUOTES, 'UTF-8') ?></p>
                            </div>
                        </div>
                    </div>

                    <!-- Integrity -->
                    <div class="col-12 col-md-4">
                        <div class="cia-card" style="background: <?= $ciaI['bg'] ?>;">
                            <div class="cia-dot" style="background: <?= $ciaI['color'] ?>; color: white;">
                                🛡️
                            </div>
                            <div class="cia-info">
                                <h6>Integrity</h6>
                                <p class="cia-status" style="color: <?= $ciaI['color'] ?>;">
                                    <?= htmlspecialchars($ciaI['status'], ENT_QUOTES, 'UTF-8') ?>
                                </p>
                                <p class="cia-note"><?= htmlspecialchars($ciaI['note'], ENT_QUOTES, 'UTF-8') ?></p>
                            </div>
                        </div>
                    </div>

                    <!-- Availability -->
                    <div class="col-12 col-md-4">
                        <div class="cia-card" style="background: <?= $ciaA['bg'] ?>;">
                            <div class="cia-dot" style="background: <?= $ciaA['color'] ?>; color: white;">
                                📡
                            </div>
                            <div class="cia-info">
                                <h6>Availability</h6>
                                <p class="cia-status" style="color: <?= $ciaA['color'] ?>;">
                                    <?= htmlspecialchars($ciaA['status'], ENT_QUOTES, 'UTF-8') ?>
                                </p>
                                <p class="cia-note"><?= htmlspecialchars($ciaA['note'], ENT_QUOTES, 'UTF-8') ?></p>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </div>
    <!-- End CIA Triad -->

    <!-- ========================================================
         ROW 3 — CHART.JS CHARTS
    ========================================================= -->
    <div class="row g-3 section-gap">

        <!-- Donut — Risk Distribution (Low / Medium / High) -->
        <div class="col-12 col-md-6">
            <div class="section-card">
                <div class="card-header-mv">
                    📊 Risk Distribution
                </div>
                <div class="card-body-mv">
                    <?php if ($totalRisks > 0): ?>
                        <div class="chart-wrapper">
                            <canvas id="riskDonutChart"></canvas>
                        </div>
                    <?php else: ?>
                        <div class="no-data-msg">
                            <span class="no-data-icon">📊</span>
                            No risk data available yet
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Bar — Incidents by Status -->
        <div class="col-12 col-md-6">
            <div class="section-card">
                <div class="card-header-mv">
                    🚨 Incidents by Status
                </div>
                <div class="card-body-mv">
                    <?php if (($incOpen + $incInvestigating + $incResolved) > 0): ?>
                        <div class="chart-wrapper">
                            <canvas id="incidentBarChart"></canvas>
                        </div>
                    <?php else: ?>
                        <div class="no-data-msg">
                            <span class="no-data-icon">🚨</span>
                            No incident data available yet
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

    </div>
    <!-- End Charts -->

    <!-- ========================================================
         ROW 4 — SUSPICIOUS WIDGET + RECENT ACTIVITY (Admin only)
    ========================================================= -->
    <?php if ($userRole === 'admin'): ?>
    <div class="row g-3 section-gap">

        <!-- Suspicious Activity Widget -->
        <div class="col-12 col-md-4">
            <div class="suspicious-widget <?= $todaySuspicious > 0 ? 'has-alerts' : '' ?>">
                <div class="sw-header">
                    <span class="sw-label">⚠️ Today's Suspicious Activity</span>
                </div>
                <p class="sw-count <?= $todaySuspicious > 0 ? 'alert' : '' ?>"><?= $todaySuspicious ?></p>
                <p class="sw-subtext">
                    <?php if ($todaySuspicious > 0): ?>
                        Suspicious event(s) detected today — review immediately
                    <?php else: ?>
                        No suspicious events detected today
                    <?php endif; ?>
                </p>
                <a href="logs.php" class="sw-link <?= $todaySuspicious === 0 ? 'safe' : '' ?>">
                    📋 View Activity Logs
                </a>
            </div>
        </div>

        <!-- Recent Activity — last 5 logs -->
        <div class="col-12 col-md-8">
            <div class="section-card" style="margin-bottom: 0;">
                <div class="card-header-mv">
                    📋 Recent Activity
                </div>
                <div class="card-body-mv">
                    <?php if (!empty($recentActivity)): ?>
                        <?php foreach ($recentActivity as $log): ?>
                            <div class="activity-row">
                                <div class="activity-dot <?= $log['is_suspicious'] ? 'suspicious' : '' ?>"></div>
                                <div class="activity-info">
                                    <div class="activity-user">
                                        <?= htmlspecialchars($log['user_name'], ENT_QUOTES, 'UTF-8') ?>
                                    </div>
                                    <div class="activity-action">
                                        <?= htmlspecialchars($log['action'], ENT_QUOTES, 'UTF-8') ?>
                                    </div>
                                    <div class="activity-time">
                                        🕐 <?= htmlspecialchars($log['timestamp'], ENT_QUOTES, 'UTF-8') ?>
                                    </div>
                                </div>
                                <?php if ($log['is_suspicious']): ?>
                                    <span class="activity-suspicious-badge">⚠ SUSPICIOUS</span>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                        <a href="logs.php" class="view-all-link">View all logs →</a>
                    <?php else: ?>
                        <div class="no-data-msg">
                            <span class="no-data-icon">📋</span>
                            No activity logs yet
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

    </div>
    <?php endif; ?>
    <!-- End Admin Row -->

    <!-- ========================================================
         ROW 5 — COMPLIANCE CHECKLIST + RECENT INCIDENTS
    ========================================================= -->
    <div class="row g-3 section-gap">

        <!-- Compliance Checklist — all roles -->
        <div class="col-12 col-md-6">
            <div class="section-card" style="margin-bottom: 0;">
                <div class="card-header-mv">
                    ✅ Compliance Checklist
                </div>
                <div class="card-body-mv">

                    <div class="checklist-item">
                        <span class="checklist-icon">✅</span>
                        OTP Authentication enabled
                    </div>
                    <div class="checklist-item">
                        <span class="checklist-icon">✅</span>
                        Role-based access active
                    </div>
                    <div class="checklist-item">
                        <span class="checklist-icon">✅</span>
                        Activity logging active
                    </div>
                    <div class="checklist-item">
                        <span class="checklist-icon">✅</span>
                        Account lockout active
                    </div>
                    <div class="checklist-item">
                        <span class="checklist-icon">✅</span>
                        Password policy enforced
                    </div>
                    <div class="checklist-item">
                        <span class="checklist-icon">✅</span>
                        Session timeout active
                    </div>
                    <div class="checklist-item">
                        <span class="checklist-icon">✅</span>
                        Incident response system active
                    </div>
                    <div class="checklist-item">
                        <span class="checklist-icon">✅</span>
                        Audit export available
                    </div>

                </div>
            </div>
        </div>

        <!-- Recent Incidents — all roles -->
        <div class="col-12 col-md-6">
            <div class="section-card" style="margin-bottom: 0;">
                <div class="card-header-mv">
                    🚨 Recent Open Incidents
                </div>
                <div class="card-body-mv">
                    <?php if (!empty($recentIncidents)): ?>
                        <?php foreach ($recentIncidents as $incident): ?>
                            <div class="incident-item">
                                <div class="incident-title">
                                    <?= htmlspecialchars($incident['title'], ENT_QUOTES, 'UTF-8') ?>
                                </div>
                                <div class="incident-meta">
                                    <!-- Priority badge -->
                                    <?php
                                    $priorityClass = match($incident['priority']) {
                                        'Low'    => 'badge-priority-low',
                                        'Medium' => 'badge-priority-medium',
                                        'High'   => 'badge-priority-high',
                                        default  => 'badge-priority-medium',
                                    };
                                    ?>
                                    <span class="<?= $priorityClass ?>">
                                        <?= htmlspecialchars($incident['priority'], ENT_QUOTES, 'UTF-8') ?>
                                    </span>

                                    <!-- Status badge -->
                                    <?php
                                    $statusClass = match($incident['status']) {
                                        'Open'          => 'badge-open',
                                        'Investigating' => 'badge-investigating',
                                        'Resolved'      => 'badge-resolved',
                                        default         => 'badge-open',
                                    };
                                    ?>
                                    <span class="<?= $statusClass ?>">
                                        <?= htmlspecialchars($incident['status'], ENT_QUOTES, 'UTF-8') ?>
                                    </span>

                                    <span style="font-size:11px; color:#94A3B8; margin-left: auto;">
                                        <?= date('M j, Y', strtotime($incident['created_at'])) ?>
                                    </span>
                                </div>
                            </div>
                        <?php endforeach; ?>
                        <a href="incidents.php" class="view-all-link">View all incidents →</a>
                    <?php else: ?>
                        <div class="no-data-msg">
                            <span class="no-data-icon">✅</span>
                            No open incidents — system is clear
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

    </div>
    <!-- End Row 5 -->

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
    // 10 minutes → auto redirect
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
    // CHART.JS — DONUT CHART: Risk Distribution
    // Colors exactly as per spec palette
    // ============================================================
    <?php if ($totalRisks > 0): ?>
    (function () {
        const riskCtx = document.getElementById('riskDonutChart');
        if (!riskCtx) return;

        new Chart(riskCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Low Risk (1–4)', 'Medium Risk (5–12)', 'High Risk (13–25)'],
                datasets: [{
                    data: [<?= $riskLow ?>, <?= $riskMedium ?>, <?= $riskHigh ?>],
                    backgroundColor: ['#22C55E', '#F59E0B', '#EF4444'],
                    borderColor:     ['#16A34A', '#D97706', '#DC2626'],
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            font: { family: 'Poppins', size: 12 },
                            padding: 16,
                            usePointStyle: true,
                            pointStyleWidth: 10
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const pct   = total > 0
                                    ? Math.round((context.parsed / total) * 100)
                                    : 0;
                                return ' ' + context.label + ': ' + context.parsed + ' (' + pct + '%)';
                            }
                        }
                    }
                },
                cutout: '62%'
            }
        });
    })();
    <?php endif; ?>

    // ============================================================
    // CHART.JS — BAR CHART: Incidents by Status
    // Colors exactly as per spec palette
    // ============================================================
    <?php if (($incOpen + $incInvestigating + $incResolved) > 0): ?>
    (function () {
        const incCtx = document.getElementById('incidentBarChart');
        if (!incCtx) return;

        new Chart(incCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['Open', 'Investigating', 'Resolved'],
                datasets: [{
                    label: 'Incidents',
                    data: [<?= $incOpen ?>, <?= $incInvestigating ?>, <?= $incResolved ?>],
                    backgroundColor: ['#EF4444', '#F59E0B', '#22C55E'],
                    borderColor:     ['#DC2626', '#D97706', '#16A34A'],
                    borderWidth: 2,
                    borderRadius: 6,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                return ' ' + context.parsed.y + ' incident(s)';
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            font: { family: 'Poppins', size: 11 }
                        },
                        grid: {
                            color: 'rgba(0,0,0,0.05)'
                        }
                    },
                    x: {
                        ticks: {
                            font: { family: 'Poppins', size: 12, weight: '500' }
                        },
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    })();
    <?php endif; ?>

</script>

</body>
</html>