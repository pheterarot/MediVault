<?php
// ============================================================
// MEDIVAULT — incidents.php
// Purpose:  Security incident reporting and management —
//           all roles can report and view, Admin manages
//           status, assigned_to, and can delete resolved
// Layout:   Full sidebar (identical to dashboard.php)
// Access:   All 4 roles (admin/doctor/nurse/receptionist)
//
// Role matrix:
//   All roles   → view all incidents, report new incident
//   Admin only  → edit modal, change status inline,
//                 change assigned_to, delete resolved,
//                 Assigned To field visible on form
//
// Security:
//   CSRF on every POST (verifyCsrf())
//   Server-side role checks on every action
//   Prepared statements throughout
//   XSS prevention via clean() / htmlspecialchars()
//   All actions logged to activity_logs
//   sendIncidentAlert() called on new incident
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';
require 'includes/mailer.php';

// ============================================================
// ACCESS CONTROL — all 4 roles
// ============================================================
requireRole(['admin', 'doctor', 'nurse', 'receptionist']);

$userId   = $_SESSION['user_id'];
$userName = $_SESSION['user_name'];
$userRole = $_SESSION['user_role'];
$ip       = getUserIP();

// ============================================================
// FEEDBACK MESSAGES — passed via ?msg= after redirects
// ============================================================
$successMsg = '';
$errorMsg   = '';

if (isset($_GET['msg'])) {
    $msgMap = [
        'added'          => 'Incident reported successfully.',
        'updated'        => 'Incident updated successfully.',
        'status_updated' => 'Status updated successfully.',
        'deleted'        => 'Incident soft-deleted and moved to Trash.',
        'restored'       => 'Incident restored successfully.',
        'not_resolved'   => 'Only resolved incidents can be deleted.',
        'not_found'      => 'Incident not found.',
        'access_denied'  => 'You do not have permission to perform that action.',
    ];
    $msgKey = clean($_GET['msg']);
    if (isset($msgMap[$msgKey])) {
        if (in_array($msgKey, ['not_resolved', 'not_found', 'access_denied'])) {
            $errorMsg = $msgMap[$msgKey];
        } else {
            $successMsg = $msgMap[$msgKey];
        }
    }
}

// ============================================================
// POST HANDLER — add, update, status change, delete
// All actions require CSRF validation
// All actions require server-side role check
// ============================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrf();

    $action = isset($_POST['action']) ? clean($_POST['action']) : '';

    // --------------------------------------------------------
    // ACTION: add_incident — all roles may submit
    // --------------------------------------------------------
    if ($action === 'add_incident') {

        $title       = clean($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $priority    = clean($_POST['priority'] ?? 'Medium');
        $assignedTo  = null;

        // Assigned To: only Admin sends/sets this field
        if ($userRole === 'admin' && !empty($_POST['assigned_to'])) {
            $assignedTo = (int)$_POST['assigned_to'];
        }

        // Basic validation
        if (empty($title) || empty($description)) {
            header('Location: incidents.php?msg=error_empty');
            exit;
        }

        // Whitelist priority
        if (!in_array($priority, ['Low', 'Medium', 'High'])) {
            $priority = 'Medium';
        }

        // Validate assigned_to exists
        if ($assignedTo !== null) {
            $chk = $conn->prepare("SELECT id FROM users WHERE id = ? AND deleted_at IS NULL");
            $chk->bind_param("i", $assignedTo);
            $chk->execute();
            if (!$chk->get_result()->fetch_assoc()) {
                $assignedTo = null;
            }
            $chk->close();
        }

        // Insert incident
        $stmt = $conn->prepare(
            "INSERT INTO incidents (title, description, priority, assigned_to, reported_by)
             VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->bind_param("sssii", $title, $description, $priority, $assignedTo, $userId);
        $stmt->execute();
        $stmt->close();

        // Log the action
        logActivity(
            $conn,
            $userId,
            "Reported new incident: " . $title . " (Priority: " . $priority . ")",
            $ip
        );

        // Send incident alert email to admin
        $adminEmail = getAdminEmail($conn);
        if ($adminEmail) {
            sendIncidentAlert($adminEmail, $userName, $title, $priority);
        }

        header('Location: incidents.php?msg=added');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: update_incident — Admin only
    // --------------------------------------------------------
    if ($action === 'update_incident') {

        if ($userRole !== 'admin') {
            header('Location: incidents.php?msg=access_denied');
            exit;
        }

        $incidentId  = (int)($_POST['incident_id'] ?? 0);
        $title       = clean($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $priority    = clean($_POST['priority'] ?? 'Medium');
        $status      = clean($_POST['status'] ?? 'Open');
        $assignedTo  = !empty($_POST['assigned_to']) ? (int)$_POST['assigned_to'] : null;

        if (empty($title) || empty($description) || $incidentId <= 0) {
            header('Location: incidents.php?msg=error_empty');
            exit;
        }

        if (!in_array($priority, ['Low', 'Medium', 'High'])) $priority = 'Medium';
        if (!in_array($status, ['Open', 'Investigating', 'Resolved'])) $status = 'Open';

        $stmt = $conn->prepare(
            "UPDATE incidents
             SET title = ?, description = ?, priority = ?, status = ?, assigned_to = ?
             WHERE id = ?"
        );
        $stmt->bind_param("ssssii", $title, $description, $priority, $status, $assignedTo, $incidentId);
        $stmt->execute();
        $stmt->close();

        logActivity(
            $conn,
            $userId,
            "Updated incident #" . $incidentId . ": " . $title,
            $ip
        );

        header('Location: incidents.php?msg=updated');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: update_status — Admin only, inline dropdown
    // --------------------------------------------------------
    if ($action === 'update_status') {

        if ($userRole !== 'admin') {
            header('Location: incidents.php?msg=access_denied');
            exit;
        }

        $incidentId = (int)($_POST['incident_id'] ?? 0);
        $newStatus  = clean($_POST['status'] ?? '');

        if ($incidentId <= 0 || !in_array($newStatus, ['Open', 'Investigating', 'Resolved'])) {
            header('Location: incidents.php?msg=not_found');
            exit;
        }

        $stmt = $conn->prepare("UPDATE incidents SET status = ? WHERE id = ?");
        $stmt->bind_param("si", $newStatus, $incidentId);
        $stmt->execute();
        $stmt->close();

        logActivity(
            $conn,
            $userId,
            "Changed incident #" . $incidentId . " status to: " . $newStatus,
            $ip
        );

        header('Location: incidents.php?msg=status_updated');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: delete_incident — Admin only, resolved only
    // --------------------------------------------------------
    if ($action === 'delete_incident') {

        if ($userRole !== 'admin') {
            header('Location: incidents.php?msg=access_denied');
            exit;
        }

        $incidentId = (int)($_POST['incident_id'] ?? 0);

        if ($incidentId <= 0) {
            header('Location: incidents.php?msg=not_found');
            exit;
        }

        // Fetch the incident to verify it is Resolved
        $chk = $conn->prepare("SELECT title, status FROM incidents WHERE id = ? AND deleted_at IS NULL");
        $chk->bind_param("i", $incidentId);
        $chk->execute();
        $existing = $chk->get_result()->fetch_assoc();
        $chk->close();

        if (!$existing) {
            header('Location: incidents.php?msg=not_found');
            exit;
        }

        if ($existing['status'] !== 'Resolved') {
            header('Location: incidents.php?msg=not_resolved');
            exit;
        }

        $stmt = $conn->prepare(
            "UPDATE incidents SET deleted_at = NOW(), deleted_by = ? WHERE id = ?"
        );
        $stmt->bind_param("ii", $userId, $incidentId);
        $stmt->execute();
        $stmt->close();

        logActivity(
            $conn,
            $userId,
            "Deleted resolved incident #" . $incidentId . ": " . $existing['title'],
            $ip
        );

        header('Location: incidents.php?msg=deleted');
        exit;
    }

    // --------------------------------------------------------
    // ACTION: restore_incident — Admin only, from Trash
    // --------------------------------------------------------
    if ($action === 'restore_incident') {

        if ($userRole !== 'admin') {
            header('Location: incidents.php?msg=access_denied');
            exit;
        }

        $incidentId = (int)($_POST['incident_id'] ?? 0);

        if ($incidentId <= 0) {
            header('Location: incidents.php?msg=not_found');
            exit;
        }

        // Fetch from trash to verify it exists and is actually deleted
        $chk = $conn->prepare(
            "SELECT title FROM incidents WHERE id = ? AND deleted_at IS NOT NULL"
        );
        $chk->bind_param("i", $incidentId);
        $chk->execute();
        $existing = $chk->get_result()->fetch_assoc();
        $chk->close();

        if (!$existing) {
            header('Location: incidents.php?msg=not_found');
            exit;
        }

        $stmt = $conn->prepare(
            "UPDATE incidents SET deleted_at = NULL, deleted_by = NULL WHERE id = ?"
        );
        $stmt->bind_param("i", $incidentId);
        $stmt->execute();
        $stmt->close();

        logActivity(
            $conn,
            $userId,
            "Restored soft-deleted incident #" . $incidentId . ": " . $existing['title'],
            $ip
        );

        header('Location: incidents.php?msg=restored');
        exit;
    }
}

// ============================================================
// LOG PAGE ACCESS
// ============================================================
logActivity($conn, $userId, "Viewed incidents page", $ip);

// ============================================================
// FETCH ALL INCIDENTS — newest first
// JOIN users twice: assigned_to and reported_by names
// ============================================================
$stmt = $conn->prepare(
    "SELECT i.id, i.title, i.description, i.priority, i.status,
            i.created_at,
            a.name AS assigned_name,
            r.name AS reporter_name,
            i.assigned_to, i.reported_by
     FROM incidents i
     LEFT JOIN users a ON a.id = i.assigned_to
     LEFT JOIN users r ON r.id = i.reported_by
     WHERE i.deleted_at IS NULL
     ORDER BY i.id DESC, i.created_at DESC"
);
$stmt->execute();
$result    = $stmt->get_result();
$incidents = [];
while ($row = $result->fetch_assoc()) {
    $incidents[] = $row;
}
$stmt->close();

// ============================================================
// FETCH ALL USERS — for Assigned To dropdown (Admin only)
// ============================================================
$allUsers = [];
if ($userRole === 'admin') {
    $stmt = $conn->prepare("SELECT id, name, role FROM users WHERE deleted_at IS NULL ORDER BY name ASC");
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $allUsers[] = $row;
    }
    $stmt->close();
}

// ============================================================
// FETCH TRASHED INCIDENTS — Admin only, for Trash section
// ============================================================
$trashedIncidents = [];
if ($userRole === 'admin') {
    $stmt = $conn->prepare(
        "SELECT i.id, i.title, i.description, i.priority, i.status,
                i.created_at, i.deleted_at,
                a.name AS assigned_name,
                r.name  AS reporter_name,
                d.name  AS deleted_by_name
         FROM incidents i
         LEFT JOIN users a ON a.id = i.assigned_to
         LEFT JOIN users r ON r.id = i.reported_by
         LEFT JOIN users d ON d.id = i.deleted_by
         WHERE i.deleted_at IS NOT NULL
         ORDER BY i.deleted_at DESC"
    );
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $trashedIncidents[] = $row;
    }
    $stmt->close();
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Incidents</title>
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
           SECTION CARD — form + table container
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
            padding: 24px;
        }

        /* ======================================================
           FORM STYLES
        ====================================================== */
        .form-label {
            font-size: 13px;
            font-weight: 600;
            color: #475569;
            margin-bottom: 5px;
        }

        .form-control,
        .form-select {
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 13px;
            color: #1E293B;
            padding: 9px 12px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: #2563EB;
            box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
            outline: none;
        }

        textarea.form-control {
            resize: vertical;
            min-height: 90px;
        }

        /* ======================================================
           BUTTONS — exact spec colors
        ====================================================== */
        .btn-primary-mv {
            background: #2563EB;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            font-weight: 500;
            padding: 9px 22px;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .btn-primary-mv:hover {
            background: #1E40AF;
            transform: translateY(-1px);
        }

        .btn-danger-mv {
            background: #EF4444;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-family: 'Poppins', sans-serif;
            font-size: 12px;
            font-weight: 500;
            padding: 5px 12px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .btn-danger-mv:hover {
            background: #DC2626;
        }

        .btn-restore-mv {
            background: #22C55E;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-family: 'Poppins', sans-serif;
            font-size: 12px;
            font-weight: 500;
            padding: 5px 12px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .btn-restore-mv:hover {
            background: #16A34A;
        }

        .trash-section-card .card-header-mv {
            background: linear-gradient(135deg, #7C3AED, #6D28D9);
        }

        .btn-edit-mv {
            background: #F59E0B;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-family: 'Poppins', sans-serif;
            font-size: 12px;
            font-weight: 500;
            padding: 5px 12px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .btn-edit-mv:hover {
            background: #D97706;
        }

        /* ======================================================
           TABLE STYLES
        ====================================================== */
        .table-mv {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .table-mv thead th {
            background: #F8FAFC;
            color: #475569;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 12px 14px;
            border-bottom: 2px solid #E2E8F0;
            white-space: nowrap;
        }

        .table-mv tbody tr {
            border-bottom: 1px solid #F1F5F9;
            transition: background 0.15s;
        }

        .table-mv tbody tr:hover {
            background: #F8FAFC;
        }

        .table-mv tbody tr:last-child {
            border-bottom: none;
        }

        .table-mv tbody td {
            padding: 12px 14px;
            color: #1E293B;
            vertical-align: middle;
        }

        .incident-title-cell {
            max-width: 200px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-weight: 600;
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
            white-space: nowrap;
        }

        .badge-investigating {
            background: #F59E0B;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }

        .badge-resolved {
            background: #22C55E;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }

        .badge-priority-low {
            background: #38BDF8;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }

        .badge-priority-medium {
            background: #F59E0B;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }

        .badge-priority-high {
            background: #EF4444;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }

        /* ======================================================
           INLINE STATUS DROPDOWN (Admin only)
        ====================================================== */
        .status-form-inline {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .status-select-inline {
            border: 1px solid #E2E8F0;
            border-radius: 6px;
            font-family: 'Poppins', sans-serif;
            font-size: 12px;
            padding: 4px 8px;
            color: #1E293B;
            cursor: pointer;
            background: #ffffff;
        }

        .status-select-inline:focus {
            border-color: #2563EB;
            outline: none;
        }

        .btn-status-apply {
            background: #2563EB;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 500;
            padding: 4px 10px;
            cursor: pointer;
            font-family: 'Poppins', sans-serif;
            transition: background 0.2s;
        }

        .btn-status-apply:hover {
            background: #1E40AF;
        }

        /* ======================================================
           ALERT MESSAGES
        ====================================================== */
        .alert-mv-success {
            background: #F0FDF4;
            border: 1px solid #86EFAC;
            color: #166534;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 13px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .alert-mv-error {
            background: #FEF2F2;
            border: 1px solid #FECACA;
            color: #991B1B;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 13px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* ======================================================
           EMPTY STATE
        ====================================================== */
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: #94A3B8;
        }

        .empty-state .empty-icon {
            font-size: 40px;
            display: block;
            margin-bottom: 10px;
        }

        /* ======================================================
           MODAL OVERRIDES
        ====================================================== */
        .modal-header-mv {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            border-radius: 12px 12px 0 0;
            padding: 16px 20px;
        }

        .modal-header-mv .modal-title {
            font-size: 15px;
            font-weight: 600;
        }

        .modal-header-mv .btn-close {
            filter: brightness(0) invert(1);
            opacity: 0.8;
        }

        .modal-content {
            border: none;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
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

            .status-form-inline {
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

<!-- ============================================================
     MOBILE OVERLAY
============================================================ -->
<div id="overlay"></div>

<!-- ============================================================
     SIDEBAR — identical to dashboard.php, active on incidents
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

        <?php if ($userRole === 'admin'): ?>
        <a href="assets.php">
            <span>🏗️</span> Assets
        </a>
        <?php endif; ?>

        <?php if ($userRole === 'admin'): ?>
        <a href="risks.php">
            <span>⚠️</span> Risks
        </a>
        <?php endif; ?>

        <a href="incidents.php" class="active">
            <span>🚨</span> Incidents
        </a>

        <?php if ($userRole === 'admin'): ?>
        <a href="logs.php">
            <span>📋</span> Logs
        </a>
        <?php endif; ?>

        <?php if ($userRole === 'admin'): ?>
        <a href="users.php">
            <span>👥</span> Users
        </a>
        <?php endif; ?>

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
    <span class="topbar-title">🚨 Incidents</span>
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
        <h2>Incident Management</h2>
        <p>Report and track security incidents — all roles can submit, Admin manages status</p>
    </div>

    <!-- FEEDBACK MESSAGES -->
    <?php if ($successMsg): ?>
        <div class="alert-mv-success">✅ <?= htmlspecialchars($successMsg, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>
    <?php if ($errorMsg): ?>
        <div class="alert-mv-error">⚠️ <?= htmlspecialchars($errorMsg, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <!-- ========================================================
         REPORT INCIDENT FORM — all roles
    ========================================================= -->
    <div class="section-card">
        <div class="card-header-mv">
            🚨 Report New Incident
        </div>
        <div class="card-body-mv">
            <form method="POST" action="incidents.php">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="action" value="add_incident">

                <div class="row g-3">

                    <!-- Title -->
                    <div class="col-12 col-md-6">
                        <label class="form-label" for="title">Incident Title <span style="color:#EF4444;">*</span></label>
                        <input
                            type="text"
                            class="form-control"
                            id="title"
                            name="title"
                            placeholder="Brief title of the incident"
                            maxlength="200"
                            required
                        >
                    </div>

                    <!-- Priority -->
                    <div class="col-12 col-md-<?= $userRole === 'admin' ? '3' : '6' ?>">
                        <label class="form-label" for="priority">Priority <span style="color:#EF4444;">*</span></label>
                        <select class="form-select" id="priority" name="priority" required>
                            <option value="Low">🔵 Low</option>
                            <option value="Medium" selected>🟡 Medium</option>
                            <option value="High">🔴 High</option>
                        </select>
                    </div>

                    <!-- Assigned To — Admin only -->
                    <?php if ($userRole === 'admin'): ?>
                    <div class="col-12 col-md-3">
                        <label class="form-label" for="assigned_to">Assign To</label>
                        <select class="form-select" id="assigned_to" name="assigned_to">
                            <option value="">— Unassigned —</option>
                            <?php foreach ($allUsers as $u): ?>
                                <option value="<?= (int)$u['id'] ?>">
                                    <?= htmlspecialchars($u['name'], ENT_QUOTES, 'UTF-8') ?>
                                    (<?= htmlspecialchars(ucfirst($u['role']), ENT_QUOTES, 'UTF-8') ?>)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <?php endif; ?>

                    <!-- Description -->
                    <div class="col-12">
                        <label class="form-label" for="description">Description <span style="color:#EF4444;">*</span></label>
                        <textarea
                            class="form-control"
                            id="description"
                            name="description"
                            placeholder="Describe the incident in detail — what happened, when, where, who was involved..."
                            required
                        ></textarea>
                    </div>

                    <!-- Submit -->
                    <div class="col-12">
                        <button type="submit" class="btn-primary-mv">
                            🚨 Submit Incident Report
                        </button>
                    </div>

                </div>
            </form>
        </div>
    </div>

    <!-- ========================================================
         INCIDENTS TABLE — all roles view
    ========================================================= -->
    <div class="section-card">
        <div class="card-header-mv" style="justify-content: space-between;">
            <span>📋 All Incidents (<?= count($incidents) ?>)</span>
        </div>
        <div class="card-body-mv" style="padding: 0;">

            <?php if (empty($incidents)): ?>
                <div class="empty-state">
                    <span class="empty-icon">✅</span>
                    No incidents reported — system is clear.
                </div>

            <?php else: ?>
                <div class="table-responsive">
                    <table class="table-mv">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Title</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th>Assigned To</th>
                                <th>Reported By</th>
                                <th>Date</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($incidents as $inc): ?>
                            <?php
                                // Priority badge class
                                $priorityClass = match($inc['priority']) {
                                    'Low'    => 'badge-priority-low',
                                    'Medium' => 'badge-priority-medium',
                                    'High'   => 'badge-priority-high',
                                    default  => 'badge-priority-medium',
                                };

                                // Status badge class
                                $statusClass = match($inc['status']) {
                                    'Open'          => 'badge-open',
                                    'Investigating' => 'badge-investigating',
                                    'Resolved'      => 'badge-resolved',
                                    default         => 'badge-open',
                                };
                            ?>
                            <tr>
                                <!-- ID -->
                                <td style="color:#94A3B8; font-weight:600;">#<?= (int)$inc['id'] ?></td>

                                <!-- Title -->
                                <td>
                                    <div class="incident-title-cell" title="<?= htmlspecialchars($inc['title'], ENT_QUOTES, 'UTF-8') ?>">
                                        <?= htmlspecialchars($inc['title'], ENT_QUOTES, 'UTF-8') ?>
                                    </div>
                                </td>

                                <!-- Priority Badge -->
                                <td>
                                    <span class="<?= $priorityClass ?>">
                                        <?= htmlspecialchars($inc['priority'], ENT_QUOTES, 'UTF-8') ?>
                                    </span>
                                </td>

                                <!-- Status — Admin gets inline dropdown, others see badge -->
                                <td>
                                    <?php if ($userRole === 'admin'): ?>
                                        <form method="POST" action="incidents.php" class="status-form-inline">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                            <input type="hidden" name="action" value="update_status">
                                            <input type="hidden" name="incident_id" value="<?= (int)$inc['id'] ?>">
                                            <select name="status" class="status-select-inline">
                                                <option value="Open"          <?= $inc['status'] === 'Open'          ? 'selected' : '' ?>>Open</option>
                                                <option value="Investigating" <?= $inc['status'] === 'Investigating' ? 'selected' : '' ?>>Investigating</option>
                                                <option value="Resolved"      <?= $inc['status'] === 'Resolved'      ? 'selected' : '' ?>>Resolved</option>
                                            </select>
                                            <button type="submit" class="btn-status-apply">Apply</button>
                                        </form>
                                    <?php else: ?>
                                        <span class="<?= $statusClass ?>">
                                            <?= htmlspecialchars($inc['status'], ENT_QUOTES, 'UTF-8') ?>
                                        </span>
                                    <?php endif; ?>
                                </td>

                                <!-- Assigned To -->
                                <td style="color:#475569;">
                                    <?php if ($inc['assigned_name']): ?>
                                        <?= htmlspecialchars($inc['assigned_name'], ENT_QUOTES, 'UTF-8') ?>
                                    <?php else: ?>
                                        <span style="color:#94A3B8; font-style:italic;">Unassigned</span>
                                    <?php endif; ?>
                                </td>

                                <!-- Reported By -->
                                <td style="color:#475569;">
                                    <?= htmlspecialchars($inc['reporter_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                                </td>

                                <!-- Date -->
                                <td style="color:#94A3B8; white-space:nowrap;">
                                    <?= date('M j, Y', strtotime($inc['created_at'])) ?>
                                    <div style="font-size:11px;">
                                        <?= date('g:i A', strtotime($inc['created_at'])) ?>
                                    </div>
                                </td>

                                <!-- Actions -->
                                <td>
                                    <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">

                                        <?php if ($userRole === 'admin'): ?>

                                            <!-- Edit button — opens modal -->
                                            <button
                                                class="btn-edit-mv"
                                                data-id="<?= (int)$inc['id'] ?>"
                                                data-title="<?= htmlspecialchars($inc['title'], ENT_QUOTES, 'UTF-8') ?>"
                                                data-description="<?= htmlspecialchars($inc['description'], ENT_QUOTES, 'UTF-8') ?>"
                                                data-priority="<?= htmlspecialchars($inc['priority'], ENT_QUOTES, 'UTF-8') ?>"
                                                data-status="<?= htmlspecialchars($inc['status'], ENT_QUOTES, 'UTF-8') ?>"
                                                data-assigned="<?= $inc['assigned_to'] !== null ? (int)$inc['assigned_to'] : '' ?>"
                                                onclick="openEditModal(this)"
                                            >
                                                ✏️ Edit
                                            </button>

                                            <!-- Delete — only if Resolved -->
                                            <?php if ($inc['status'] === 'Resolved'): ?>
                                                    <form method="POST" action="incidents.php" style="display:inline;" onsubmit="return confirm('Move this resolved incident to Trash? Admins can restore it later.');">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                                    <input type="hidden" name="action" value="delete_incident">
                                                    <input type="hidden" name="incident_id" value="<?= (int)$inc['id'] ?>">
                                                    <button type="submit" class="btn-danger-mv">🗑️ Delete</button>
                                                </form>
                                            <?php else: ?>
                                                <span style="font-size:11px; color:#CBD5E1; font-style:italic;">Resolve to delete</span>
                                            <?php endif; ?>

                                        <?php else: ?>
                                            <span style="font-size:12px; color:#94A3B8;">—</span>
                                        <?php endif; ?>

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

    <!-- ========================================================
         TRASH SECTION — Admin only, soft-deleted incidents
    ========================================================= -->
    <?php if ($userRole === 'admin'): ?>
    <div class="section-card trash-section-card" style="margin-top: 24px;">
        <div class="card-header-mv" style="justify-content: space-between;">
            <span>🗑️ Trash — Deleted Incidents (<?= count($trashedIncidents) ?>)</span>
        </div>
        <div class="card-body-mv" style="padding: 0;">

            <?php if (empty($trashedIncidents)): ?>
                <div class="empty-state">
                    <span class="empty-icon">🗑️</span>
                    Trash is empty — no deleted incidents.
                </div>

            <?php else: ?>
                <div class="table-responsive">
                    <table class="table-mv">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Title</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th>Reported By</th>
                                <th>Deleted By</th>
                                <th>Deleted At</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($trashedIncidents as $t): ?>
                            <?php
                                $priorityClass = match($t['priority']) {
                                    'Low'    => 'badge-priority-low',
                                    'Medium' => 'badge-priority-medium',
                                    'High'   => 'badge-priority-high',
                                    default  => 'badge-priority-medium',
                                };
                            ?>
                            <tr>
                                <td style="color:#94A3B8; font-weight:600;">#<?= (int)$t['id'] ?></td>

                                <td>
                                    <div class="incident-title-cell" title="<?= htmlspecialchars($t['title'], ENT_QUOTES, 'UTF-8') ?>">
                                        <?= htmlspecialchars($t['title'], ENT_QUOTES, 'UTF-8') ?>
                                    </div>
                                </td>

                                <td>
                                    <span class="<?= $priorityClass ?>">
                                        <?= htmlspecialchars($t['priority'], ENT_QUOTES, 'UTF-8') ?>
                                    </span>
                                </td>

                                <td style="color:#475569;">
                                    <?= htmlspecialchars($t['status'], ENT_QUOTES, 'UTF-8') ?>
                                </td>

                                <td style="color:#475569;">
                                    <?= htmlspecialchars($t['reporter_name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?>
                                </td>

                                <td style="color:#475569;">
                                    <?= htmlspecialchars($t['deleted_by_name'] ?? '—', ENT_QUOTES, 'UTF-8') ?>
                                </td>

                                <td style="color:#94A3B8; white-space:nowrap;">
                                    <?= date('M j, Y', strtotime($t['deleted_at'])) ?>
                                    <div style="font-size:11px;">
                                        <?= date('g:i A', strtotime($t['deleted_at'])) ?>
                                    </div>
                                </td>

                                <td>
                                    <form method="POST" action="incidents.php" style="display:inline;"
                                          onsubmit="return confirm('Restore this incident back to the active list?');">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                        <input type="hidden" name="action" value="restore_incident">
                                        <input type="hidden" name="incident_id" value="<?= (int)$t['id'] ?>">
                                        <button type="submit" class="btn-restore-mv">♻️ Restore</button>
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

</main>

<!-- ============================================================
     EDIT INCIDENT MODAL — Admin only
============================================================ -->
<?php if ($userRole === 'admin'): ?>
<div class="modal fade" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content">

            <div class="modal-header-mv">
                <h5 class="modal-title" id="editModalLabel">✏️ Edit Incident</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>

            <div class="modal-body" style="padding: 24px;">
                <form method="POST" action="incidents.php" id="editForm">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="action" value="update_incident">
                    <input type="hidden" name="incident_id" id="edit_incident_id">

                    <div class="row g-3">

                        <!-- Title -->
                        <div class="col-12">
                            <label class="form-label" for="edit_title">Incident Title <span style="color:#EF4444;">*</span></label>
                            <input type="text" class="form-control" id="edit_title" name="title" maxlength="200" required>
                        </div>

                        <!-- Priority -->
                        <div class="col-12 col-md-4">
                            <label class="form-label" for="edit_priority">Priority</label>
                            <select class="form-select" id="edit_priority" name="priority">
                                <option value="Low">🔵 Low</option>
                                <option value="Medium">🟡 Medium</option>
                                <option value="High">🔴 High</option>
                            </select>
                        </div>

                        <!-- Status -->
                        <div class="col-12 col-md-4">
                            <label class="form-label" for="edit_status">Status</label>
                            <select class="form-select" id="edit_status" name="status">
                                <option value="Open">Open</option>
                                <option value="Investigating">Investigating</option>
                                <option value="Resolved">Resolved</option>
                            </select>
                        </div>

                        <!-- Assigned To -->
                        <div class="col-12 col-md-4">
                            <label class="form-label" for="edit_assigned_to">Assign To</label>
                            <select class="form-select" id="edit_assigned_to" name="assigned_to">
                                <option value="">— Unassigned —</option>
                                <?php foreach ($allUsers as $u): ?>
                                    <option value="<?= (int)$u['id'] ?>">
                                        <?= htmlspecialchars($u['name'], ENT_QUOTES, 'UTF-8') ?>
                                        (<?= htmlspecialchars(ucfirst($u['role']), ENT_QUOTES, 'UTF-8') ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <!-- Description -->
                        <div class="col-12">
                            <label class="form-label" for="edit_description">Description <span style="color:#EF4444;">*</span></label>
                            <textarea class="form-control" id="edit_description" name="description" style="min-height:110px;" required></textarea>
                        </div>

                    </div>
                </form>
            </div>

            <div class="modal-footer" style="padding: 16px 24px; border-top: 1px solid #E2E8F0;">
                <button type="button" class="btn-danger-mv" data-bs-dismiss="modal">Cancel</button>
                <button type="submit" form="editForm" class="btn-primary-mv">💾 Save Changes</button>
            </div>

        </div>
    </div>
</div>
<?php endif; ?>

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
    // EDIT MODAL — populate fields from table row data
    // Called by each Edit button's onclick
    // ============================================================
    <?php if ($userRole === 'admin'): ?>
    function openEditModal(btn) {
        document.getElementById('edit_incident_id').value  = btn.dataset.id;
        document.getElementById('edit_title').value        = btn.dataset.title;
        document.getElementById('edit_description').value  = btn.dataset.description;
        document.getElementById('edit_priority').value     = btn.dataset.priority;
        document.getElementById('edit_status').value       = btn.dataset.status;

        const assignedSelect = document.getElementById('edit_assigned_to');
        assignedSelect.value = btn.dataset.assigned || '';

        const modal = new bootstrap.Modal(document.getElementById('editModal'));
        modal.show();
    }
    <?php endif; ?>

    // ============================================================
    // AUTO-DISMISS FEEDBACK MESSAGES after 4 seconds
    // ============================================================
    const successAlert = document.querySelector('.alert-mv-success');
    const errorAlert   = document.querySelector('.alert-mv-error');

    if (successAlert) {
        setTimeout(() => {
            successAlert.style.transition = 'opacity 0.5s';
            successAlert.style.opacity    = '0';
            setTimeout(() => successAlert.remove(), 500);
        }, 4000);
    }

    if (errorAlert) {
        setTimeout(() => {
            errorAlert.style.transition = 'opacity 0.5s';
            errorAlert.style.opacity    = '0';
            setTimeout(() => errorAlert.remove(), 500);
        }, 5000);
    }
</script>

</body>
</html>