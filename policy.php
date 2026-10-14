<?php
// ============================================================
// MEDIVAULT — policy.php
// Purpose:  Security policy documentation viewer
// Layout:   Full sidebar
// Access:   All roles (admin, doctor, nurse, receptionist)
// Rules:    View only — no add/edit/delete for any role
//           Log page access to activity_logs
//           Sidebar identical to dashboard.php
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';

// ============================================================
// ACCESS CONTROL — all 4 roles allowed
// ============================================================
requireRole(['admin', 'doctor', 'nurse', 'receptionist']);

$userId   = $_SESSION['user_id'];
$userName = $_SESSION['user_name'];
$userRole = $_SESSION['user_role'];
$ip       = getUserIP();

// ============================================================
// LOG PAGE ACCESS
// ============================================================
logActivity($conn, $userId, "Viewed policy page", $ip);

// ============================================================
// FETCH ALL POLICIES — ordered by ID ascending
// ============================================================
$policies = [];
$stmt = $conn->prepare(
    "SELECT id, title, content, updated_at
     FROM policies
     ORDER BY id ASC"
);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $policies[] = $row;
}
$stmt->close();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — Policy</title>
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
           POLICY CARDS
        ====================================================== */
        .policy-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            background: #ffffff;
            margin-bottom: 24px;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .policy-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
        }

        .policy-card-header {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            font-weight: 600;
            font-size: 15px;
            padding: 16px 22px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .policy-card-header .policy-number {
            background: rgba(255,255,255,0.2);
            color: #ffffff;
            font-size: 11px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 20px;
            flex-shrink: 0;
        }

        .policy-card-body {
            padding: 22px;
        }

        .policy-content {
            color: #475569;
            font-size: 14px;
            line-height: 1.8;
            white-space: pre-line;
        }

        .policy-card-footer {
            padding: 10px 22px 14px;
            border-top: 1px solid #F1F5F9;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .policy-card-footer span {
            font-size: 11px;
            color: #94A3B8;
        }

        /* ======================================================
           EMPTY STATE
        ====================================================== */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #94A3B8;
        }

        .empty-state .empty-icon {
            font-size: 48px;
            display: block;
            margin-bottom: 12px;
        }

        .empty-state h5 {
            font-size: 16px;
            font-weight: 600;
            color: #1E293B;
            margin-bottom: 6px;
        }

        .empty-state p {
            font-size: 13px;
            color: #94A3B8;
            margin: 0;
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

            .policy-card-header {
                font-size: 14px;
            }

            .policy-content {
                font-size: 13px;
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
     MOBILE OVERLAY — closes sidebar on backdrop click
============================================================ -->
<div id="overlay"></div>

<!-- ============================================================
     SIDEBAR — identical to dashboard.php, active on policy.php
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

        <!-- Users — ADMIN ONLY -->
        <?php if ($userRole === 'admin'): ?>
        <a href="users.php">
            <span>👥</span> Users
        </a>
        <?php endif; ?>

        <!-- Policy — all roles — ACTIVE -->
        <a href="policy.php" class="active">
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

    <span class="topbar-title">📄 Security Policies</span>

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
        <h2>Security Policies</h2>
        <p>View and understand your organization's security guidelines and compliance requirements.</p>
    </div>

    <!-- ========================================================
         POLICY CARDS — one per policy row from DB
    ========================================================= -->
    <?php if (!empty($policies)): ?>

        <div class="row g-0">
            <?php foreach ($policies as $index => $policy): ?>
            <div class="col-12 col-md-6 pe-md-3">
                <!-- Using col-12 col-md-6 so cards go 2-column on desktop,
                     stacked on mobile. Left column gets pe-md-3 for gutter. -->
            </div>
            <?php endforeach; ?>
        </div>

        <?php
        // Render cards cleanly — full width per card, stacked layout
        // This gives the most readable policy experience per spec:
        // "Clean readable layout" — full-width cards read better than 2-col for text-heavy content
        foreach ($policies as $index => $policy):
            $policyNumber = str_pad($index + 1, 2, '0', STR_PAD_LEFT);
        ?>
        <div class="policy-card">

            <!-- Card Header — blue gradient, policy title -->
            <div class="policy-card-header">
                <span>📄</span>
                <span><?= htmlspecialchars($policy['title'], ENT_QUOTES, 'UTF-8') ?></span>
                <span class="policy-number ms-auto">Policy <?= $policyNumber ?></span>
            </div>

            <!-- Card Body — policy content, readable font size -->
            <div class="policy-card-body">
                <p class="policy-content"><?= htmlspecialchars($policy['content'], ENT_QUOTES, 'UTF-8') ?></p>
            </div>

            <!-- Card Footer — last updated timestamp -->
            <div class="policy-card-footer">
                <span>🕐</span>
                <span>Last updated: <?= date('F j, Y', strtotime($policy['updated_at'])) ?></span>
            </div>

        </div>
        <?php endforeach; ?>

    <?php else: ?>

        <!-- Empty State — no policies in DB yet -->
        <div class="policy-card">
            <div class="policy-card-body">
                <div class="empty-state">
                    <span class="empty-icon">📋</span>
                    <h5>No Policies Found</h5>
                    <p>No security policies have been added to the system yet. Contact your administrator.</p>
                </div>
            </div>
        </div>

    <?php endif; ?>

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
</script>

</body>
</html>