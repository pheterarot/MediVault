<?php
// ============================================================
// MEDIVAULT — 404.php
// Purpose:  Handle wrong or missing URLs gracefully
// Layout:   No sidebar — centered card layout
// Access:   Public (no role required — may not be logged in)
// Rules:    Set HTTP 404 response code immediately
//           Show "Go to Dashboard" only if session exists
//           Always show "Go to Login"
//           MediVault branding — Poppins, spec colors
//           No sidebar, no topbar
// ============================================================

session_start();

// ============================================================
// SET HTTP RESPONSE CODE — must be 404, not 200
// Always set before any HTML output
// ============================================================
http_response_code(404);

// ============================================================
// SESSION CHECK — determines which buttons to show
// Only check if user_id exists — no DB or auth needed here
// Never require db.php or auth.php on a 404 page —
// the missing page might be a broken include path itself
// ============================================================
$isLoggedIn = isset($_SESSION['user_id']);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVault — 404 Not Found</title>
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
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        /* ======================================================
           CENTERED CARD — pre-login style layout
        ====================================================== */
        .error-card {
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            width: 100%;
            max-width: 480px;
            overflow: hidden;
            text-align: center;
        }

        /* ======================================================
           CARD HEADER — blue gradient branding
        ====================================================== */
        .error-card-header {
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            padding: 28px 30px 24px;
        }

        .error-card-header .brand-title {
            color: #ffffff;
            font-size: 22px;
            font-weight: 700;
            letter-spacing: 1px;
            margin: 0 0 4px;
        }

        .error-card-header .brand-tagline {
            color: #BAE6FD;
            font-size: 11px;
            margin: 0;
        }

        /* ======================================================
           CARD BODY — 404 display + message
        ====================================================== */
        .error-card-body {
            padding: 40px 36px 36px;
        }

        /* Large 404 text — primary blue per spec */
        .error-code {
            font-size: 96px;
            font-weight: 700;
            color: #2563EB;
            line-height: 1;
            margin-bottom: 8px;
            letter-spacing: -2px;
        }

        .error-divider {
            width: 50px;
            height: 3px;
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            border-radius: 2px;
            margin: 0 auto 20px;
        }

        /* "Page Not Found" heading */
        .error-heading {
            font-size: 20px;
            font-weight: 600;
            color: #1E293B;
            margin-bottom: 12px;
        }

        /* Helpful message */
        .error-message {
            font-size: 14px;
            color: #94A3B8;
            line-height: 1.7;
            margin-bottom: 32px;
        }

        /* ======================================================
           BUTTONS
        ====================================================== */
        .btn-go-dashboard {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: linear-gradient(135deg, #1E40AF, #2563EB);
            color: #ffffff;
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            font-weight: 600;
            padding: 11px 24px;
            border-radius: 8px;
            border: none;
            text-decoration: none;
            transition: all 0.2s;
            width: 100%;
            margin-bottom: 12px;
        }

        .btn-go-dashboard:hover {
            background: linear-gradient(135deg, #1e3a8a, #1E40AF);
            color: #ffffff;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(37,99,235,0.3);
        }

        .btn-go-login {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: #ffffff;
            color: #2563EB;
            font-family: 'Poppins', sans-serif;
            font-size: 14px;
            font-weight: 600;
            padding: 10px 24px;
            border-radius: 8px;
            border: 2px solid #2563EB;
            text-decoration: none;
            transition: all 0.2s;
            width: 100%;
        }

        .btn-go-login:hover {
            background: #EFF6FF;
            color: #1E40AF;
            border-color: #1E40AF;
            transform: translateY(-1px);
        }

        /* ======================================================
           CARD FOOTER — subtle branding
        ====================================================== */
        .error-card-footer {
            background: #F1F5F9;
            padding: 14px 30px;
            border-top: 1px solid #E2E8F0;
        }

        .error-card-footer p {
            color: #94A3B8;
            font-size: 11px;
            margin: 0;
        }

        /* ======================================================
           RESPONSIVE
        ====================================================== */
        @media (max-width: 480px) {
            .error-code {
                font-size: 72px;
            }

            .error-heading {
                font-size: 18px;
            }

            .error-card-body {
                padding: 30px 24px 28px;
            }
        }
    </style>
</head>
<body>

<!-- ============================================================
     CENTERED ERROR CARD — no sidebar on 404 page
============================================================ -->
<div class="error-card">

    <!-- Card Header — MediVault branding -->
    <div class="error-card-header">
        <p class="brand-title">🏥 MediVault</p>
        <p class="brand-tagline">Securing Patient Records. Protecting Lives.</p>
    </div>

    <!-- Card Body — 404 display + message + buttons -->
    <div class="error-card-body">

        <!-- Large 404 in primary blue -->
        <div class="error-code">404</div>

        <!-- Accent divider -->
        <div class="error-divider"></div>

        <!-- Page Not Found heading -->
        <h1 class="error-heading">Page Not Found</h1>

        <!-- Helpful message -->
        <p class="error-message">
            The page you're looking for doesn't exist, has been moved,
            or you may not have permission to access it.
        </p>

        <!-- Buttons — conditional on session -->

        <?php if ($isLoggedIn): ?>
        <!-- Go to Dashboard — only shown if user is logged in -->
        <a href="dashboard.php" class="btn-go-dashboard">
            <span>📊</span> Go to Dashboard
        </a>
        <?php endif; ?>

        <!-- Go to Login — always shown -->
        <a href="index.php" class="btn-go-login">
            <span>🔑</span> Go to Login
        </a>

    </div>

    <!-- Card Footer -->
    <div class="error-card-footer">
        <p>MediVault Security System &copy; <?= date('Y') ?> &mdash; If this keeps happening, contact your administrator.</p>
    </div>

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>
