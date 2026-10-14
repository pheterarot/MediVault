<?php
// ============================================================
// Copy this file to includes/config.production.php and fill in
// your real InfinityFree values. config.production.php is listed
// in .gitignore — never commit it.
// ============================================================
$host     = 'sqlXXX.infinityfree.com';
$dbname   = 'if0_XXXXXXXX_medivault';
$username = 'if0_XXXXXXXX';
$password = 'YOUR_DB_PASSWORD';

// Email (Brevo) — used by mailer.php
define('SMTP_HOST', 'smtp-relay.brevo.com');
define('SMTP_PORT', 587);
define('SMTP_USER', 'YOUR_BREVO_SMTP_LOGIN');
define('SMTP_PASS', 'YOUR_BREVO_SMTP_KEY');
