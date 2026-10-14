<?php
session_start();
require 'includes/db.php';

if (isset($_SESSION['user_id'])) {
    $ip = getUserIP();

    // Different log message for timeout vs manual logout
    $action = isset($_GET['reason']) && $_GET['reason'] === 'timeout'
        ? "Session expired — auto logout after inactivity"
        : "User logged out";

    logActivity($conn, $_SESSION['user_id'], $action, $ip);
}

session_unset();
session_destroy();

// Redirect with appropriate message
$reason = $_GET['reason'] ?? '';

if ($reason === 'timeout') {
    header('Location: index.php?msg=session_expired');
} else {
    header('Location: index.php?msg=logout');
}
exit;