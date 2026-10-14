<?php
// ============================================================
// MEDIVAULT — audit.php
// Purpose:  Export activity logs as a branded PDF report
// Layout:   No HTML — triggers file download only
// Access:   Admin only
// Rules:    Log export action BEFORE sending file headers
//           Supports filters: date range, user, suspicious only
//           Batch 7: WHERE al.deleted_at IS NULL by default
//                    Pass GET include_deleted=1 to include them
//                    Filter note reflects deleted inclusion
//           Uses TCPDF (manually placed in /tcpdf/ at project root)
//           No redirect after download — browser handles it
// ============================================================

session_start();
require 'includes/db.php';
require 'includes/auth.php';

// ============================================================
// ACCESS CONTROL — admin only
// ============================================================
requireRole(['admin']);

$userId   = $_SESSION['user_id'];
$userName = $_SESSION['user_name'];
$ip       = getUserIP();

// ============================================================
// FILTER PARAMETERS — passed via GET from logs.php export form
// All inputs sanitized before use in SQL
// ============================================================
$filterFrom          = $_GET['from']            ?? '';
$filterTo            = $_GET['to']              ?? '';
$filterUser          = (int)($_GET['user_id']   ?? 0);
$filterSuspicious    = isset($_GET['suspicious']) && $_GET['suspicious'] === '1';
// Batch 7+: export scope — active (default), all, deleted_only
$exportScope = $_GET['export_scope'] ?? 'active';
if (!in_array($exportScope, ['active', 'all', 'deleted_only'])) {
    $exportScope = 'active';
}

// Validate date formats — reject malformed input
if ($filterFrom && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $filterFrom)) $filterFrom = '';
if ($filterTo   && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $filterTo))   $filterTo   = '';

// ============================================================
// LOAD TCPDF
// Place the TCPDF folder at /tcpdf/ in your project root
// Download from: https://github.com/tecnickcom/TCPDF/releases
// ============================================================
require dirname(__FILE__) . '/tcpdf/tcpdf.php';

// ============================================================
// STEP 1 — BUILD SQL QUERY WITH FILTERS
// ============================================================
$where  = [];
$params = [];
$types  = '';

// Batch 7+: scope filter on deleted_at
if ($exportScope === 'active') {
    $where[] = 'al.deleted_at IS NULL';
} elseif ($exportScope === 'deleted_only') {
    $where[] = 'al.deleted_at IS NOT NULL';
}
// 'all' — no deleted_at condition added

if ($filterFrom) {
    $where[]  = 'al.timestamp >= ?';
    $params[] = $filterFrom . ' 00:00:00';
    $types   .= 's';
}
if ($filterTo) {
    $where[]  = 'al.timestamp <= ?';
    $params[] = $filterTo . ' 23:59:59';
    $types   .= 's';
}
if ($filterUser > 0) {
    $where[]  = 'al.user_id = ?';
    $params[] = $filterUser;
    $types   .= 'i';
}
if ($filterSuspicious) {
    $where[] = 'al.is_suspicious = 1';
}

$whereClause = count($where) ? 'WHERE ' . implode(' AND ', $where) : '';

$sql = "SELECT
            al.id              AS log_id,
            u.name             AS user_name,
            u.email            AS user_email,
            al.action,
            al.ip_address,
            al.is_suspicious,
            al.flagged_reason,
            al.timestamp,
            al.deleted_at
        FROM activity_logs al
        LEFT JOIN users u ON al.user_id = u.id
        {$whereClause}
        ORDER BY al.timestamp DESC";

$stmt = $conn->prepare($sql);
if ($types && $params) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();
$logs   = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// ============================================================
// STEP 2 — SUMMARY COUNTS
// ============================================================
$totalLogs       = count($logs);
$suspiciousCount = 0;
$deletedCount    = 0;
$oldestEntry     = '';
$newestEntry     = '';

foreach ($logs as $log) {
    if ($log['is_suspicious'])  $suspiciousCount++;
    if (!empty($log['deleted_at'])) $deletedCount++;
}
if ($totalLogs > 0) {
    $newestEntry = $logs[0]['timestamp'];
    $oldestEntry = $logs[$totalLogs - 1]['timestamp'];
}

// ============================================================
// STEP 3 — LOG THE EXPORT BEFORE HEADERS
// ============================================================
$filterDesc = [];
if ($filterFrom || $filterTo) $filterDesc[] = "Date: " . ($filterFrom ?: 'start') . " to " . ($filterTo ?: 'now');
if ($filterUser > 0)          $filterDesc[] = "User ID: {$filterUser}";
if ($filterSuspicious)        $filterDesc[] = "Suspicious only";
if ($exportScope === 'all')          $filterDesc[] = "Includes deleted entries";
if ($exportScope === 'deleted_only') $filterDesc[] = "Deleted entries only";
$filterNote = $filterDesc ? ' [Filters: ' . implode(', ', $filterDesc) . ']' : '';

$filename = 'medivault-audit-' . date('Y-m-d') . '.pdf';
logActivity($conn, $userId, "Exported audit log PDF — {$filename}{$filterNote}", $ip);

// ============================================================
// STEP 4 — CUSTOM TCPDF CLASS WITH BRANDED HEADER + FOOTER
// ============================================================
class MediVaultPDF extends TCPDF {

    public $exportedBy  = '';
    public $generatedAt = '';

    public function Header() {
        // Dark blue background bar
        $this->SetFillColor(30, 64, 175);
        $this->Rect(0, 0, $this->getPageWidth(), 26, 'F');

        // Lighter blue accent strip at bottom of header
        $this->SetFillColor(37, 99, 235);
        $this->Rect(0, 21, $this->getPageWidth(), 5, 'F');

        // Title left
        $this->SetTextColor(255, 255, 255);
        $this->SetFont('helvetica', 'B', 16);
        $this->SetXY(10, 4);
        $this->Cell(0, 9, 'MediVault', 0, 0, 'L');

        // Tagline left
        $this->SetFont('helvetica', '', 7.5);
        $this->SetTextColor(186, 230, 253);
        $this->SetXY(10, 14);
        $this->Cell(0, 5, 'Securing Patient Records. Protecting Lives.', 0, 0, 'L');

        // Report label right
        $this->SetFont('helvetica', 'B', 10);
        $this->SetTextColor(255, 255, 255);
        $this->SetXY(-90, 4);
        $this->Cell(80, 7, 'ACTIVITY AUDIT REPORT', 0, 0, 'R');

        // Generated at right
        $this->SetFont('helvetica', '', 7.5);
        $this->SetTextColor(186, 230, 253);
        $this->SetXY(-90, 13);
        $this->Cell(80, 5, $this->generatedAt, 0, 0, 'R');
    }

    public function Footer() {
        $this->SetY(-13);

        // Footer background
        $this->SetFillColor(241, 245, 249);
        $this->Rect(0, $this->GetY() - 1, $this->getPageWidth(), 16, 'F');

        // Left text
        $this->SetFont('helvetica', '', 7.5);
        $this->SetTextColor(148, 163, 184);
        $this->SetX(10);
        $this->Cell(0, 8, 'MediVault Security System  |  Confidential — Authorized Personnel Only', 0, 0, 'L');

        // Page number right
        $this->SetX(-45);
        $this->Cell(35, 8, 'Page ' . $this->getAliasNumPage() . ' of ' . $this->getAliasNbPages(), 0, 0, 'R');
    }
}

// ---- Init PDF (Landscape A4) ----
$pdf = new MediVaultPDF('L', 'mm', 'A4', true, 'UTF-8', false);
$pdf->exportedBy  = $userName;
$pdf->generatedAt = date('F j, Y   H:i');

$pdf->SetCreator('MediVault Security System');
$pdf->SetAuthor($userName);
$pdf->SetTitle('MediVault Audit Report — ' . date('Y-m-d'));
$pdf->SetSubject('Activity Audit Log Export');
$pdf->SetMargins(10, 30, 10);
$pdf->SetHeaderMargin(0);
$pdf->SetFooterMargin(13);
$pdf->SetAutoPageBreak(true, 16);
$pdf->AddPage();
$pdf->SetFont('helvetica', '', 9);

// ============================================================
// META INFO STRIP — exported by, filters, deleted note
// Batch 7: filter note mentions if deleted entries are included
// ============================================================
$pdf->SetFillColor(239, 246, 255);
$pdf->SetDrawColor(37, 99, 235);
$pdf->SetLineWidth(0.3);

$showDeletedMeta = ($exportScope === 'all' || $exportScope === 'deleted_only');

// Taller meta strip when deleted note is present
$metaH = ($showDeletedMeta && $deletedCount > 0) ? 16 : 11;
$pdf->RoundedRect(10, 32, $pdf->getPageWidth() - 20, $metaH, 2, '1111', 'DF');

$pdf->SetFont('helvetica', 'B', 7.5);
$pdf->SetTextColor(30, 64, 175);
$pdf->SetXY(14, 34.5);
$pdf->Cell(28, 5, 'Exported by:', 0, 0, 'L');

$pdf->SetFont('helvetica', '', 7.5);
$pdf->SetTextColor(30, 41, 59);
$pdf->Cell(55, 5, $userName, 0, 0, 'L');

$pdf->SetFont('helvetica', 'B', 7.5);
$pdf->SetTextColor(30, 64, 175);
$pdf->Cell(22, 5, 'Generated:', 0, 0, 'L');

$pdf->SetFont('helvetica', '', 7.5);
$pdf->SetTextColor(30, 41, 59);
$pdf->Cell(55, 5, date('F j, Y   H:i'), 0, 0, 'L');

if ($filterNote) {
    $pdf->SetFont('helvetica', 'B', 7.5);
    $pdf->SetTextColor(30, 64, 175);
    $pdf->Cell(16, 5, 'Filters:', 0, 0, 'L');
    $pdf->SetFont('helvetica', '', 7.5);
    $pdf->SetTextColor(30, 41, 59);
    $cleanFilter = ltrim(str_replace('[Filters: ', '', rtrim($filterNote, ']')));
    $pdf->Cell(0, 5, $cleanFilter, 0, 0, 'L');
}

// Batch 7+: second line in meta strip for deleted scope
if ($showDeletedMeta && $deletedCount > 0) {
    $pdf->SetXY(14, 34.5 + 6);
    $pdf->SetFont('helvetica', 'B', 7);
    $pdf->SetTextColor(127, 29, 29);
    $pdf->Cell(40, 5, '⚠ Deleted entries included:', 0, 0, 'L');
    $pdf->SetFont('helvetica', '', 7);
    $pdf->SetTextColor(30, 41, 59);
    $pdf->Cell(0, 5, $deletedCount . ' soft-deleted log ' . ($deletedCount === 1 ? 'entry is' : 'entries are') . ' shown in this report.', 0, 0, 'L');
}

// ============================================================
// SUMMARY STAT BOXES
// Batch 7: 5 boxes when include_deleted; 4 boxes otherwise
// ============================================================
$statTop = 32 + $metaH + 4;
$pdf->SetY($statTop);

$pageW = $pdf->getPageWidth(); // 297mm landscape

if ($exportScope === 'all' || $exportScope === 'deleted_only') {
    // 5-box layout: Total, Suspicious, Clean, Deleted, Date Range
    $boxGap   = 3;
    $boxCount = 5;
    $boxW     = ($pageW - 20 - ($boxCount - 1) * $boxGap) / $boxCount;
    $boxH     = 19;
    $boxY     = $statTop;

    $dateRange = 'N/A';
    if ($oldestEntry && $newestEntry) {
        $dateRange = date('M j, Y', strtotime($oldestEntry)) . ' — ' . date('M j, Y', strtotime($newestEntry));
    }

    $stats = [
        ['label' => 'TOTAL LOGS',    'value' => (string)$totalLogs,                         'vcolor' => [30,  64,  175], 'bg' => [239, 246, 255], 'border' => [147, 197, 253]],
        ['label' => 'SUSPICIOUS',    'value' => (string)$suspiciousCount,                   'vcolor' => [153, 27,  27],  'bg' => [254, 226, 226], 'border' => [252, 165, 165]],
        ['label' => 'CLEAN',         'value' => (string)($totalLogs - $suspiciousCount),    'vcolor' => [22,  101, 52],  'bg' => [220, 252, 231], 'border' => [134, 239, 172]],
        ['label' => 'DELETED',       'value' => (string)$deletedCount,                      'vcolor' => [127, 29,  29],  'bg' => [254, 242, 242], 'border' => [252, 202, 202]],
        ['label' => 'DATE RANGE',    'value' => $dateRange,                                 'vcolor' => [100, 116, 139], 'bg' => [241, 245, 249], 'border' => [203, 213, 225]],
    ];
} else {
    // 4-box layout (original)
    $boxGap   = 4;
    $boxCount = 4;
    $boxW     = ($pageW - 20 - ($boxCount - 1) * $boxGap) / $boxCount;
    $boxH     = 19;
    $boxY     = $statTop;

    $dateRange = 'N/A';
    if ($oldestEntry && $newestEntry) {
        $dateRange = date('M j, Y', strtotime($oldestEntry)) . ' — ' . date('M j, Y', strtotime($newestEntry));
    }

    $stats = [
        ['label' => 'TOTAL LOGS',    'value' => (string)$totalLogs,                         'vcolor' => [30,  64,  175], 'bg' => [239, 246, 255], 'border' => [147, 197, 253]],
        ['label' => 'SUSPICIOUS',    'value' => (string)$suspiciousCount,                   'vcolor' => [153, 27,  27],  'bg' => [254, 226, 226], 'border' => [252, 165, 165]],
        ['label' => 'CLEAN ENTRIES', 'value' => (string)($totalLogs - $suspiciousCount),    'vcolor' => [22,  101, 52],  'bg' => [220, 252, 231], 'border' => [134, 239, 172]],
        ['label' => 'DATE RANGE',    'value' => $dateRange,                                 'vcolor' => [100, 116, 139], 'bg' => [241, 245, 249], 'border' => [203, 213, 225]],
    ];
}

foreach ($stats as $i => $stat) {
    $x = 10 + $i * ($boxW + $boxGap);

    $pdf->SetFillColor($stat['bg'][0], $stat['bg'][1], $stat['bg'][2]);
    $pdf->SetDrawColor($stat['border'][0], $stat['border'][1], $stat['border'][2]);
    $pdf->SetLineWidth(0.3);
    $pdf->RoundedRect($x, $boxY, $boxW, $boxH, 2, '1111', 'DF');

    // Label
    $pdf->SetFont('helvetica', 'B', 6.5);
    $pdf->SetTextColor($stat['vcolor'][0], $stat['vcolor'][1], $stat['vcolor'][2]);
    $pdf->SetXY($x + 2, $boxY + 3);
    $pdf->Cell($boxW - 4, 4, $stat['label'], 0, 0, 'C');

    // Value
    $isLong = strlen($stat['value']) > 10;
    $pdf->SetFont('helvetica', 'B', $isLong ? 8 : 15);
    $pdf->SetXY($x + 2, $boxY + 8);
    $pdf->Cell($boxW - 4, 8, $stat['value'], 0, 0, 'C');
}

// ============================================================
// TABLE
// ============================================================
$tableTop = $statTop + $boxH + 4;
$pdf->SetY($tableTop);

// Column widths — total = pageW - 20 margins = 277mm
$cols = [
    'ID'         => 12,
    'User'       => 42,
    'Action'     => 88,
    'IP Address' => 32,
    'Suspicious' => 23,
    'Timestamp'  => 38,
    // Flagged reason is rendered as sub-line inside Action cell
];

// When showing deleted entries, add a Deleted column
if ($exportScope === 'all') {
    $cols['Deleted'] = 20;
}

// Remaining space filler — adjust Action to fill exactly
$usedW = array_sum($cols);
$cols['Action'] += (277 - $usedW); // absorb any rounding

// ---- Table header row ----
$pdf->SetFillColor(30, 64, 175);
$pdf->SetTextColor(255, 255, 255);
$pdf->SetFont('helvetica', 'B', 8);
$pdf->SetDrawColor(255, 255, 255);
$pdf->SetLineWidth(0.3);

foreach ($cols as $label => $w) {
    $pdf->Cell($w, 8, $label, 1, 0, 'C', true);
}
$pdf->Ln();

// ---- Data rows ----
$pdf->SetLineWidth(0.2);
$rowIndex = 0;

if (empty($logs)) {
    $pdf->SetFillColor(255, 255, 255);
    $pdf->SetTextColor(148, 163, 184);
    $pdf->SetFont('helvetica', 'I', 9);
    $pdf->Cell(array_sum($cols), 12, 'No log entries found for the selected filters.', 1, 1, 'C', true);
} else {
    foreach ($logs as $log) {
        $isSuspicious = (bool)$log['is_suspicious'];
        $isDeleted    = !empty($log['deleted_at']);
        $flaggedText  = $log['flagged_reason'] ? $log['flagged_reason'] : '';

        // Estimate row height based on action text length
        $approxLines = max(1, ceil($pdf->GetStringWidth($log['action']) / ($cols['Action'] - 6)));
        $lineH       = 5;
        $rowH        = max(10, $approxLines * $lineH + ($flaggedText ? 5 : 0));

        // Page break check with header repeat
        if ($pdf->GetY() + $rowH > ($pdf->getPageHeight() - 18)) {
            $pdf->AddPage();
            $pdf->SetFillColor(30, 64, 175);
            $pdf->SetTextColor(255, 255, 255);
            $pdf->SetFont('helvetica', 'B', 8);
            $pdf->SetDrawColor(255, 255, 255);
            foreach ($cols as $label => $w) {
                $pdf->Cell($w, 8, $label, 1, 0, 'C', true);
            }
            $pdf->Ln();
        }

        // Row fill color
        // Deleted rows get a faint red tint in 'all' scope
        if ($isDeleted && $exportScope === 'all') {
            $pdf->SetFillColor(254, 242, 242); // very light red for deleted
        } elseif ($isSuspicious) {
            $pdf->SetFillColor(254, 226, 226);
        } elseif ($rowIndex % 2 === 0) {
            $pdf->SetFillColor(255, 255, 255);
        } else {
            $pdf->SetFillColor(248, 250, 252);
        }

        $pdf->SetDrawColor(226, 232, 240);
        $rowY  = $pdf->GetY();
        $baseX = 10;

        // -- ID --
        $pdf->SetXY($baseX, $rowY);
        $pdf->SetTextColor(148, 163, 184);
        $pdf->SetFont('helvetica', '', 7);
        $pdf->MultiCell($cols['ID'], $rowH, '#' . $log['log_id'], 1, 'C', true, 0);

        // -- User: name + email --
        $halfH = $rowH / 2;
        $nameColor = $isDeleted ? [148, 163, 184] : [30, 41, 59];
        $pdf->SetXY($baseX + $cols['ID'], $rowY);
        $pdf->SetFont('helvetica', 'B', 7.5);
        $pdf->SetTextColor($nameColor[0], $nameColor[1], $nameColor[2]);
        $pdf->MultiCell($cols['User'], $halfH, $log['user_name'] ?? 'Unknown', 'LTR', 'L', true, 0);
        $pdf->SetXY($baseX + $cols['ID'], $rowY + $halfH);
        $pdf->SetFont('helvetica', '', 6.5);
        $pdf->SetTextColor(100, 116, 139);
        $pdf->MultiCell($cols['User'], $halfH, $log['user_email'] ?? '', 'LBR', 'L', true, 0);

        // -- Action + optional flagged sub-line --
        $actionX    = $baseX + $cols['ID'] + $cols['User'];
        $actionColor = $isDeleted ? [148, 163, 184] : [30, 41, 59];
        if ($flaggedText) {
            $mainH = $rowH * 0.60;
            $subH  = $rowH * 0.40;
            $pdf->SetXY($actionX, $rowY);
            $pdf->SetFont('helvetica', '', 7.5);
            $pdf->SetTextColor($actionColor[0], $actionColor[1], $actionColor[2]);
            $pdf->MultiCell($cols['Action'], $mainH, $log['action'], 'LTR', 'L', true, 0);
            $pdf->SetXY($actionX, $rowY + $mainH);
            $pdf->SetFont('helvetica', 'I', 6.5);
            $pdf->SetTextColor(153, 27, 27);
            $pdf->MultiCell($cols['Action'], $subH, chr(0xE2).chr(0x9A).chr(0x91) . ' ' . $flaggedText, 'LBR', 'L', true, 0);
        } else {
            $pdf->SetXY($actionX, $rowY);
            $pdf->SetFont('helvetica', '', 7.5);
            $pdf->SetTextColor($actionColor[0], $actionColor[1], $actionColor[2]);
            $pdf->MultiCell($cols['Action'], $rowH, $log['action'], 1, 'L', true, 0);
        }

        // -- IP Address --
        $ipX = $actionX + $cols['Action'];
        $pdf->SetXY($ipX, $rowY);
        $pdf->SetFont('helvetica', '', 7);
        $pdf->SetTextColor(100, 116, 139);
        $pdf->MultiCell($cols['IP Address'], $rowH, $log['ip_address'] ?? '—', 1, 'C', true, 0);

        // -- Suspicious badge --
        $suspX = $ipX + $cols['IP Address'];
        $pdf->SetXY($suspX, $rowY);
        if ($isSuspicious) {
            $pdf->SetFont('helvetica', 'B', 7.5);
            $pdf->SetTextColor(153, 27, 27);
            $pdf->MultiCell($cols['Suspicious'], $rowH, '! YES', 1, 'C', true, 0);
        } else {
            $pdf->SetFont('helvetica', '', 7.5);
            $pdf->SetTextColor(22, 101, 52);
            $pdf->MultiCell($cols['Suspicious'], $rowH, 'Clean', 1, 'C', true, 0);
        }

        // -- Timestamp (date + time stacked) --
        $tsX = $suspX + $cols['Suspicious'];
        $pdf->SetXY($tsX, $rowY);
        $pdf->SetFont('helvetica', 'B', 7);
        $pdf->SetTextColor(30, 41, 59);
        $pdf->MultiCell($cols['Timestamp'], $rowH / 2, date('M j, Y', strtotime($log['timestamp'])), 'LTR', 'C', true, 0);
        $pdf->SetXY($tsX, $rowY + $rowH / 2);
        $pdf->SetFont('helvetica', '', 7);
        $pdf->SetTextColor(100, 116, 139);
        $pdf->MultiCell($cols['Timestamp'], $rowH / 2, date('H:i:s', strtotime($log['timestamp'])), 'LBR', 'C', true, 0);

        // -- Deleted column (only in 'all' scope) --
        if ($exportScope === 'all') {
            $delX = $tsX + $cols['Timestamp'];
            $pdf->SetXY($delX, $rowY);
            if ($isDeleted) {
                $pdf->SetFont('helvetica', 'B', 6.5);
                $pdf->SetTextColor(127, 29, 29);
                $pdf->MultiCell($cols['Deleted'], $rowH, 'DELETED', 1, 'C', true, 0);
            } else {
                $pdf->SetFont('helvetica', '', 6.5);
                $pdf->SetTextColor(22, 101, 52);
                $pdf->MultiCell($cols['Deleted'], $rowH, 'Active', 1, 'C', true, 0);
            }
        }

        $pdf->SetY($rowY + $rowH);
        $rowIndex++;
    }
}

// ============================================================
// STEP 5 — OUTPUT PDF AS DOWNLOAD
// ============================================================
$conn->close();
$pdf->Output($filename, 'D');
exit;