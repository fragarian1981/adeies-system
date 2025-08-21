<?php
/**
 * ========================================================================
 * PENDING-REQUESTS.PHP - ΚΑΡΤΕΛΑ 3: ΕΚΚΡΕΜΕΙΣ ΑΙΤΗΣΕΙΣ (MANAGER VIEW)
 * ========================================================================
 * 
 * ΣΚΟΠΟΣ:
 * Προβολή και διαχείριση εκκρεμών αιτήσεων άδειας από προϊσταμένους/administrators.
 * Παρέχει δυνατότητες έγκρισης, απόρριψης και bulk operations.
 * 
 * ΔΙΚΑΙΩΜΑΤΑ ΠΡΟΣΒΑΣΗΣ:
 * - Μόνο χρήστες με ΠΡΟΙΣΤΑΜΕΝΟΣ = 1 ή ADMINISTRATOR = 1
 * - Προϊστάμενοι βλέπουν μόνο αιτήσεις που τους έχουν ανατεθεί
 * - Administrators βλέπουν όλες τις αιτήσεις
 * 
 * ΚΥΡΙΕΣ ΛΕΙΤΟΥΡΓΙΕΣ:
 * - Προβολή εκκρεμών αιτήσεων με πλήρεις λεπτομέρειες
 * - Έγκριση/Απόρριψη μεμονωμένων αιτήσεων
 * - Bulk operations (πολλαπλές εγκρίσεις/απορρίψεις)
 * - Προσθήκη σχολίων προϊσταμένου
 * - Email notifications στους υπαλλήλους
 * - Filtering και searching
 * - Export σε PDF/Excel
 * - Audit trail logging
 * 
 * DEPENDENCIES:
 * - common.php (authentication, database, email functions)
 * - PHPMailer για email notifications
 * - TCPDF για PDF generation
 * 
 * SECURITY FEATURES:
 * - Role-based access control (RBAC)
 * - SQL injection protection
 * - XSS protection
 * - CSRF protection με tokens
 * - Input validation και sanitization
 * 
 * AUTHOR: Leave Management System Team
 * DATE: 2025
 * VERSION: 2.0
 * LAST MODIFIED: Current Date
 * ========================================================================
 */

// Εισαγωγή βασικών συναρτήσεων και security checks
require_once 'common.php';
checkAuth(); // Βασικός έλεγχος authentication

// ========================================================================
// AUTHORIZATION CHECK - ΕΛΕΓΧΟΣ ΔΙΚΑΙΩΜΑΤΩΝ ΠΡΟΣΒΑΣΗΣ
// ========================================================================

/**
 * Έλεγχος αν ο συνδεδεμένος χρήστης έχει δικαιώματα προϊσταμένου ή administrator
 * 
 * BUSINESS LOGIC:
 * - ADMINISTRATOR = 1: Βλέπει όλες τις αιτήσεις (superuser)
 * - ΠΡΟΙΣΤΑΜΕΝΟΣ = 1: Βλέπει μόνο αιτήσεις που του έχουν ανατεθεί
 * - Άλλοι χρήστες: Redirect στην αρχική με error message
 */
$user_mitroo = $_SESSION['user_mitroo'];
$user_role_check = $pdo->prepare("SELECT ΠΡΟΙΣΤΑΜΕΝΟΣ, ADMINISTRATOR, ΟΝΟΜΑ, ΕΠΩΝΥΜΟ FROM users WHERE ΜΗΤΡΩΟ = ?");
$user_role_check->execute([$user_mitroo]);
$user_data = $user_role_check->fetch();

// Security: Block access if user is not manager or admin
if (!$user_data || ($user_data['ΠΡΟΙΣΤΑΜΕΝΟΣ'] != 1 && $user_data['ADMINISTRATOR'] != 1)) {
    $_SESSION['error'] = "❌ Δεν έχετε δικαιώματα πρόσβασης σε αυτή τη σελίδα.";
    header("Location: index.php");
    exit;
}

// Καθορισμός επιπέδου πρόσβασης
$is_admin = ($user_data['ADMINISTRATOR'] == 1);
$is_manager = ($user_data['ΠΡΟΙΣΤΑΜΕΝΟΣ'] == 1);

// ========================================================================
// ΑΡΧΙΚΟΠΟΙΗΣΗ ΜΕΤΑΒΛΗΤΩΝ ΚΑΙ ΠΑΡΑΜΕΤΡΩΝ
// ========================================================================

// Messages για user feedback
$success = '';
$error = '';
$info = '';

// Φίλτρα και pagination parameters
$filter_department = $_GET['department'] ?? 'ALL';      // Φίλτρο τμήματος
$filter_leave_type = $_GET['leave_type'] ?? 'ALL';      // Φίλτρο τύπου άδειας  
$filter_priority = $_GET['priority'] ?? 'ALL';          // Φίλτρο προτεραιότητας
$filter_date_from = $_GET['date_from'] ?? '';           // Φίλτρο ημερομηνίας από
$filter_date_to = $_GET['date_to'] ?? '';               // Φίλτρο ημερομηνίας έως
$sort_by = $_GET['sort'] ?? 'submitted_at';             // Πεδίο ταξινόμησης
$sort_order = $_GET['order'] ?? 'ASC';                  // Κατεύθυνση ταξινόμησης
$page = max(1, (int)($_GET['page'] ?? 1));              // Τρέχουσα σελίδα
$per_page = 15;                                         // Αιτήσεις ανά σελίδα

// Υπολογισμός offset για SQL pagination
$offset = ($page - 1) * $per_page;

// CSRF Protection - δημιουργία token για forms
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ========================================================================
// ΧΕΙΡΙΣΜΟΣ POST REQUESTS - ACTIONS ΚΑΙ FORM SUBMISSIONS
// ========================================================================

if ($_POST) {
    // CSRF Protection validation
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "❌ Μη έγκυρο security token. Παρακαλώ δοκιμάστε ξανά.";
    } else {
        $action = $_POST['action'] ?? '';
        
        switch ($action) {
            
            case 'approve_request':
                /**
                 * ================================================================
                 * ΕΓΚΡΙΣΗ ΜΕΜΟΝΩΜΕΝΗΣ ΑΙΤΗΣΗΣ
                 * ================================================================
                 * 
                 * ΔΙΑΔΙΚΑΣΙΑ:
                 * 1. Validation request ID και ownership
                 * 2. Έλεγχος υπολοίπων άδειας
                 * 3. Update request status
                 * 4. Αφαίρεση από user balance
                 * 5. Email notification στον υπάλληλο
                 * 6. Audit trail logging
                 * 7. Success/Error feedback
                 */
                
                $request_id = (int)$_POST['request_id'];
                $manager_comments = trim($_POST['manager_comments'] ?? '');
                
                try {
                    // Begin transaction για data consistency
                    $pdo->beginTransaction();
                    
                    // Λήψη στοιχείων αίτησης με user info
                    $request_sql = "
                        SELECT r.*, u.ΟΝΟΜΑ, u.ΕΠΩΝΥΜΟ, u.EMAIL, u.ΤΜΗΜΑ
                        FROM requests r
                        JOIN users u ON r.mitroo = u.ΜΗΤΡΩΟ
                        WHERE r.id = ? AND r.status = 'ΕΚΚΡΕΜΕΙ'
                    ";
                    
                    // Security: Προσθήκη WHERE clause ανάλογα με το role
                    if (!$is_admin) {
                        $request_sql .= " AND r.selected_manager_mitroo = ?";
                        $stmt = $pdo->prepare($request_sql);
                        $stmt->execute([$request_id, $user_mitroo]);
                    } else {
                        $stmt = $pdo->prepare($request_sql);
                        $stmt->execute([$request_id]);
                    }
                    
                    $request = $stmt->fetch();
                    
                    if (!$request) {
                        throw new Exception("Η αίτηση δεν βρέθηκε ή δεν έχετε δικαίωμα έγκρισης.");
                    }
                    
                    // Έλεγχος υπολοίπων άδειας πριν την έγκριση
                    $balance_check = checkLeaveBalance(
                        $pdo, 
                        $request['mitroo'], 
                        $request['typos'], 
                        $request['meres'], 
                        0, // imeres_poreias - TODO: προσθήκη στη βάση
                        $request['wres']
                    );
                    
                    if (!$balance_check['status']) {
                        throw new Exception("Ο υπάλληλος δεν έχει επαρκές υπόλοιπο: " . $balance_check['message']);
                    }
                    
                    // Update request status σε ΕΓΚΕΚΡΙΜΕΝΗ
                    $update_sql = "
                        UPDATE requests 
                        SET status = 'ΕΓΚΕΚΡΙΜΕΝΗ',
                            approved_by = ?,
                            approved_at = NOW(),
                            manager_comments = ?
                        WHERE id = ?
                    ";
                    $update_stmt = $pdo->prepare($update_sql);
                    $update_stmt->execute([$user_mitroo, $manager_comments, $request_id]);
                    
                    // Αφαίρεση από user balance
                    updateUserBalance($pdo, $request['mitroo'], $request['typos'], $request['meres'], $request['wres']);
                    
                    // Commit transaction
                    $pdo->commit();
                    
                    // Email notification στον υπάλληλο
                    $email_sent = sendApprovalEmail($pdo, $request_id, $manager_comments);
                    
                    // Audit trail logging
                    logManagerAction($pdo, $user_mitroo, 'APPROVE_REQUEST', [
                        'request_id' => $request_id,
                        'employee_mitroo' => $request['mitroo'],
                        'leave_type' => $request['typos'],
                        'days' => $request['meres'],
                        'hours' => $request['wres'],
                        'comments' => $manager_comments
                    ]);
                    
                    // Success message
                    $success = "✅ Η αίτηση εγκρίθηκε επιτυχώς!";
                    if ($email_sent) {
                        $success .= " Στάλθηκε email ειδοποίησης στον υπάλληλο.";
                    }
                    
                } catch (Exception $e) {
                    // Rollback σε περίπτωση σφάλματος
                    $pdo->rollback();
                    $error = "❌ Σφάλμα κατά την έγκριση: " . $e->getMessage();
                    
                    // Error logging
                    error_log("APPROVAL ERROR: " . $e->getMessage() . " - User: $user_mitroo, Request: $request_id");
                }
                break;
                
            case 'reject_request':
                /**
                 * ================================================================
                 * ΑΠΟΡΡΙΨΗ ΜΕΜΟΝΩΜΕΝΗΣ ΑΙΤΗΣΗΣ  
                 * ================================================================
                 * 
                 * ΔΙΑΔΙΚΑΣΙΑ:
                 * 1. Validation request ID και ownership
                 * 2. Έλεγχος υποχρεωτικών σχολίων απόρριψης
                 * 3. Update request status
                 * 4. Email notification με αιτιολογία
                 * 5. Audit trail logging
                 */
                
                $request_id = (int)$_POST['request_id'];
                $rejection_reason = trim($_POST['rejection_reason'] ?? '');
                
                // Validation: Υποχρεωτικά σχόλια για απόρριψη
                if (empty($rejection_reason)) {
                    $error = "❌ Η αιτιολογία απόρριψης είναι υποχρεωτική.";
                    break;
                }
                
                try {
                    $pdo->beginTransaction();
                    
                    // Λήψη στοιχείων αίτησης
                    $request_sql = "
                        SELECT r.*, u.ΟΝΟΜΑ, u.ΕΠΩΝΥΜΟ, u.EMAIL
                        FROM requests r
                        JOIN users u ON r.mitroo = u.ΜΗΤΡΩΟ
                        WHERE r.id = ? AND r.status = 'ΕΚΚΡΕΜΕΙ'
                    ";
                    
                    if (!$is_admin) {
                        $request_sql .= " AND r.selected_manager_mitroo = ?";
                        $stmt = $pdo->prepare($request_sql);
                        $stmt->execute([$request_id, $user_mitroo]);
                    } else {
                        $stmt = $pdo->prepare($request_sql);
                        $stmt->execute([$request_id]);
                    }
                    
                    $request = $stmt->fetch();
                    
                    if (!$request) {
                        throw new Exception("Η αίτηση δεν βρέθηκε ή δεν έχετε δικαίωμα απόρριψης.");
                    }
                    
                    // Update request status σε ΑΠΟΡΡΙΦΘΗΚΕ
                    $update_sql = "
                        UPDATE requests 
                        SET status = 'ΑΠΟΡΡΙΦΘΗΚΕ',
                            rejected_by = ?,
                            rejected_at = NOW(),
                            rejection_reason = ?
                        WHERE id = ?
                    ";
                    $update_stmt = $pdo->prepare($update_sql);
                    $update_stmt->execute([$user_mitroo, $rejection_reason, $request_id]);
                    
                    $pdo->commit();
                    
                    // Email notification
                    $email_sent = sendRejectionEmail($pdo, $request_id, $rejection_reason);
                    
                    // Audit trail
                    logManagerAction($pdo, $user_mitroo, 'REJECT_REQUEST', [
                        'request_id' => $request_id,
                        'employee_mitroo' => $request['mitroo'],
                        'reason' => $rejection_reason
                    ]);
                    
                    $success = "✅ Η αίτηση απορρίφθηκε.";
                    if ($email_sent) {
                        $success .= " Στάλθηκε email ειδοποίησης.";
                    }
                    
                } catch (Exception $e) {
                    $pdo->rollback();
                    $error = "❌ Σφάλμα κατά την απόρριψη: " . $e->getMessage();
                }
                break;
                
            case 'bulk_approve':
                /**
                 * ================================================================
                 * BULK ΕΓΚΡΙΣΗ ΠΟΛΛΑΠΛΩΝ ΑΙΤΗΣΕΩΝ
                 * ================================================================
                 * 
                 * ΕΠΙΧΕΙΡΗΣΙΑΚΗ ΛΟΓΙΚΗ:
                 * - Επεξεργασία πολλαπλών αιτήσεων σε μία transaction
                 * - Έλεγχος υπολοίπων για κάθε αίτηση ξεχωριστά
                 * - Αποτυχία μίας αίτησης δεν επηρεάζει τις άλλες
                 * - Detailed feedback για κάθε αίτηση
                 */
                
                $selected_requests = $_POST['selected_requests'] ?? [];
                $bulk_comments = trim($_POST['bulk_comments'] ?? '');
                
                if (empty($selected_requests)) {
                    $error = "❌ Δεν επιλέχθηκαν αιτήσεις για έγκριση.";
                    break;
                }
                
                $approved_count = 0;
                $failed_requests = [];
                
                foreach ($selected_requests as $request_id) {
                    try {
                        $pdo->beginTransaction();
                        
                        // Λήψη αίτησης με validation
                        $request_sql = "
                            SELECT r.*, u.ΟΝΟΜΑ, u.ΕΠΩΝΥΜΟ, u.EMAIL
                            FROM requests r
                            JOIN users u ON r.mitroo = u.ΜΗΤΡΩΟ
                            WHERE r.id = ? AND r.status = 'ΕΚΚΡΕΜΕΙ'
                        ";
                        
                        if (!$is_admin) {
                            $request_sql .= " AND r.selected_manager_mitroo = ?";
                            $stmt = $pdo->prepare($request_sql);
                            $stmt->execute([$request_id, $user_mitroo]);
                        } else {
                            $stmt = $pdo->prepare($request_sql);
                            $stmt->execute([$request_id]);
                        }
                        
                        $request = $stmt->fetch();
                        
                        if (!$request) {
                            throw new Exception("Αίτηση #$request_id δεν βρέθηκε");
                        }
                        
                        // Balance check
                        $balance_check = checkLeaveBalance(
                            $pdo, 
                            $request['mitroo'], 
                            $request['typos'], 
                            $request['meres'], 
                            0, 
                            $request['wres']
                        );
                        
                        if (!$balance_check['status']) {
                            throw new Exception("Ανεπαρκές υπόλοιπο για " . $request['ΟΝΟΜΑ'] . " " . $request['ΕΠΩΝΥΜΟ']);
                        }
                        
                        // Approve request
                        $update_sql = "
                            UPDATE requests 
                            SET status = 'ΕΓΚΕΚΡΙΜΕΝΗ',
                                approved_by = ?,
                                approved_at = NOW(),
                                manager_comments = ?
                            WHERE id = ?
                        ";
                        $update_stmt = $pdo->prepare($update_sql);
                        $update_stmt->execute([$user_mitroo, $bulk_comments, $request_id]);
                        
                        // Update balance
                        updateUserBalance($pdo, $request['mitroo'], $request['typos'], $request['meres'], $request['wres']);
                        
                        $pdo->commit();
                        $approved_count++;
                        
                        // Send individual email
                        sendApprovalEmail($pdo, $request_id, $bulk_comments);
                        
                    } catch (Exception $e) {
                        $pdo->rollback();
                        $failed_requests[] = "Αίτηση #$request_id: " . $e->getMessage();
                    }
                }
                
                // Bulk operation feedback
                if ($approved_count > 0) {
                    $success = "✅ Εγκρίθηκαν $approved_count αιτήσεις επιτυχώς.";
                }
                
                if (!empty($failed_requests)) {
                    $error = "❌ Αποτυχίες:\n" . implode("\n", $failed_requests);
                }
                
                // Audit trail για bulk operation
                logManagerAction($pdo, $user_mitroo, 'BULK_APPROVE', [
                    'approved_count' => $approved_count,
                    'failed_count' => count($failed_requests),
                    'requests' => $selected_requests
                ]);
                
                break;
                
            case 'bulk_reject':
                /**
                 * ================================================================
                 * BULK ΑΠΟΡΡΙΨΗ ΠΟΛΛΑΠΛΩΝ ΑΙΤΗΣΕΩΝ
                 * ================================================================
                 */
                
                $selected_requests = $_POST['selected_requests'] ?? [];
                $bulk_rejection_reason = trim($_POST['bulk_rejection_reason'] ?? '');
                
                if (empty($selected_requests)) {
                    $error = "❌ Δεν επιλέχθηκαν αιτήσεις για απόρριψη.";
                    break;
                }
                
                if (empty($bulk_rejection_reason)) {
                    $error = "❌ Η αιτιολογία bulk απόρριψης είναι υποχρεωτική.";
                    break;
                }
                
                $rejected_count = 0;
                
                foreach ($selected_requests as $request_id) {
                    try {
                        $pdo->beginTransaction();
                        
                        $update_sql = "
                            UPDATE requests 
                            SET status = 'ΑΠΟΡΡΙΦΘΗΚΕ',
                                rejected_by = ?,
                                rejected_at = NOW(),
                                rejection_reason = ?
                            WHERE id = ? AND status = 'ΕΚΚΡΕΜΕΙ'
                        ";
                        
                        if (!$is_admin) {
                            $update_sql .= " AND selected_manager_mitroo = ?";
                            $stmt = $pdo->prepare($update_sql);
                            $stmt->execute([$user_mitroo, $bulk_rejection_reason, $request_id, $user_mitroo]);
                        } else {
                            $stmt = $pdo->prepare($update_sql);
                            $stmt->execute([$user_mitroo, $bulk_rejection_reason, $request_id]);
                        }
                        
                        if ($stmt->rowCount() > 0) {
                            $pdo->commit();
                            $rejected_count++;
                            sendRejectionEmail($pdo, $request_id, $bulk_rejection_reason);
                        } else {
                            $pdo->rollback();
                        }
                        
                    } catch (Exception $e) {
                        $pdo->rollback();
                    }
                }
                
                $success = "✅ Απορρίφθηκαν $rejected_count αιτήσεις.";
                break;
        }
    }
}

// ========================================================================
// ΚΑΤΑΣΚΕΥΗ ΚΥΡΙΟΥ SQL QUERY ΜΕ ΦΙΛΤΡΑ
// ========================================================================

/**
 * Δημιουργία dynamic SQL query με βάση τα φίλτρα και το role του χρήστη
 * 
 * SECURITY CONSIDERATIONS:
 * - Prepared statements για όλες τις παραμέτρους
 * - Role-based filtering (manager vs admin)
 * - Input validation για sort fields
 * - Escape clauses για LIKE queries
 */

// Βασικό SQL με JOINs για user και department info
$sql = "
    SELECT 
        r.*,
        u.ΟΝΟΜΑ, u.ΕΠΩΝΥΜΟ, u.EMAIL, u.ΤΜΗΜΑ,
        m.ΟΝΟΜΑ as manager_name, m.ΕΠΩΝΥΜΟ as manager_surname,
        DATEDIFF(r.imerominia, CURDATE()) as days_until_leave
    FROM requests r
    JOIN users u ON r.mitroo = u.ΜΗΤΡΩΟ
    LEFT JOIN users m ON r.selected_manager_mitroo = m.ΜΗΤΡΩΟ
    WHERE r.status = 'ΕΚΚΡΕΜΕΙ'
";

// Parameters array για prepared statement
$params = [];

// Role-based access control
if (!$is_admin) {
    // Managers βλέπουν μόνο αιτήσεις που τους έχουν ανατεθεί
    $sql .= " AND r.selected_manager_mitroo = ?";
    $params[] = $user_mitroo;
}

// Department filter
if ($filter_department !== 'ALL') {
    $sql .= " AND u.ΤΜΗΜΑ = ?";
    $params[] = $filter_department;
}

// Leave type filter
if ($filter_leave_type !== 'ALL') {
    $sql .= " AND r.typos = ?";
    $params[] = $filter_leave_type;
}

// Priority filter (υπολογίζεται βάσει ημερομηνίας άδειας)
if ($filter_priority !== 'ALL') {
    switch ($filter_priority) {
        case 'URGENT':
            // Άδειες που ξεκινούν σε 3 ημέρες ή λιγότερο
            $sql .= " AND DATEDIFF(r.imerominia, CURDATE()) <= 3";
            break;
        case 'NORMAL':
            // Άδειες που ξεκινούν σε 4-14 ημέρες
            $sql .= " AND DATEDIFF(r.imerominia, CURDATE()) BETWEEN 4 AND 14";
            break;
        case 'LOW':
            // Άδειες που ξεκινούν σε περισσότερες από 14 ημέρες
            $sql .= " AND DATEDIFF(r.imerominia, CURDATE()) > 14";
            break;
    }
}

// Date range filters
if (!empty($filter_date_from)) {
    $sql .= " AND r.imerominia >= ?";
    $params[] = $filter_date_from;
}

if (!empty($filter_date_to)) {
    $sql .= " AND r.imerominia <= ?";
    $params[] = $filter_date_to;
}

// Sorting validation και construction
$allowed_sort_fields = [
    'submitted_at' => 'r.submitted_at',
    'imerominia' => 'r.imerominia', 
    'typos' => 'r.typos',
    'employee_name' => 'u.ΕΠΩΝΥΜΟ',
    'department' => 'u.ΤΜΗΜΑ',
    'days_until' => 'days_until_leave',
    'meres' => 'r.meres'
];

$sort_field = $allowed_sort_fields[$sort_by] ?? 'r.submitted_at';
$sort_direction = strtoupper($sort_order) === 'DESC' ? 'DESC' : 'ASC';

$sql .= " ORDER BY $sort_field $sort_direction";

// ========================================================================
// PAGINATION CALCULATIONS
// ========================================================================

// Count query για total results
$count_sql = preg_replace('/SELECT.*?FROM/s', 'SELECT COUNT(*) FROM', $sql);
$count_sql = preg_replace('/ORDER BY.*$/', '', $count_sql);

$count_stmt = $pdo->prepare($count_sql);
$count_stmt->execute($params);
$total_requests = $count_stmt->fetchColumn();

$total_pages = ceil($total_requests / $per_page);

// Add LIMIT για pagination
$sql .= " LIMIT $per_page OFFSET $offset";

// ========================================================================
// ΕΚΤΕΛΕΣΗ ΚΥΡΙΟΥ QUERY
// ========================================================================

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$requests = $stmt->fetchAll();

// ========================================================================
// ΣΥΛΛΟΓΗ ΣΤΑΤΙΣΤΙΚΩΝ ΚΑΙ METADATA
// ========================================================================

/**
 * Στατιστικά για dashboard και quick insights
 */

// Στατιστικά εκκρεμών αιτήσεων
$stats_sql = "
    SELECT 
        COUNT(*) as total_pending,
        COUNT(CASE WHEN DATEDIFF(r.imerominia, CURDATE()) <= 3 THEN 1 END) as urgent,
        COUNT(CASE WHEN DATEDIFF(r.imerominia, CURDATE()) BETWEEN 4 AND 14 THEN 1 END) as normal,
        COUNT(CASE WHEN DATEDIFF(r.imerominia, CURDATE()) > 14 THEN 1 END) as low_priority,
        COUNT(CASE WHEN r.typos = 'ΚΑΝΟΝΙΚΗ' THEN 1 END) as regular_leaves,
        COUNT(CASE WHEN r.typos = 'ΟΛΙΓΟΩΡΗ' THEN 1 END) as hourly_leaves,
        AVG(DATEDIFF(r.imerominia, r.submitted_at)) as avg_notice_days
    FROM requests r
    JOIN users u ON r.mitroo = u.ΜΗΤΡΩΟ
    WHERE r.status = 'ΕΚΚΡΕΜΕΙ'
";

if (!$is_admin) {
    $stats_sql .= " AND r.selected_manager_mitroo = ?";
    $stats_stmt = $pdo->prepare($stats_sql);
    $stats_stmt->execute([$user_mitroo]);
} else {
    $stats_stmt = $pdo->prepare($stats_sql);
    $stats_stmt->execute();
}

$stats = $stats_stmt->fetch();

// Departments list για filter dropdown
$departments_sql = "
    SELECT DISTINCT u.ΤΜΗΜΑ
    FROM requests r
    JOIN users u ON r.mitroo = u.ΜΗΤΡΩΟ
    WHERE r.status = 'ΕΚΚΡΕΜΕΙ'
";

if (!$is_admin) {
    $departments_sql .= " AND r.selected_manager_mitroo = ?";
    $dept_stmt = $pdo->prepare($departments_sql);
    $dept_stmt->execute([$user_mitroo]);
} else {
    $dept_stmt = $pdo->prepare($departments_sql);
    $dept_stmt->execute();
}

$departments = $dept_stmt->fetchAll(PDO::FETCH_COLUMN);

// Leave types για filter
$leave_types_sql = "
    SELECT DISTINCT r.typos
    FROM requests r
    WHERE r.status = 'ΕΚΚΡΕΜΕΙ'
";

if (!$is_admin) {
    $leave_types_sql .= " AND r.selected_manager_mitroo = ?";
    $types_stmt = $pdo->prepare($leave_types_sql);
    $types_stmt->execute([$user_mitroo]);
} else {
    $types_stmt = $pdo->prepare($leave_types_sql);
    $types_stmt->execute();
}

$leave_types = $types_stmt->fetchAll(PDO::FETCH_COLUMN);

// ========================================================================
// HELPER FUNCTIONS ΓΙΑ UI FORMATTING
// ========================================================================

/**
 * Υπολογισμός προτεραιότητας αίτησης βάσει ημερομηνίας
 * 
 * @param int $days_until Ημέρες μέχρι την άδεια
 * @return array [priority_level, css_class, emoji]
 */
function calculatePriority($days_until) {
    if ($days_until <= 0) {
        return ['OVERDUE', 'priority-overdue', '🚨'];
    } elseif ($days_until <= 3) {
        return ['URGENT', 'priority-urgent', '⚡'];
    } elseif ($days_until <= 14) {
        return ['NORMAL', 'priority-normal', '📅'];
    } else {
        return ['LOW', 'priority-low', '🕐'];
    }
}

/**
 * Μορφοποίηση τύπου άδειας για εμφάνιση
 */
function formatLeaveTypeDisplay($type) {
    $types = [
        'ΚΑΝΟΝΙΚΗ' => ['name' => 'Κανονική Άδεια', 'emoji' => '🏖️'],
        'ΒΡΑΧΕΙΑ' => ['name' => 'Βραχεία Άδεια', 'emoji' => '📅'],
        'ΟΛΙΓΟΩΡΗ' => ['name' => 'Ολιγόωρη Άδεια', 'emoji' => '⏰'],
        'ΑΝΑΡΡΩΤΙΚΗ' => ['name' => 'Αναρρωτική', 'emoji' => '🏥'],
        'ΕΞΕΤΑΣΕΩΝ' => ['name' => 'Εξετάσεων', 'emoji' => '📚'],
        'ΜΗΤΡΟΤΗΤΑΣ' => ['name' => 'Μητρότητας', 'emoji' => '👶'],
        'ΓΑΜΟΣ' => ['name' => 'Γάμου', 'emoji' => '💒'],
        'ΠΕΝΘΟΣ' => ['name' => 'Πένθους', 'emoji' => '🕊️']
    ];
    
    return $types[$type] ?? ['name' => $type, 'emoji' => '📋'];
}

/**
 * Υπολογισμός business days μεταξύ δύο ημερομηνιών
 */
function calculateBusinessDays($start_date, $end_date) {
    $start = new DateTime($start_date);
    $end = new DateTime($end_date);
    $interval = new DateInterval('P1D');
    $daterange = new DatePeriod($start, $interval, $end);
    
    $business_days = 0;
    foreach($daterange as $date){
        // Skip weekends (Saturday = 6, Sunday = 0)
        if($date->format('w') != 0 && $date->format('w') != 6) {
            $business_days++;
        }
    }
    
    return $business_days;
}

// ========================================================================
// GENERAR CSRF TOKEN ΓΙΑ FORMS
// ========================================================================
$csrf_token = $_SESSION['csrf_token'];

?>

<!DOCTYPE html>
<html lang="el">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Εκκρεμείς Αιτήσεις - Σύστημα Αδειών</title>
    
    <!-- ========================================================================
         CSS STYLES - ADVANCED MANAGEMENT INTERFACE
         ======================================================================== -->
    <style>
        /* === ΒΑΣΙΚΕΣ ΡΥΘΜΙΣΕΙΣ === */
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container { 
            max-width: 1600px; 
            margin: 0 auto; 
            padding: 20px; 
        }
        
        /* === HEADER SECTION === */
        .header {
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
            color: #333;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .header h1 {
            font-size: 2.2rem;
            font-weight: 700;
            color: #667eea;
        }
        
        .header-info {
            text-align: right;
            font-size: 0.9rem;
            color: #666;
        }
        
        .manager-badge {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* === STATISTICS DASHBOARD === */
        .stats-dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border-top: 4px solid;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.15);
        }
        
        .stat-card.total { border-top-color: #17a2b8; }
        .stat-card.urgent { border-top-color: #dc3545; }
        .stat-card.normal { border-top-color: #ffc107; }
        .stat-card.low { border-top-color: #28a745; }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 8px;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .stat-description {
            font-size: 0.8rem;
            color: #888;
            margin-top: 5px;
        }
        
        /* === FILTERS AND ACTIONS BAR === */
        .controls-section {
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .filters-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .filter-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
            font-size: 0.9rem;
        }
        
        .filter-group select,
        .filter-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
            background: white;
        }
        
        .filter-group select:focus,
        .filter-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .actions-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
        }
        
        .bulk-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        /* === MAIN CONTENT TABLE === */
        .content-section {
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .requests-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .requests-table th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        .requests-table td {
            padding: 15px 12px;
            border-bottom: 1px solid #f1f3f4;
            vertical-align: middle;
        }
        
        .requests-table tr:hover {
            background-color: rgba(102, 126, 234, 0.05);
        }
        
        /* === PRIORITY INDICATORS === */
        .priority-indicator {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 8px;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .priority-overdue { background: #dc3545; color: white; }
        .priority-urgent { background: #fd7e14; color: white; }
        .priority-normal { background: #ffc107; color: #212529; }
        .priority-low { background: #28a745; color: white; }
        
        /* === EMPLOYEE INFO DISPLAY === */
        .employee-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .employee-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(45deg, #667eea, #764ba2);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.9rem;
        }
        
        .employee-details strong {
            display: block;
            color: #333;
        }
        
        .employee-details small {
            color: #666;
            font-size: 0.8rem;
        }
        
        /* === LEAVE TYPE BADGES === */
        .leave-type-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
        }
        
        /* === ACTION BUTTONS === */
        .action-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            text-align: center;
        }
        
        .btn-sm { padding: 6px 12px; font-size: 0.75rem; }
        .btn-xs { padding: 4px 8px; font-size: 0.7rem; }
        
        .btn-success { background: #28a745; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-info { background: #17a2b8; color: white; }
        .btn-warning { background: #ffc107; color: #212529; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-primary { background: #007bff; color: white; }
        
        .btn:hover { 
            transform: translateY(-1px); 
            box-shadow: 0 4px 8px rgba(0,0,0,0.15); 
            filter: brightness(110%);
        }
        
        /* === BULK SELECTION === */
        .bulk-checkbox {
            width: 18px;
            height: 18px;
            accent-color: #667eea;
        }
        
        .bulk-selected {
            background-color: rgba(102, 126, 234, 0.1) !important;
        }
        
        /* === MODALS === */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            backdrop-filter: blur(5px);
        }
        
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 30px;
            border-radius: 12px;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .modal-header {
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .modal-header h3 {
            color: #333;
            margin-bottom: 5px;
        }
        
        .modal-body textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            resize: vertical;
            min-height: 100px;
            font-family: inherit;
        }
        
        .modal-footer {
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #e9ecef;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        
        /* === PAGINATION === */
        .pagination-container {
            padding: 20px;
            border-top: 1px solid #f1f3f4;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(248,249,250,0.5);
        }
        
        .pagination {
            display: flex;
            gap: 5px;
        }
        
        .pagination a, .pagination span {
            padding: 10px 15px;
            border: 1px solid #dee2e6;
            color: #495057;
            text-decoration: none;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .pagination a:hover {
            background: #e9ecef;
            transform: translateY(-1px);
        }
        
        .pagination .current {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-color: #667eea;
        }
        
        /* === ALERTS === */
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid;
            display: flex;
            align-items: center;
            gap: 10px;
            backdrop-filter: blur(10px);
        }
        
        .alert-success {
            background: rgba(212, 237, 218, 0.9);
            color: #155724;
            border-left-color: #28a745;
        }
        
        .alert-danger {
            background: rgba(248, 215, 218, 0.9);
            color: #721c24;
            border-left-color: #dc3545;
        }
        
        .alert-info {
            background: rgba(209, 236, 241, 0.9);
            color: #0c5460;
            border-left-color: #17a2b8;
        }
        
        /* === RESPONSIVE DESIGN === */
        @media (max-width: 1200px) {
            .container { padding: 15px; }
            .stats-dashboard { grid-template-columns: repeat(2, 1fr); }
            .filters-row { grid-template-columns: 1fr 1fr; }
        }
        
        @media (max-width: 768px) {
            .header h1 { font-size: 1.8rem; }
            .header-content { flex-direction: column; text-align: center; }
            .stats-dashboard { grid-template-columns: 1fr; }
            .filters-row { grid-template-columns: 1fr; }
            .actions-bar { flex-direction: column; align-items: stretch; }
            
            .requests-table {
                font-size: 0.8rem;
            }
            
            .requests-table th,
            .requests-table td {
                padding: 10px 8px;
            }
            
            .action-buttons {
                flex-direction: column;
            }
            
            .btn {
                justify-content: center;
                width: 100%;
            }
        }
        
        /* === LOADING STATES === */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255,255,255,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            backdrop-filter: blur(5px);
        }
        
        /* === TOOLTIPS === */
        .tooltip {
            position: relative;
            cursor: help;
        }
        
        .tooltip:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            white-space: nowrap;
            z-index: 1000;
        }
        
        /* === BACK BUTTON === */
        .back-btn {
            background: rgba(255,255,255,0.9);
            color: #667eea;
            padding: 12px 20px;
            border: 2px solid #667eea;
            border-radius: 8px;
            text-decoration: none;
            margin-bottom: 20px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .back-btn:hover {
            background: #667eea;
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- ========================================================================
             HEADER SECTION - ΤΙΤΛΟΣ ΚΑΙ MANAGER INFO
             ======================================================================== -->
        <div class="header">
            <div class="header-content">
                <div>
                    <h1>📋 Εκκρεμείς Αιτήσεις Άδειας</h1>
                    <p>Διαχείριση και έγκριση αιτήσεων άδειας υπαλλήλων</p>
                </div>
                <div class="header-info">
                    <div class="manager-badge">
                        <?php echo $is_admin ? '👑 Administrator' : '👤 Προϊστάμενος'; ?>
                    </div>
                    <div style="margin-top: 8px;">
                        <strong><?php echo htmlspecialchars($user_data['ΟΝΟΜΑ'] . ' ' . $user_data['ΕΠΩΝΥΜΟ']); ?></strong><br>
                        <small>Μητρώο: <?php echo htmlspecialchars($user_mitroo); ?></small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Κουμπί επιστροφής -->
        <a href="index.php" class="back-btn">
            ← Επιστροφή στην Αρχική
        </a>

        <!-- ========================================================================
             MESSAGES SECTION - ΕΜΦΑΝΙΣΗ FEEDBACK ΜΗΝΥΜΑΤΩΝ
             ======================================================================== -->
        <?php if ($success): ?>
            <div class="alert alert-success">
                ✅ <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="alert alert-danger">
                ❌ <?php echo nl2br(htmlspecialchars($error)); ?>
            </div>
        <?php endif; ?>

        <?php if ($info): ?>
            <div class="alert alert-info">
                ℹ️ <?php echo htmlspecialchars($info); ?>
            </div>
        <?php endif; ?>

        <!-- ========================================================================
             STATISTICS DASHBOARD - ΣΤΑΤΙΣΤΙΚΑ ΕΚΚΡΕΜΩΝ ΑΙΤΗΣΕΩΝ  
             ======================================================================== -->
        <div class="stats-dashboard">
            <div class="stat-card total">
                <div class="stat-number" style="color: #17a2b8;">
                    <?php echo $stats['total_pending'] ?? 0; ?>
                </div>
                <div class="stat-label">Συνολικές Εκκρεμείς</div>
                <div class="stat-description">
                    Μέσος χρόνος προειδοποίησης: <?php echo round($stats['avg_notice_days'] ?? 0); ?> ημέρες
                </div>
            </div>

            <div class="stat-card urgent">
                <div class="stat-number" style="color: #dc3545;">
                    <?php echo $stats['urgent'] ?? 0; ?>
                </div>
                <div class="stat-label">Επείγουσες</div>
                <div class="stat-description">
                    Άδειες που ξεκινούν σε ≤3 ημέρες
                </div>
            </div>

            <div class="stat-card normal">
                <div class="stat-number" style="color: #ffc107;">
                    <?php echo $stats['normal'] ?? 0; ?>
                </div>
                <div class="stat-label">Κανονικές</div>
                <div class="stat-description">
                    Άδειες που ξεκινούν σε 4-14 ημέρες
                </div>
            </div>

            <div class="stat-card low">
                <div class="stat-number" style="color: #28a745;">
                    <?php echo $stats['low_priority'] ?? 0; ?>
                </div>
                <div class="stat-label">Χαμηλή Προτεραιότητα</div>
                <div class="stat-description">
                    Άδειες που ξεκινούν σε >14 ημέρες
                </div>
            </div>
        </div>

        <!-- ========================================================================
             FILTERS AND CONTROLS SECTION - ΦΙΛΤΡΑ ΚΑΙ BULK ACTIONS
             ======================================================================== -->
        <div class="controls-section">
            <form method="GET" id="filters-form">
                <div class="filters-row">
                    <!-- Department Filter -->
                    <div class="filter-group">
                        <label for="department">🏢 Τμήμα:</label>
                        <select name="department" id="department" onchange="applyFilters()">
                            <option value="ALL" <?php echo $filter_department === 'ALL' ? 'selected' : ''; ?>>
                                Όλα τα τμήματα
                            </option>
                            <?php foreach ($departments as $dept): ?>
                                <option value="<?php echo htmlspecialchars($dept); ?>" 
                                        <?php echo $filter_department === $dept ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($dept); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- Leave Type Filter -->
                    <div class="filter-group">
                        <label for="leave_type">📋 Τύπος Άδειας:</label>
                        <select name="leave_type" id="leave_type" onchange="applyFilters()">
                            <option value="ALL" <?php echo $filter_leave_type === 'ALL' ? 'selected' : ''; ?>>
                                Όλοι οι τύποι
                            </option>
                            <?php foreach ($leave_types as $type): ?>
                                <?php $type_info = formatLeaveTypeDisplay($type); ?>
                                <option value="<?php echo htmlspecialchars($type); ?>" 
                                        <?php echo $filter_leave_type === $type ? 'selected' : ''; ?>>
                                    <?php echo $type_info['emoji'] . ' ' . htmlspecialchars($type_info['name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- Priority Filter -->
                    <div class="filter-group">
                        <label for="priority">⚡ Προτεραιότητα:</label>
                        <select name="priority" id="priority" onchange="applyFilters()">
                            <option value="ALL" <?php echo $filter_priority === 'ALL' ? 'selected' : ''; ?>>
                                Όλες οι προτεραιότητες
                            </option>
                            <option value="URGENT" <?php echo $filter_priority === 'URGENT' ? 'selected' : ''; ?>>
                                🚨 Επείγουσες (≤3 ημέρες)
                            </option>
                            <option value="NORMAL" <?php echo $filter_priority === 'NORMAL' ? 'selected' : ''; ?>>
                                📅 Κανονικές (4-14 ημέρες)
                            </option>
                            <option value="LOW" <?php echo $filter_priority === 'LOW' ? 'selected' : ''; ?>>
                                🕐 Χαμηλή (>14 ημέρες)
                            </option>
                        </select>
                    </div>

                    <!-- Date From -->
                    <div class="filter-group">
                        <label for="date_from">📅 Άδεια από:</label>
                        <input type="date" name="date_from" id="date_from" 
                               value="<?php echo htmlspecialchars($filter_date_from); ?>" 
                               onchange="applyFilters()">
                    </div>

                    <!-- Date To -->
                    <div class="filter-group">
                        <label for="date_to">📅 Άδεια έως:</label>
                        <input type="date" name="date_to" id="date_to" 
                               value="<?php echo htmlspecialchars($filter_date_to); ?>" 
                               onchange="applyFilters()">
                    </div>

                    <!-- Sorting -->
                    <div class="filter-group">
                        <label for="sort">📊 Ταξινόμηση:</label>
                        <select name="sort" id="sort" onchange="applyFilters()">
                            <option value="submitted_at" <?php echo $sort_by === 'submitted_at' ? 'selected' : ''; ?>>
                                Ημερομηνία Υποβολής
                            </option>
                            <option value="imerominia" <?php echo $sort_by === 'imerominia' ? 'selected' : ''; ?>>
                                Ημερομηνία Άδειας
                            </option>
                            <option value="days_until" <?php echo $sort_by === 'days_until' ? 'selected' : ''; ?>>
                                Ημέρες μέχρι την άδεια
                            </option>
                            <option value="employee_name" <?php echo $sort_by === 'employee_name' ? 'selected' : ''; ?>>
                                Όνομα Υπαλλήλου
                            </option>
                            <option value="department" <?php echo $sort_by === 'department' ? 'selected' : ''; ?>>
                                Τμήμα
                            </option>
                            <option value="typos" <?php echo $sort_by === 'typos' ? 'selected' : ''; ?>>
                                Τύπος Άδειας
                            </option>
                        </select>
                    </div>

                    <!-- Sort Order -->
                    <div class="filter-group">
                        <label for="order">🔄 Σειρά:</label>
                        <select name="order" id="order" onchange="applyFilters()">
                            <option value="ASC" <?php echo $sort_order === 'ASC' ? 'selected' : ''; ?>>
                                Αύξουσα ⬆️
                            </option>
                            <option value="DESC" <?php echo $sort_order === 'DESC' ? 'selected' : ''; ?>>
                                Φθίνουσα ⬇️
                            </option>
                        </select>
                    </div>
                </div>

                <!-- Hidden field για διατήρηση σελίδας -->
                <input type="hidden" name="page" value="1">
            </form>

            <!-- Bulk Actions Bar -->
            <div class="actions-bar">
                <div class="bulk-actions">
                    <label>
                        <input type="checkbox" id="select-all" class="bulk-checkbox"> 
                        Επιλογή όλων
                    </label>
                    <button type="button" class="btn btn-success btn-sm" onclick="showBulkApproveModal()" disabled id="bulk-approve-btn">
                        ✅ Bulk Έγκριση
                    </button>
                    <button type="button" class="btn btn-danger btn-sm" onclick="showBulkRejectModal()" disabled id="bulk-reject-btn">
                        ❌ Bulk Απόρριψη
                    </button>
                    <span id="selected-count" class="selected-count">0 επιλεγμένες</span>
                </div>

                <div class="quick-actions">
                    <button type="button" class="btn btn-info btn-sm" onclick="exportRequests('pdf')">
                        📄 Export PDF
                    </button>
                    <button type="button" class="btn btn-secondary btn-sm" onclick="exportRequests('excel')">
                        📊 Export Excel
                    </button>
                    <button type="button" class="btn btn-primary btn-sm" onclick="location.reload()">
                        🔄 Ανανέωση
                    </button>
                </div>
            </div>
        </div>

        <!-- ========================================================================
             MAIN CONTENT - ΠΙΝΑΚΑΣ ΕΚΚΡΕΜΩΝ ΑΙΤΗΣΕΩΝ
             ======================================================================== -->
        <div class="content-section">
            <?php if (empty($requests)): ?>
                <!-- Empty State -->
                <div style="text-align: center; padding: 60px 20px; color: #6c757d;">
                    <div style="font-size: 4rem; margin-bottom: 20px; opacity: 0.5;">🎉</div>
                    <h3 style="margin-bottom: 10px; color: #495057;">Δεν υπάρχουν εκκρεμείς αιτήσεις!</h3>
                    <p>
                        <?php if ($filter_department !== 'ALL' || $filter_leave_type !== 'ALL' || $filter_priority !== 'ALL'): ?>
                            Δοκιμάστε να αλλάξετε τα φίλτρα αναζήτησης.
                        <?php else: ?>
                            Όλες οι αιτήσεις έχουν διεκπεραιωθεί.
                        <?php endif; ?>
                    </p>
                </div>
            <?php else: ?>
                <!-- Requests Table -->
                <table class="requests-table">
                    <thead>
                        <tr>
                            <th width="40">
                                <input type="checkbox" id="select-all-header" class="bulk-checkbox">
                            </th>
                            <th>👤 Υπάλληλος</th>
                            <th>📋 Τύπος Άδειας</th>
                            <th>📅 Ημερομηνία Άδειας</th>
                            <th>⏱️ Διάρκεια</th>
                            <th>⚡ Προτεραιότητα</th>
                            <th>📤 Υποβλήθηκε</th>
                            <th>📝 Λεπτομέρειες</th>
                            <th>⚡ Ενέργειες</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($requests as $request): ?>
                            <?php 
                            $priority = calculatePriority($request['days_until_leave']);
                            $leave_type_info = formatLeaveTypeDisplay($request['typos']);
                            ?>
                            <tr data-request-id="<?php echo $request['id']; ?>" class="request-row">
                                <!-- Bulk Selection Checkbox -->
                                <td>
                                    <input type="checkbox" name="bulk_select" value="<?php echo $request['id']; ?>" 
                                           class="bulk-checkbox request-checkbox">
                                </td>

                                <!-- Employee Info -->
                                <td>
                                    <div class="employee-info">
                                        <div class="employee-avatar">
                                            <?php echo strtoupper(substr($request['ΟΝΟΜΑ'], 0, 1) . substr($request['ΕΠΩΝΥΜΟ'], 0, 1)); ?>
                                        </div>
                                        <div class="employee-details">
                                            <strong><?php echo htmlspecialchars($request['ΟΝΟΜΑ'] . ' ' . $request['ΕΠΩΝΥΜΟ']); ?></strong>
                                            <small>
                                                <?php echo htmlspecialchars($request['ΤΜΗΜΑ']); ?> | 
                                                Μητρώο: <?php echo htmlspecialchars($request['mitroo']); ?>
                                            </small>
                                        </div>
                                    </div>
                                </td>

                                <!-- Leave Type -->
                                <td>
                                    <div class="leave-type-badge">
                                        <?php echo $leave_type_info['emoji']; ?>
                                        <?php echo htmlspecialchars($leave_type_info['name']); ?>
                                    </div>
                                </td>

                                <!-- Leave Date -->
                                <td>
                                    <strong><?php echo date('d/m/Y', strtotime($request['imerominia'])); ?></strong>
                                    <br>
                                    <small style="color: #666;">
                                        <?php echo date('l', strtotime($request['imerominia'])); ?>
                                    </small>
                                </td>

                                <!-- Duration -->
                                <td>
                                    <?php if ($request['typos'] === 'ΟΛΙΓΟΩΡΗ'): ?>
                                        <strong><?php echo $request['wres']; ?> ώρες</strong>
                                        <?php if ($request['ora_enarxis'] && $request['ora_lixis']): ?>
                                            <br>
                                            <small style="color: #666;">
                                                <?php echo substr($request['ora_enarxis'], 0, 5) . '-' . substr($request['ora_lixis'], 0, 5); ?>
                                            </small>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <strong><?php echo $request['meres']; ?> ημέρες</strong>
                                        <br>
                                        <small style="color: #666;">
                                            <?php echo calculateBusinessDays($request['imerominia'], date('Y-m-d', strtotime($request['imerominia'] . ' +' . $request['meres'] . ' days'))); ?> εργάσιμες
                                        </small>
                                    <?php endif; ?>
                                </td>

                                <!-- Priority -->
                                <td>
                                    <div class="priority-indicator <?php echo $priority[1]; ?>">
                                        <?php echo $priority[2]; ?>
                                        <?php if ($request['days_until_leave'] <= 0): ?>
                                            ΕΚΠΡΟΘΕΣΜΗ
                                        <?php elseif ($request['days_until_leave'] == 1): ?>
                                            ΑΥΡΙΟ
                                        <?php else: ?>
                                            <?php echo $request['days_until_leave']; ?> ημέρες
                                        <?php endif; ?>
                                    </div>
                                </td>

                                <!-- Submitted Date -->
                                <td>
                                    <strong><?php echo date('d/m/Y', strtotime($request['submitted_at'])); ?></strong>
                                    <br>
                                    <small style="color: #666;">
                                        <?php echo date('H:i', strtotime($request['submitted_at'])); ?>
                                    </small>
                                </td>

                                <!-- Details -->
                                <td>
                                    <?php if (!empty($request['logos'])): ?>
                                        <div class="tooltip" data-tooltip="<?php echo htmlspecialchars($request['logos']); ?>">
                                            <small style="color: #666;">
                                                <?php echo htmlspecialchars(substr($request['logos'], 0, 30)) . (strlen($request['logos']) > 30 ? '...' : ''); ?>
                                            </small>
                                        </div>
                                    <?php endif; ?>
                                    
                                    <?php if (!empty($request['topos_dianysis'])): ?>
                                        <br>
                                        <small style="color: #888;">
                                            📍 <?php echo htmlspecialchars($request['topos_dianysis']); ?>
                                        </small>
                                    <?php endif; ?>
                                </td>

                                <!-- Actions -->
                                <td>
                                    <div class="action-buttons">
                                        <!-- View Details -->
                                        <button type="button" class="btn btn-info btn-xs" 
                                                onclick="viewRequestDetails(<?php echo $request['id']; ?>)"
                                                title="Προβολή λεπτομερειών">
                                            👁️ Προβολή
                                        </button>

                                        <!-- Approve -->
                                        <button type="button" class="btn btn-success btn-xs" 
                                                onclick="showApproveModal(<?php echo $request['id']; ?>)"
                                                title="Έγκριση αίτησης">
                                            ✅ Έγκριση
                                        </button>

                                        <!-- Reject -->
                                        <button type="button" class="btn btn-danger btn-xs" 
                                                onclick="showRejectModal(<?php echo $request['id']; ?>)"
                                                title="Απόρριψη αίτησης">
                                            ❌ Απόρριψη
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <!-- ========================================================================
                     PAGINATION SECTION
                     ======================================================================== -->
                <?php if ($total_pages > 1): ?>
                    <div class="pagination-container">
                        <div class="pagination-info">
                            Εμφάνιση <?php echo count($requests); ?> από <?php echo $total_requests; ?> συνολικά 
                            (Σελίδα <?php echo $page; ?> από <?php echo $total_pages; ?>)
                        </div>
                        
                        <div class="pagination">
                            <!-- First Page -->
                            <?php if ($page > 1): ?>
                                <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => 1])); ?>">
                                    ⏮️ Πρώτη
                                </a>
                            <?php endif; ?>

                            <!-- Previous Page -->
                            <?php if ($page > 1): ?>
                                <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page - 1])); ?>">
                                    ← Προηγούμενη
                                </a>
                            <?php endif; ?>

                            <!-- Page Numbers -->
                            <?php 
                            $start_page = max(1, $page - 2);
                            $end_page = min($total_pages, $page + 2);
                            
                            for ($i = $start_page; $i <= $end_page; $i++): 
                            ?>
                                <?php if ($i == $page): ?>
                                    <span class="current"><?php echo $i; ?></span>
                                <?php else: ?>
                                    <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $i])); ?>">
                                        <?php echo $i; ?>
                                    </a>
                                <?php endif; ?>
                            <?php endfor; ?>

                            <!-- Next Page -->
                            <?php if ($page < $total_pages): ?>
                                <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page + 1])); ?>">
                                    Επόμενη →
                                </a>
                            <?php endif; ?>

                            <!-- Last Page -->
                            <?php if ($page < $total_pages): ?>
                                <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $total_pages])); ?>">
                                    Τελευταία ⏭️
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- ========================================================================
         MODAL WINDOWS - APPROVE, REJECT, BULK OPERATIONS
         ======================================================================== -->

    <!-- Approve Modal -->
    <div id="approve-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>✅ Έγκριση Αίτησης</h3>
                <p>Προσθέστε σχόλια προϊσταμένου (προαιρετικό)</p>
            </div>
            <form method="POST" id="approve-form">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="action" value="approve_request">
                <input type="hidden" name="request_id" id="approve-request-id">
                
                <div class="modal-body">
                    <label for="manager_comments">💬 Σχόλια Προϊσταμένου:</label>
                    <textarea name="manager_comments" id="manager_comments" 
                              placeholder="Προσθέστε σχόλια για την έγκριση (προαιρετικό)"></textarea>
                </div>
                
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('approve-modal')">
                        Ακύρωση
                    </button>
                    <button type="submit" class="btn btn-success">
                        ✅ Έγκριση Αίτησης
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Reject Modal -->
    <div id="reject-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>❌ Απόρριψη Αίτησης</h3>
                <p>Η αιτιολογία απόρριψης είναι υποχρεωτική</p>
            </div>
            <form method="POST" id="reject-form">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="action" value="reject_request">
                <input type="hidden" name="request_id" id="reject-request-id">
                
                <div class="modal-body">
                    <label for="rejection_reason">📝 Αιτιολογία Απόρριψης *:</label>
                    <textarea name="rejection_reason" id="rejection_reason" required
                              placeholder="Αναφέρετε τους λόγους απόρριψης της αίτησης..."></textarea>
                </div>
                
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('reject-modal')">
                        Ακύρωση
                    </button>
                    <button type="submit" class="btn btn-danger">
                        ❌ Απόρριψη Αίτησης
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Bulk Approve Modal -->
    <div id="bulk-approve-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>✅ Bulk Έγκριση Αιτήσεων</h3>
                <p>Έγκριση πολλαπλών αιτήσεων ταυτόχρονα</p>
            </div>
            <form method="POST" id="bulk-approve-form">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="action" value="bulk_approve">
                <div id="bulk-approve-requests"></div>
                
                <div class="modal-body">
                    <label for="bulk_comments">💬 Κοινά Σχόλια:</label>
                    <textarea name="bulk_comments" id="bulk_comments" 
                              placeholder="Κοινά σχόλια για όλες τις εγκρίσεις (προαιρετικό)"></textarea>
                </div>
                
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('bulk-approve-modal')">
                        Ακύρωση
                    </button>
                    <button type="submit" class="btn btn-success">
                        ✅ Έγκριση Όλων
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Bulk Reject Modal -->
    <div id="bulk-reject-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>❌ Bulk Απόρριψη Αιτήσεων</h3>
                <p>Απόρριψη πολλαπλών αιτήσεων ταυτόχρονα</p>
            </div>
            <form method="POST" id="bulk-reject-form">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="action" value="bulk_reject">
                <div id="bulk-reject-requests"></div>
                
                <div class="modal-body">
                    <label for="bulk_rejection_reason">📝 Κοινή Αιτιολογία Απόρριψης *:</label>
                    <textarea name="bulk_rejection_reason" id="bulk_rejection_reason" required
                              placeholder="Κοινή αιτιολογία για όλες τις απορρίψεις..."></textarea>
                </div>
                
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('bulk-reject-modal')">
                        Ακύρωση
                    </button>
                    <button type="submit" class="btn btn-danger">
                        ❌ Απόρριψη Όλων
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- ========================================================================
         JAVASCRIPT SECTION - ADVANCED MANAGEMENT FUNCTIONALITY
         ======================================================================== -->
    <script>
        /**
         * ========================================================================
         * PENDING REQUESTS MANAGEMENT SYSTEM - CLIENT-SIDE FUNCTIONALITY
         * ========================================================================
         * 
         * ΠΕΡΙΓΡΑΦΗ:
         * Προηγμένη JavaScript εφαρμογή για διαχείριση εκκρεμών αιτήσεων.
         * Παρέχει real-time UI updates, bulk operations, AJAX functionality,
         * form validation και enhanced UX features.
         * 
         * ΚΥΡΙΕΣ ΛΕΙΤΟΥΡΓΙΕΣ:
         * - Bulk selection και operations
         * - Modal management για approve/reject
         * - AJAX communications
         * - Form validation
         * - Keyboard shortcuts
         * - Auto-refresh functionality
         * - Export operations
         * - Enhanced filtering
         * ========================================================================
         */

        // Global variables και state management
        let selectedRequests = new Set();
        let autoRefreshInterval = null;
        let lastUpdateCheck = new Date().toISOString();

        /**
         * ================================================================
         * INITIALIZATION - ΕΚΚΙΝΗΣΗ ΕΦΑΡΜΟΓΗΣ
         * ================================================================
         */
        document.addEventListener('DOMContentLoaded', function() {
            console.log('🚀 Pending Requests Management System loaded');
            
            // Initialize bulk selection functionality
            initializeBulkSelection();
            
            // Setup keyboard shortcuts
            setupKeyboardShortcuts();
            
            // Initialize auto-refresh
            initializeAutoRefresh();
            
            // Setup form validations
            setupFormValidations();
            
            // Initialize tooltips
            initializeTooltips();
            
            console.log(`📊 Loaded ${document.querySelectorAll('.request-row').length} pending requests`);
            console.log(`👤 User Role: ${<?php echo $is_admin ? '"Administrator"' : '"Manager"'; ?>}`);
        });

        /**
         * ================================================================
         * BULK SELECTION FUNCTIONALITY
         * ================================================================
         * 
         * Διαχείριση επιλογής πολλαπλών αιτήσεων για bulk operations
         */
        function initializeBulkSelection() {
            // Select All checkbox functionality
            const selectAllHeader = document.getElementById('select-all-header');
            const selectAll = document.getElementById('select-all');
            const requestCheckboxes = document.querySelectorAll('.request-checkbox');
            
            // Header select all functionality
            if (selectAllHeader) {
                selectAllHeader.addEventListener('change', function() {
                    const isChecked = this.checked;
                    requestCheckboxes.forEach(checkbox => {
                        checkbox.checked = isChecked;
                        updateRowSelection(checkbox.closest('tr'), isChecked);
                        
                        if (isChecked) {
                            selectedRequests.add(checkbox.value);
                        } else {
                            selectedRequests.delete(checkbox.value);
                        }
                    });
                    updateBulkActionButtons();
                });
            }

            // Sidebar select all functionality  
            if (selectAll) {
                selectAll.addEventListener('change', function() {
                    if (selectAllHeader) {
                        selectAllHeader.checked = this.checked;
                        selectAllHeader.dispatchEvent(new Event('change'));
                    }
                });
            }

            // Individual checkbox functionality
            requestCheckboxes.forEach(checkbox => {
                checkbox.addEventListener('change', function() {
                    const requestId = this.value;
                    const row = this.closest('tr');
                    
                    if (this.checked) {
                        selectedRequests.add(requestId);
                        updateRowSelection(row, true);
                    } else {
                        selectedRequests.delete(requestId);
                        updateRowSelection(row, false);
                    }
                    
                    // Update select all checkboxes
                    const totalCheckboxes = requestCheckboxes.length;
                    const checkedCheckboxes = document.querySelectorAll('.request-checkbox:checked').length;
                    
                    if (selectAllHeader) {
                        selectAllHeader.checked = (checkedCheckboxes === totalCheckboxes);
                        selectAllHeader.indeterminate = (checkedCheckboxes > 0 && checkedCheckboxes < totalCheckboxes);
                    }
                    
                    if (selectAll) {
                        selectAll.checked = (checkedCheckboxes === totalCheckboxes);
                        selectAll.indeterminate = (checkedCheckboxes > 0 && checkedCheckboxes < totalCheckboxes);
                    }
                    
                    updateBulkActionButtons();
                });
            });
        }

        /**
         * Update visual selection state για table row
         */
        function updateRowSelection(row, isSelected) {
            if (isSelected) {
                row.classList.add('bulk-selected');
            } else {
                row.classList.remove('bulk-selected');
            }
        }

        /**
         * Update bulk action buttons based on selection
         */
        function updateBulkActionButtons() {
            const selectedCount = selectedRequests.size;
            const bulkApproveBtn = document.getElementById('bulk-approve-btn');
            const bulkRejectBtn = document.getElementById('bulk-reject-btn');
            const selectedCountSpan = document.getElementById('selected-count');
            
            if (selectedCountSpan) {
                selectedCountSpan.textContent = `${selectedCount} επιλεγμένες`;
            }
            
            const hasSelection = selectedCount > 0;
            
            if (bulkApproveBtn) {
                bulkApproveBtn.disabled = !hasSelection;
                bulkApproveBtn.style.opacity = hasSelection ? '1' : '0.5';
            }
            
            if (bulkRejectBtn) {
                bulkRejectBtn.disabled = !hasSelection;
                bulkRejectBtn.style.opacity = hasSelection ? '1' : '0.5';
            }
        }

        /**
         * ================================================================
         * MODAL MANAGEMENT FUNCTIONS
         * ================================================================
         */

        /**
         * Show approve modal για single request
         */
        function showApproveModal(requestId) {
            document.getElementById('approve-request-id').value = requestId;
            document.getElementById('manager_comments').value = '';
            showModal('approve-modal');
        }

        /**
         * Show reject modal για single request
         */
        function showRejectModal(requestId) {
            document.getElementById('reject-request-id').value = requestId;
            document.getElementById('rejection_reason').value = '';
            showModal('reject-modal');
        }

        /**
         * Show bulk approve modal
         */
        function showBulkApproveModal() {
            if (selectedRequests.size === 0) {
                alert('⚠️ Παρακαλώ επιλέξτε τουλάχιστον μία αίτηση.');
                return;
            }

            // Δημιουργία hidden inputs για επιλεγμένες αιτήσεις
            const container = document.getElementById('bulk-approve-requests');
            container.innerHTML = '';
            
            selectedRequests.forEach(requestId => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'selected_requests[]';
                input.value = requestId;
                container.appendChild(input);
            });

            document.getElementById('bulk_comments').value = '';
            showModal('bulk-approve-modal');
        }

        /**
         * Show bulk reject modal
         */
        function showBulkRejectModal() {
            if (selectedRequests.size === 0) {
                alert('⚠️ Παρακαλώ επιλέξτε τουλάχιστον μία αίτηση.');
                return;
            }

            // Δημιουργία hidden inputs για επιλεγμένες αιτήσεις
            const container = document.getElementById('bulk-reject-requests');
            container.innerHTML = '';
            
            selectedRequests.forEach(requestId => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'selected_requests[]';
                input.value = requestId;
                container.appendChild(input);
            });

            document.getElementById('bulk_rejection_reason').value = '';
            showModal('bulk-reject-modal');
        }

        /**
         * Generic modal show function
         */
        function showModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'block';
                document.body.style.overflow = 'hidden'; // Prevent background scrolling
                
                // Focus στο πρώτο input field
                const firstInput = modal.querySelector('textarea, input[type="text"]');
                if (firstInput) {
                    setTimeout(() => firstInput.focus(), 100);
                }
            }
        }

        /**
         * Generic modal close function
         */
        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'none';
                document.body.style.overflow = 'auto'; // Restore scrolling
            }
        }

        /**
         * Close modal when clicking outside
         */
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('modal')) {
                closeModal(e.target.id);
            }
        });

        /**
         * ================================================================
         * FORM VALIDATION FUNCTIONS
         * ================================================================
         */
        function setupFormValidations() {
            // Approve form validation
            const approveForm = document.getElementById('approve-form');
            if (approveForm) {
                approveForm.addEventListener('submit', function(e) {
                    const submitBtn = this.querySelector('button[type="submit"]');
                    if (submitBtn) {
                        submitBtn.innerHTML = '<span class="loading"></span> Εγκρίνεται...';
                        submitBtn.disabled = true;
                    }
                });
            }

            // Reject form validation
            const rejectForm = document.getElementById('reject-form');
            if (rejectForm) {
                rejectForm.addEventListener('submit', function(e) {
                    const reason = document.getElementById('rejection_reason').value.trim();
                    if (reason.length < 10) {
                        e.preventDefault();
                        alert('⚠️ Η αιτιολογία απόρριψης πρέπει να είναι τουλάχιστον 10 χαρακτήρες.');
                        return false;
                    }

                    const submitBtn = this.querySelector('button[type="submit"]');
                    if (submitBtn) {
                        submitBtn.innerHTML = '<span class="loading"></span> Απορρίπτεται...';
                        submitBtn.disabled = true;
                    }
                });
            }

            // Bulk approve form validation
            const bulkApproveForm = document.getElementById('bulk-approve-form');
            if (bulkApproveForm) {
                bulkApproveForm.addEventListener('submit', function(e) {
                    if (!confirm(`⚠️ ΠΡΟΣΟΧΗ!\n\nΘα εγκριθούν ${selectedRequests.size} αιτήσεις.\nΕίστε σίγουροι;`)) {
                        e.preventDefault();
                        return false;
                    }

                    const submitBtn = this.querySelector('button[type="submit"]');
                    if (submitBtn) {
                        submitBtn.innerHTML = '<span class="loading"></span> Εγκρίνονται...';
                        submitBtn.disabled = true;
                    }
                });
            }

            // Bulk reject form validation
            const bulkRejectForm = document.getElementById('bulk-reject-form');
            if (bulkRejectForm) {
                bulkRejectForm.addEventListener('submit', function(e) {
                    const reason = document.getElementById('bulk_rejection_reason').value.trim();
                    if (reason.length < 10) {
                        e.preventDefault();
                        alert('⚠️ Η αιτιολογία bulk απόρριψης πρέπει να είναι τουλάχιστον 10 χαρακτήρες.');
                        return false;
                    }

                    if (!confirm(`⚠️ ΠΡΟΣΟΧΗ!\n\nΘα απορριφθούν ${selectedRequests.size} αιτήσεις.\nΕίστε σίγουροι;`)) {
                        e.preventDefault();
                        return false;
                    }

                    const submitBtn = this.querySelector('button[type="submit"]');
                    if (submitBtn) {
                        submitBtn.innerHTML = '<span class="loading"></span> Απορρίπτονται...';
                        submitBtn.disabled = true;
                    }
                });
            }
        }

        /**
         * ================================================================
         * FILTERING AND SEARCH FUNCTIONALITY
         * ================================================================
         */

        /**
         * Apply filters and reload page
         */
        function applyFilters() {
            // Reset page to 1 when applying filters
            document.querySelector('input[name="page"]').value = 1;
            document.getElementById('filters-form').submit();
        }

        /**
         * Clear all filters
         */
        function clearAllFilters() {
            const form = document.getElementById('filters-form');
            const selects = form.querySelectorAll('select');
            const inputs = form.querySelectorAll('input[type="date"]');
            
            selects.forEach(select => {
                if (select.name !== 'sort' && select.name !== 'order') {
                    select.value = 'ALL';
                } else if (select.name === 'sort') {
                    select.value = 'submitted_at';
                } else if (select.name === 'order') {
                    select.value = 'ASC';
                }
            });

            inputs.forEach(input => {
                input.value = '';
            });

            applyFilters();
        }

        /**
         * ================================================================
         * REQUEST DETAILS FUNCTIONALITY
         * ================================================================
         */

        /**
         * View detailed request information
         */
        function viewRequestDetails(requestId) {
            // Create popup window με request details
            const popup = window.open(
                `request-details.php?id=${requestId}&mode=popup`, 
                'RequestDetails',
                'width=800,height=700,scrollbars=yes,resizable=yes,toolbar=no,menubar=no'
            );
            
            if (!popup) {
                // Fallback: Navigate to details page in same window
                window.open(`request-details.php?id=${requestId}`, '_blank');
            }
        }

        /**
         * ================================================================
         * AUTO-REFRESH FUNCTIONALITY
         * ================================================================
         */
        function initializeAutoRefresh() {
            // Auto-refresh κάθε 60 δευτερόλεπτα για real-time updates
            autoRefreshInterval = setInterval(checkForUpdates, 60000);
            
            // Check for visibility change to pause/resume auto-refresh
            document.addEventListener('visibilitychange', function() {
                if (document.hidden) {
                    if (autoRefreshInterval) {
                        clearInterval(autoRefreshInterval);
                        autoRefreshInterval = null;
                    }
                } else {
                    if (!autoRefreshInterval) {
                        autoRefreshInterval = setInterval(checkForUpdates, 60000);
                    }
                }
            });
        }

        /**
         * Check for new updates via AJAX
         */
        function checkForUpdates() {
            fetch('ajax/check-pending-updates.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    last_check: lastUpdateCheck,
                    current_filters: getCurrentFilters()
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.has_updates) {
                    showUpdateNotification(data.update_count);
                }
                lastUpdateCheck = new Date().toISOString();
            })
            .catch(error => {
                console.log('Update check failed:', error);
            });
        }

        /**
         * Get current filter state
         */
        function getCurrentFilters() {
            const form = document.getElementById('filters-form');
            const formData = new FormData(form);
            const filters = {};
            
            for (let [key, value] of formData.entries()) {
                filters[key] = value;
            }
            
            return filters;
        }

        /**
         * Show notification για updates
         */
        function showUpdateNotification(updateCount) {
            const notification = document.createElement('div');
            notification.className = 'alert alert-info';
            notification.style.position = 'fixed';
            notification.style.top = '20px';
            notification.style.right = '20px';
            notification.style.zIndex = '9999';
            notification.style.maxWidth = '350px';
            notification.innerHTML = `
                <strong>🔄 Νέες ενημερώσεις!</strong><br>
                ${updateCount} νέες αλλαγές στις εκκρεμείς αιτήσεις.
                <br>
                <button onclick="location.reload()" class="btn btn-sm btn-primary" style="margin-top: 8px;">
                    🔄 Ανανέωση
                </button>
                <button onclick="this.parentElement.remove()" class="btn btn-sm btn-secondary" style="margin-top: 8px; margin-left: 5px;">
                    ✕ Κλείσιμο
                </button>
            `;

            document.body.appendChild(notification);

            // Auto-remove μετά από 15 δευτερόλεπτα
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 15000);
        }

        /**
         * ================================================================
         * KEYBOARD SHORTCUTS
         * ================================================================
         */
        function setupKeyboardShortcuts() {
            document.addEventListener('keydown', function(e) {
                // Ctrl+A: Select/Deselect All
                if (e.ctrlKey && e.key === 'a' && !e.target.matches('input, textarea')) {
                    e.preventDefault();
                    const selectAllHeader = document.getElementById('select-all-header');
                    if (selectAllHeader) {
                        selectAllHeader.checked = !selectAllHeader.checked;
                        selectAllHeader.dispatchEvent(new Event('change'));
                    }
                }

                // Ctrl+E: Bulk Approve (if items selected)
                if (e.ctrlKey && e.key === 'e') {
                    e.preventDefault();
                    if (selectedRequests.size > 0) {
                        showBulkApproveModal();
                    }
                }

                // Ctrl+R: Bulk Reject (if items selected)
                if (e.ctrlKey && e.key === 'r') {
                    e.preventDefault();
                    if (selectedRequests.size > 0) {
                        showBulkRejectModal();
                    }
                }

                // F5 or Ctrl+R: Refresh page
                if (e.key === 'F5' || (e.ctrlKey && e.key === 'r')) {
                    // Let default behavior handle this
                }

                // Escape: Close modals or clear selections
                if (e.key === 'Escape') {
                    // Close any open modals
                    const openModals = document.querySelectorAll('.modal[style*="block"]');
                    openModals.forEach(modal => {
                        closeModal(modal.id);
                    });

                    // If no modals, clear selections
                    if (openModals.length === 0 && selectedRequests.size > 0) {
                        const selectAllHeader = document.getElementById('select-all-header');
                        if (selectAllHeader) {
                            selectAllHeader.checked = false;
                            selectAllHeader.dispatchEvent(new Event('change'));
                        }
                    }
                }

                // Enter: Submit focused form
                if (e.key === 'Enter' && e.target.matches('textarea')) {
                    // Allow Enter in textareas
                    return;
                }
            });
        }

        /**
         * ================================================================
         * EXPORT FUNCTIONALITY
         * ================================================================
         */

        /**
         * Export requests to PDF or Excel
         */
        function exportRequests(format) {
            const currentFilters = getCurrentFilters();
            currentFilters.export = format;
            currentFilters.selected_only = selectedRequests.size > 0 ? 'true' : 'false';
            
            if (selectedRequests.size > 0) {
                currentFilters.selected_requests = Array.from(selectedRequests);
            }
            
            // Create temporary form για export
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = 'export-pending-requests.php';
            form.target = '_blank';
            form.style.display = 'none';

            // Add CSRF token
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = '<?php echo $csrf_token; ?>';
            form.appendChild(csrfInput);

            // Add filters as hidden inputs
            for (const [key, value] of Object.entries(currentFilters)) {
                if (Array.isArray(value)) {
                    value.forEach(v => {
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = key + '[]';
                        input.value = v;
                        form.appendChild(input);
                    });
                } else {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = key;
                    input.value = value;
                    form.appendChild(input);
                }
            }

            document.body.appendChild(form);
            form.submit();
            document.body.removeChild(form);

            // Show feedback message
            showTemporaryMessage(
                `📄 Export ${format.toUpperCase()} ξεκίνησε...`,
                'info',
                3000
            );
        }

        /**
         * ================================================================
         * UTILITY FUNCTIONS
         * ================================================================
         */

        /**
         * Initialize tooltips
         */
        function initializeTooltips() {
            const tooltipElements = document.querySelectorAll('[data-tooltip]');
            tooltipElements.forEach(element => {
                // Enhanced tooltip functionality could be added here
                element.addEventListener('mouseenter', function() {
                    // Custom tooltip implementation
                });
            });
        }

        /**
         * Show temporary message
         */
        function showTemporaryMessage(message, type = 'info', duration = 5000) {
            const alert = document.createElement('div');
            alert.className = `alert alert-${type}`;
            alert.style.position = 'fixed';
            alert.style.top = '20px';
            alert.style.left = '50%';
            alert.style.transform = 'translateX(-50%)';
            alert.style.zIndex = '9999';
            alert.style.minWidth = '300px';
            alert.style.textAlign = 'center';
            alert.innerHTML = message;

            document.body.appendChild(alert);

            setTimeout(() => {
                if (alert.parentElement) {
                    alert.style.opacity = '0';
                    alert.style.transition = 'opacity 0.5s ease';
                    setTimeout(() => alert.remove(), 500);
                }
            }, duration);
        }

        /**
         * Format number with thousands separator
         */
        function formatNumber(num) {
            return new Intl.NumberFormat('el-GR').format(num);
        }

        /**
         * Calculate business days between dates
         */
        function calculateBusinessDays(startDate, endDate) {
            const start = new Date(startDate);
            const end = new Date(endDate);
            let businessDays = 0;
            
            const currentDate = new Date(start);
            while (currentDate <= end) {
                const dayOfWeek = currentDate.getDay();
                if (dayOfWeek !== 0 && dayOfWeek !== 6) { // Skip weekends
                    businessDays++;
                }
                currentDate.setDate(currentDate.getDate() + 1);
            }
            
            return businessDays;
        }

        /**
         * ================================================================
         * DEBUG AND DEVELOPMENT FUNCTIONS
         * ================================================================
         */

        /**
         * Console logging for debugging
         */
        function logDebugInfo() {
            console.group('🔍 Pending Requests Debug Info');
            console.log('Selected Requests:', Array.from(selectedRequests));
            console.log('Current Filters:', getCurrentFilters());
            console.log('Total Requests:', document.querySelectorAll('.request-row').length);
            console.log('Auto-refresh Active:', !!autoRefreshInterval);
            console.log('Last Update Check:', lastUpdateCheck);
            console.groupEnd();
        }

        // Expose debug function to console
        window.debugPendingRequests = logDebugInfo;

        /**
         * Performance monitoring
         */
        window.addEventListener('load', function() {
            const loadTime = performance.now();
            console.log(`⚡ Page loaded in ${Math.round(loadTime)}ms`);
            
            // Log performance metrics
            if (performance.getEntriesByType) {
                const navigationTiming = performance.getEntriesByType('navigation')[0];
                if (navigationTiming) {
                    console.log(`📊 Navigation Timing:
                        - DNS Lookup: ${Math.round(navigationTiming.domainLookupEnd - navigationTiming.domainLookupStart)}ms
                        - Server Response: ${Math.round(navigationTiming.responseEnd - navigationTiming.requestStart)}ms
                        - DOM Content Loaded: ${Math.round(navigationTiming.domContentLoadedEventEnd - navigationTiming.navigationStart)}ms
                    `);
                }
            }
        });

        // Development shortcuts στο console
        console.log(`
🎯 KEYBOARD SHORTCUTS:
- Ctrl+A: Select/Deselect All Requests
- Ctrl+E: Bulk Approve (if selected)
- Ctrl+R: Bulk Reject (if selected)  
- Escape: Close modals or clear selections
- F5: Refresh page

🔧 DEBUG COMMANDS:
- window.debugPendingRequests(): Show debug info

📊 CURRENT PAGE STATS:
- Total Pending: <?php echo $stats['total_pending'] ?? 0; ?>
- Urgent Requests: <?php echo $stats['urgent'] ?? 0; ?>
- Current Page: <?php echo $page; ?>/<?php echo $total_pages; ?>
- User Role: <?php echo $is_admin ? 'Administrator' : 'Manager'; ?>
        `);

        /**
         * ================================================================
         * ADDITIONAL UTILITY FUNCTIONS
         * ================================================================
         */

        /**
         * Scroll to top smoothly
         */
        function scrollToTop() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        }

        /**
         * Copy request details to clipboard
         */
        function copyRequestDetails(requestId) {
            const row = document.querySelector(`[data-request-id="${requestId}"]`);
            if (row) {
                const details = extractRequestDetails(row);
                navigator.clipboard.writeText(details).then(() => {
                    showTemporaryMessage('📋 Στοιχεία αντιγράφηκαν!', 'success', 2000);
                });
            }
        }

        /**
         * Extract request details from table row
         */
        function extractRequestDetails(row) {
            const cells = row.querySelectorAll('td');
            // Extract text content from relevant cells
            const employee = cells[1].textContent.trim();
            const leaveType = cells[2].textContent.trim();
            const leaveDate = cells[3].textContent.trim();
            const duration = cells[4].textContent.trim();
            const priority = cells[5].textContent.trim();
            
            return `Υπάλληλος: ${employee}
Τύπος Άδειας: ${leaveType}
Ημερομηνία: ${leaveDate}
Διάρκεια: ${duration}
Προτεραιότητα: ${priority}`;
        }

        /**
         * Print current page
         */
        function printPage() {
            window.print();
        }

        /**
         * Toggle compact view
         */
        function toggleCompactView() {
            const table = document.querySelector('.requests-table');
            table.classList.toggle('compact-view');
            
            // Save preference to localStorage
            const isCompact = table.classList.contains('compact-view');
            localStorage.setItem('pendingRequestsCompactView', isCompact);
        }

        /**
         * Load saved preferences
         */
        function loadUserPreferences() {
            // Restore compact view preference
            const isCompact = localStorage.getItem('pendingRequestsCompactView') === 'true';
            if (isCompact) {
                document.querySelector('.requests-table').classList.add('compact-view');
            }
        }

        // Load preferences on page load
        document.addEventListener('DOMContentLoaded', loadUserPreferences);

        /**
         * ================================================================
         * ERROR HANDLING AND RECOVERY
         * ================================================================
         */

        /**
         * Global error handler
         */
        window.addEventListener('error', function(e) {
            console.error('JavaScript Error:', e.error);
            
            // Show user-friendly error message
            showTemporaryMessage(
                '⚠️ Προέκυψε σφάλμα. Παρακαλώ ανανεώστε τη σελίδα.',
                'danger',
                5000
            );
        });

        /**
         * Handle network errors
         */
        window.addEventListener('online', function() {
            showTemporaryMessage('🌐 Η σύνδεση αποκαταστάθηκε!', 'success', 3000);
            // Resume auto-refresh
            if (!autoRefreshInterval) {
                initializeAutoRefresh();
            }
        });

        window.addEventListener('offline', function() {
            showTemporaryMessage('📡 Χωρίς σύνδεση στο διαδίκτυο', 'warning', 5000);
            // Pause auto-refresh
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }
        });

        /**
         * ================================================================
         * ACCESSIBILITY ENHANCEMENTS
         * ================================================================
         */

        /**
         * Keyboard navigation for table
         */
        function setupKeyboardNavigation() {
            const rows = document.querySelectorAll('.request-row');
            let currentRowIndex = -1;

            document.addEventListener('keydown', function(e) {
                if (e.target.matches('input, textarea, select')) return;

                switch(e.key) {
                    case 'ArrowDown':
                        e.preventDefault();
                        currentRowIndex = Math.min(currentRowIndex + 1, rows.length - 1);
                        highlightRow(currentRowIndex);
                        break;
                    case 'ArrowUp':
                        e.preventDefault();
                        currentRowIndex = Math.max(currentRowIndex - 1, 0);
                        highlightRow(currentRowIndex);
                        break;
                    case ' ': // Space to toggle selection
                        e.preventDefault();
                        if (currentRowIndex >= 0) {
                            const checkbox = rows[currentRowIndex].querySelector('.request-checkbox');
                            if (checkbox) {
                                checkbox.checked = !checkbox.checked;
                                checkbox.dispatchEvent(new Event('change'));
                            }
                        }
                        break;
                }
            });
        }

        /**
         * Highlight current row
         */
        function highlightRow(index) {
            // Remove previous highlights
            document.querySelectorAll('.keyboard-highlight').forEach(row => {
                row.classList.remove('keyboard-highlight');
            });

            const rows = document.querySelectorAll('.request-row');
            if (rows[index]) {
                rows[index].classList.add('keyboard-highlight');
                rows[index].scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }

        // Initialize keyboard navigation
        document.addEventListener('DOMContentLoaded', setupKeyboardNavigation);

        /**
         * ================================================================
         * FINAL INITIALIZATION
         * ================================================================
         */

        // Ensure all functionality is ready
        document.addEventListener('DOMContentLoaded', function() {
            // Double-check all critical elements are present
            const criticalElements = [
                'filters-form',
                'bulk-approve-btn', 
                'bulk-reject-btn',
                'selected-count'
            ];

            criticalElements.forEach(id => {
                if (!document.getElementById(id)) {
                    console.warn(`⚠️ Critical element missing: ${id}`);
                }
            });

            // Mark page as fully loaded
            document.body.setAttribute('data-page-loaded', 'true');
            
            // Final console log
            console.log('✅ Pending Requests Management System fully initialized');
        });
    </script>

    <!-- Add some additional CSS for enhanced functionality -->
    <style>
        /* Compact view styles */
        .requests-table.compact-view th,
        .requests-table.compact-view td {
            padding: 8px 6px;
            font-size: 0.85rem;
        }

        /* Keyboard navigation highlight */
        .keyboard-highlight {
            outline: 2px solid #667eea;
            outline-offset: -2px;
            background-color: rgba(102, 126, 234, 0.1) !important;
        }

        /* Enhanced loading state */
        .loading-state {
            opacity: 0.6;
            pointer-events: none;
            position: relative;
        }

        .loading-state::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 20px;
            height: 20px;
            margin: -10px 0 0 -10px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        /* Responsive table improvements */
        @media (max-width: 768px) {
            .requests-table {
                display: block;
                overflow-x: auto;
                white-space: nowrap;
            }
            
            .modal-content {
                width: 95%;
                margin: 20px auto;
                max-height: 90vh;
            }
        }

        /* Print styles */
        @media print {
            .controls-section,
            .pagination-container,
            .action-buttons,
            .back-btn {
                display: none !important;
            }
            
            .header {
                background: white !important;
                color: black !important;
            }
        }
    </style>
</body>
</html>
