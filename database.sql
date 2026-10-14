-- ============================================================
-- MediVault - Hospital Patient Records Security System
-- Database setup file: schema + DEMO data
-- Database: medivault (MySQL 8.0)
--
-- Docker runs this file automatically the FIRST time the
-- database container starts with an empty volume.
-- To re-run it:  docker compose down -v
--                docker compose up -d --build
--
-- DEMO DATA ONLY. All names and emails are fake.
-- Every demo account uses the password: Admin@1234
-- (stored as a bcrypt hash). OTP emails are caught by Mailpit
-- at http://localhost:8025 and never leave your computer.
-- ============================================================

CREATE DATABASE IF NOT EXISTS medivault
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_general_ci;

USE medivault;

SET NAMES utf8mb4;

-- ============================================================
-- TABLE 1: users
-- ============================================================

CREATE TABLE users (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(100) NOT NULL,
    email            VARCHAR(100) NOT NULL UNIQUE,
    password         VARCHAR(255) NOT NULL,
    role             ENUM('admin','doctor','nurse','receptionist') NOT NULL,
    otp              VARCHAR(6) DEFAULT NULL,
    otp_expiry       DATETIME DEFAULT NULL,
    otp_attempts     INT DEFAULT 0,
    otp_last_sent    DATETIME DEFAULT NULL,
    failed_attempts  INT DEFAULT 0,
    is_locked        TINYINT(1) DEFAULT 0,
    first_login      TINYINT(1) DEFAULT 1,
    reset_token      VARCHAR(255) DEFAULT NULL,
    reset_expiry     DATETIME DEFAULT NULL,
    reset_used       TINYINT(1) DEFAULT 0,
    last_login_ip    VARCHAR(45) DEFAULT NULL,
    last_login_time  DATETIME DEFAULT NULL,
    created_by       INT DEFAULT NULL,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at       DATETIME DEFAULT NULL,
    deleted_by       INT DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- TABLE 2: patients
-- ============================================================

CREATE TABLE patients (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    age          INT NOT NULL,
    gender       ENUM('Male','Female','Other') NOT NULL,
    diagnosis    TEXT NOT NULL,
    created_by   INT NOT NULL,
    updated_by   INT DEFAULT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at   DATETIME DEFAULT NULL,
    deleted_by   INT DEFAULT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- TABLE 3: assets
-- ============================================================

CREATE TABLE assets (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(100) NOT NULL,
    classification   ENUM('Confidential','Internal','Public') NOT NULL,
    description      TEXT DEFAULT NULL,
    created_by       INT NOT NULL,
    updated_by       INT DEFAULT NULL,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at       DATETIME DEFAULT NULL,
    deleted_by       INT DEFAULT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- TABLE 4: risks  (risk_score = likelihood x impact)
-- ============================================================

CREATE TABLE risks (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    asset_id     INT NOT NULL,
    threat       VARCHAR(200) NOT NULL,
    likelihood   INT NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact       INT NOT NULL CHECK (impact BETWEEN 1 AND 5),
    risk_score   INT GENERATED ALWAYS AS (likelihood * impact) STORED,
    created_by   INT NOT NULL,
    updated_by   INT DEFAULT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at   DATETIME DEFAULT NULL,
    deleted_by   INT DEFAULT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- TABLE 5: incidents
-- ============================================================

CREATE TABLE incidents (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    title         VARCHAR(200) NOT NULL,
    description   TEXT NOT NULL,
    priority      ENUM('Low','Medium','High') DEFAULT 'Medium',
    status        ENUM('Open','Investigating','Resolved') DEFAULT 'Open',
    assigned_to   INT DEFAULT NULL,
    reported_by   INT NOT NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at    DATETIME DEFAULT NULL,
    deleted_by    INT DEFAULT NULL,
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (reported_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- TABLE 6: activity_logs  (is_suspicious = 1 is flagged)
-- ============================================================

CREATE TABLE activity_logs (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    user_id          INT NOT NULL,
    action           VARCHAR(255) NOT NULL,
    ip_address       VARCHAR(45) DEFAULT NULL,
    is_suspicious    TINYINT(1) DEFAULT 0,
    flagged_reason   VARCHAR(255) DEFAULT NULL,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
    deleted_at       DATETIME DEFAULT NULL,
    deleted_by       INT DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- TABLE 7: policies
-- ============================================================

CREATE TABLE policies (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    title        VARCHAR(200) NOT NULL,
    content      TEXT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- TABLE 8: password_resets  (single-use tokens)
-- ============================================================

CREATE TABLE password_resets (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    token       VARCHAR(255) NOT NULL UNIQUE,
    expiry      DATETIME NOT NULL,
    is_used     TINYINT(1) DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


-- ============================================================
-- DEMO DATA
-- ============================================================

-- 7 demo users. Password for all: Admin@1234
-- first_login = 0 so demo accounts skip the forced password change.
INSERT INTO users (name, email, password, role, first_login) VALUES
('Admin User',      'admin@example.com',
 '$2y$10$o.Bae2Ort21TKOzfblsh0.zKZQo4MR4b7u2vjf022zFKBvpg9peja', 'admin', 0),
('Dr. Santos',      'dr.santos@example.com',
 '$2y$10$o.Bae2Ort21TKOzfblsh0.zKZQo4MR4b7u2vjf022zFKBvpg9peja', 'doctor', 0),
('Dr. Reyes',       'dr.reyes@example.com',
 '$2y$10$o.Bae2Ort21TKOzfblsh0.zKZQo4MR4b7u2vjf022zFKBvpg9peja', 'doctor', 0),
('Nurse Dela Cruz', 'nurse.delacruz@example.com',
 '$2y$10$o.Bae2Ort21TKOzfblsh0.zKZQo4MR4b7u2vjf022zFKBvpg9peja', 'nurse', 0),
('Nurse Tan',       'nurse.tan@example.com',
 '$2y$10$o.Bae2Ort21TKOzfblsh0.zKZQo4MR4b7u2vjf022zFKBvpg9peja', 'nurse', 0),
('Recep Ana',       'recep.ana@example.com',
 '$2y$10$o.Bae2Ort21TKOzfblsh0.zKZQo4MR4b7u2vjf022zFKBvpg9peja', 'receptionist', 0),
('Recep Ben',       'recep.ben@example.com',
 '$2y$10$o.Bae2Ort21TKOzfblsh0.zKZQo4MR4b7u2vjf022zFKBvpg9peja', 'receptionist', 0);

-- 3 fictional patients
INSERT INTO patients (name, age, gender, diagnosis, created_by) VALUES
('Juan Dela Cruz', 45, 'Male',   'Hypertension',       2),
('Maria Reyes',     32, 'Female', 'Migraine',           2),
('Alex Tan',        27, 'Other',  'Seasonal allergies', 3);

-- 5 assets (created by Admin User, id 1)
INSERT INTO assets (name, classification, description, created_by) VALUES
('Patient Records Database',        'Confidential', 'Central database storing all patient medical records', 1),
('Hospital Network Infrastructure', 'Internal',     'Internal network connecting all hospital systems', 1),
('Staff Workstations',              'Internal',     'Desktop computers used by hospital staff', 1),
('Backup Server',                   'Confidential', 'Offsite backup of all critical hospital data', 1),
('Public Hospital Website',         'Public',       'Patient-facing hospital information website', 1);

-- 5 risks (risk_score is calculated automatically)
INSERT INTO risks (asset_id, threat, likelihood, impact, created_by) VALUES
(1, 'Unauthorized access to patient records', 5, 5, 1),
(1, 'SQL injection attack on database',       4, 5, 1),
(2, 'Network intrusion by external attacker', 3, 4, 1),
(3, 'Malware infection via USB drive',        4, 3, 1),
(4, 'Backup data corruption or loss',         2, 5, 1);

-- 3 incidents
INSERT INTO incidents (title, description, priority, status, assigned_to, reported_by) VALUES
('Unauthorized Login Attempt',
 'Multiple failed login attempts detected from unknown IP address 192.168.10.55',
 'High', 'Investigating', 2, 1),
('Patient Record Access Anomaly',
 'Unusual number of patient records accessed in short time period',
 'Medium', 'Open', NULL, 1),
('Staff Workstation Malware Alert',
 'Antivirus flagged suspicious file on workstation in ward 3',
 'High', 'Resolved', NULL, 1);

-- 5 policies
INSERT INTO policies (title, content) VALUES
('Password Policy',
 'All users must use passwords with minimum 8 characters including uppercase, lowercase, number, and special character. Passwords must be changed every 90 days. Never share passwords with anyone.'),
('Access Control Policy',
 'Users are granted minimum access required for their role. Doctors access patient records. Nurses view only. Receptionists add patients only. Admins manage all system functions.'),
('Incident Response Policy',
 'All security incidents must be reported immediately via the Incidents module. Incidents are triaged by priority: High requires immediate response within 1 hour, Medium within 24 hours, Low within 72 hours.'),
('Data Backup Policy',
 'Patient records and system data are backed up daily. Backup integrity is verified weekly. Backups are stored in an encrypted offsite location and retained for 90 days.'),
('Acceptable Use Policy',
 'MediVault systems are for authorized hospital use only. Users must not access data beyond their role permissions. All activities are logged and monitored. Violations result in immediate account suspension.');

-- Sample activity log (includes flagged entries so the dashboard has something to show)
INSERT INTO activity_logs (user_id, action, ip_address, is_suspicious, flagged_reason, timestamp) VALUES
(1, 'Login credentials verified - OTP sent to admin@example.com', '127.0.0.1', 0, NULL, DATE_SUB(NOW(), INTERVAL 5 HOUR)),
(1, 'Login successful - OTP verified',                            '127.0.0.1', 0, NULL, DATE_SUB(NOW(), INTERVAL 5 HOUR)),
(2, 'Failed login attempt - wrong password (attempt 1 of 5)',     '127.0.0.1', 0, NULL, DATE_SUB(NOW(), INTERVAL 4 HOUR)),
(2, 'Login successful - OTP verified',                            '127.0.0.1', 0, NULL, DATE_SUB(NOW(), INTERVAL 4 HOUR)),
(3, 'Login during unusual hours',                                 '127.0.0.1', 1, 'Login at 01:38:08 - outside normal hours (10PM-5AM flagged)', DATE_SUB(NOW(), INTERVAL 3 HOUR)),
(5, 'Account locked after 5 failed login attempts',               '127.0.0.1', 1, '5 consecutive wrong password attempts from IP 127.0.0.1 - account auto-locked', DATE_SUB(NOW(), INTERVAL 2 HOUR)),
(1, 'Login successful - OTP verified',                            '127.0.0.1', 0, NULL, DATE_SUB(NOW(), INTERVAL 1 HOUR));

-- ============================================================
-- END OF database.sql
-- ============================================================
