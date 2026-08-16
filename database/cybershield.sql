CREATE DATABASE IF NOT EXISTS cybershield;

USE cybershield;

CREATE TABLE IF NOT EXISTS scam_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    reporter_name VARCHAR(100),
    reporter_email VARCHAR(150),
    scam_type VARCHAR(50) NOT NULL,
    scam_url TEXT,
    scam_message TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);