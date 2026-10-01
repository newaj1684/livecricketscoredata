<?php
// CricNova Enterprise Cricket API Portal
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');

if (file_exists(__DIR__ . '/index.html')) {
    include __DIR__ . '/index.html';
    exit;
} else {
    echo "<!DOCTYPE html><html><head><title>CricNova API</title></head><body style='background:#070b14;color:#fff;font-family:sans-serif;text-align:center;padding:50px;'><h1>🏏 CricNova Enterprise Cricket API</h1><p>Status: Online</p><p>Contact: yagnikrathod089@gmail.com</p></body></html>";
}
