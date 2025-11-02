from flask import Flask, render_template_string, request, jsonify, session
import sqlite3
import requests
import re
import whois
import ssl
import socket
from datetime import datetime
import time
import hashlib
import json
import threading
from bs4 import BeautifulSoup

app = Flask(__name__)
app.secret_key = 'chowdhuryvai_security_key_2023'

# Database setup
def init_db():
    conn = sqlite3.connect('fraud_check.db')
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS checks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT NOT NULL,
                  check_type TEXT NOT NULL,
                  email TEXT,
                  risk_score INTEGER,
                  status TEXT,
                  results TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  domain TEXT UNIQUE,
                  reason TEXT,
                  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert sample blacklist data
    blacklist_domains = [
        ('fake-bank.com', 'Phishing scam'),
        ('malware-download.net', 'Malware distribution'),
        ('credit-card-stealer.org', 'Financial fraud'),
        ('fake-login-page.com', 'Credential harvesting'),
        ('bitcoin-scam.io', 'Cryptocurrency fraud')
    ]
    
    for domain, reason in blacklist_domains:
        try:
            c.execute("INSERT OR IGNORE INTO blacklist (domain, reason) VALUES (?, ?)", 
                     (domain, reason))
        except:
            pass
    
    conn.commit()
    conn.close()

init_db()

class FraudAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'bank', 'paypal', 'ebay', 'amazon',
            'password', 'security', 'update', 'confirm', 'urgent', 'important'
        ]
        
        self.trust_indicators = [
            'https', 'ssl', 'trust', 'secure', 'verified', 'official'
        ]
    
    def analyze_domain(self, url):
        """Comprehensive domain analysis"""
        try:
            # Extract domain from URL
            domain = re.findall(r'https?://([^/]+)', url)
            if not domain:
                return {"error": "Invalid URL format"}
            
            domain = domain[0]
            results = {
                'domain': domain,
                'risk_score': 0,
                'warnings': [],
                'recommendations': [],
                'details': {}
            }
            
            # Check blacklist
            if self.check_blacklist(domain):
                results['risk_score'] += 80
                results['warnings'].append('Domain found in security blacklist')
            
            # WHOIS analysis
            whois_data = self.get_whois_info(domain)
            if whois_data:
                results['details']['whois'] = whois_data
                results['risk_score'] += self.analyze_whois(whois_data)
            
            # SSL certificate check
            ssl_info = self.check_ssl_certificate(domain)
            if ssl_info:
                results['details']['ssl'] = ssl_info
                results['risk_score'] += self.analyze_ssl(ssl_info)
            
            # Domain age analysis
            domain_age = self.get_domain_age(domain)
            if domain_age:
                results['details']['domain_age_days'] = domain_age
                if domain_age < 30:
                    results['risk_score'] += 40
                    results['warnings'].append('Very new domain (less than 30 days)')
                elif domain_age < 365:
                    results['risk_score'] += 20
                    results['warnings'].append('Relatively new domain (less than 1 year)')
            
            # Content analysis
            content_analysis = self.analyze_website_content(url)
            if content_analysis:
                results['details']['content_analysis'] = content_analysis
                results['risk_score'] += content_analysis.get('risk_score', 0)
                results['warnings'].extend(content_analysis.get('warnings', []))
            
            # Final risk assessment
            results['risk_level'] = self.get_risk_level(results['risk_score'])
            results['timestamp'] = datetime.now().isoformat()
            
            return results
            
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
    def check_blacklist(self, domain):
        """Check if domain is in blacklist"""
        conn = sqlite3.connect('fraud_check.db')
        c = conn.cursor()
        c.execute("SELECT * FROM blacklist WHERE domain = ?", (domain,))
        result = c.fetchone()
        conn.close()
        return result is not None
    
    def get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': list(w.name_servers) if w.name_servers else None,
                'emails': w.emails
            }
        except:
            return None
    
    def analyze_whois(self, whois_data):
        """Analyze WHOIS data for suspicious patterns"""
        risk_score = 0
        
        # Check if registrar is known
        if whois_data.get('registrar'):
            suspicious_registrars = ['anonymous', 'privacy', 'fake']
            if any(keyword in whois_data['registrar'].lower() for keyword in suspicious_registrars):
                risk_score += 30
        
        # Check email addresses
        if whois_data.get('emails'):
            for email in whois_data['emails']:
                if email and ('anonymous' in email.lower() or 'privacy' in email.lower()):
                    risk_score += 25
        
        return risk_score
    
    def check_ssl_certificate(self, domain):
        """Check SSL certificate details"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
        except:
            return None
    
    def analyze_ssl(self, ssl_info):
        """Analyze SSL certificate"""
        risk_score = 0
        
        # Check certificate expiration
        not_after = datetime.strptime(ssl_info['not_after'], '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (not_after - datetime.now()).days
        
        if days_until_expiry < 30:
            risk_score += 20
        elif days_until_expiry < 7:
            risk_score += 40
        
        return risk_score
    
    def get_domain_age(self, domain):
        """Calculate domain age in days"""
        try:
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                age_days = (datetime.now() - creation_date).days
                return age_days
        except:
            pass
        return None
    
    def analyze_website_content(self, url):
        """Analyze website content for suspicious patterns"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            analysis = {
                'risk_score': 0,
                'warnings': [],
                'suspicious_elements': []
            }
            
            # Check for login forms
            login_forms = soup.find_all('form', {'action': True})
            for form in login_forms:
                if any(keyword in form.get('action', '').lower() for keyword in ['login', 'signin', 'auth']):
                    analysis['suspicious_elements'].append('Login form detected')
                    analysis['risk_score'] += 10
            
            # Check for password fields
            password_fields = soup.find_all('input', {'type': 'password'})
            if password_fields:
                analysis['suspicious_elements'].append('Password input fields detected')
                analysis['risk_score'] += 15
            
            # Check title and meta tags
            title = soup.find('title')
            if title:
                title_text = title.get_text().lower()
                if any(keyword in title_text for keyword in self.suspicious_keywords):
                    analysis['suspicious_elements'].append('Suspicious keywords in title')
                    analysis['risk_score'] += 5
            
            # Check for hidden elements
            hidden_elements = soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden'))
            if len(hidden_elements) > 5:
                analysis['warnings'].append('Multiple hidden elements detected')
                analysis['risk_score'] += 10
            
            return analysis
            
        except Exception as e:
            return {'error': f'Content analysis failed: {str(e)}', 'risk_score': 0}
    
    def get_risk_level(self, score):
        """Convert risk score to level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "SAFE"

# Initialize analyzer
analyzer = FraudAnalyzer()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ChowdhuryVai - Professional Fraud Check & Security Services</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background-color: #0a0a0a;
            color: #00ff00;
            font-family: 'Share Tech Mono', monospace;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(0, 255, 0, 0.05) 0%, transparent 20%),
                radial-gradient(circle at 90% 60%, rgba(0, 255, 0, 0.05) 0%, transparent 20%),
                radial-gradient(circle at 50% 80%, rgba(0, 255, 0, 0.05) 0%, transparent 20%);
            position: relative;
        }
        
        body::before {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                repeating-linear-gradient(
                    0deg,
                    rgba(0, 255, 0, 0.03) 0px,
                    rgba(0, 255, 0, 0.03) 1px,
                    transparent 1px,
                    transparent 2px
                );
            pointer-events: none;
            z-index: -1;
        }
        
        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            z-index: -2;
        }
        
        .matrix-char {
            position: absolute;
            color: rgba(0, 255, 0, 0.3);
            font-size: 14px;
            font-family: 'Share Tech Mono', monospace;
            animation: fall linear infinite;
        }
        
        @keyframes fall {
            to {
                transform: translateY(100vh);
            }
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid #00ff00;
            margin-bottom: 40px;
        }
        
        .logo {
            font-family: 'Orbitron', sans-serif;
            font-size: 28px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 3px;
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
        }
        
        .logo span {
            color: #ff0000;
        }
        
        nav ul {
            display: flex;
            list-style: none;
        }
        
        nav ul li {
            margin-left: 30px;
        }
        
        nav ul li a {
            color: #00ff00;
            text-decoration: none;
            font-size: 16px;
            transition: all 0.3s;
            position: relative;
        }
        
        nav ul li a:hover {
            color: #ffffff;
            text-shadow: 0 0 8px #00ff00;
        }
        
        nav ul li a::after {
            content: '';
            position: absolute;
            bottom: -5px;
            left: 0;
            width: 0;
            height: 2px;
            background: #00ff00;
            transition: width 0.3s;
        }
        
        nav ul li a:hover::after {
            width: 100%;
        }
        
        .hero {
            text-align: center;
            padding: 80px 0;
            margin-bottom: 60px;
            position: relative;
        }
        
        .hero::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at center, rgba(0, 255, 0, 0.1) 0%, transparent 70%);
            z-index: -1;
        }
        
        .hero h1 {
            font-family: 'Orbitron', sans-serif;
            font-size: 48px;
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 4px;
            text-shadow: 0 0 15px #00ff00;
        }
        
        .hero p {
            font-size: 20px;
            max-width: 800px;
            margin: 0 auto 30px;
            line-height: 1.6;
        }
        
        .cta-button {
            display: inline-block;
            background: transparent;
            color: #00ff00;
            border: 2px solid #00ff00;
            padding: 12px 30px;
            font-size: 18px;
            font-family: 'Orbitron', sans-serif;
            text-transform: uppercase;
            letter-spacing: 2px;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            margin: 10px;
        }
        
        .cta-button:hover {
            background: #00ff00;
            color: #000000;
            box-shadow: 0 0 20px #00ff00;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin-bottom: 60px;
        }
        
        .feature-card {
            background: rgba(0, 20, 0, 0.5);
            border: 1px solid #00ff00;
            padding: 30px;
            border-radius: 5px;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .feature-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 0, 0.1), transparent);
            transition: left 0.5s;
        }
        
        .feature-card:hover::before {
            left: 100%;
        }
        
        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 10px 20px rgba(0, 255, 0, 0.2);
        }
        
        .feature-card h3 {
            font-family: 'Orbitron', sans-serif;
            font-size: 22px;
            margin-bottom: 15px;
            color: #ffffff;
        }
        
        .feature-card p {
            line-height: 1.6;
        }
        
        .check-form {
            background: rgba(0, 20, 0, 0.5);
            border: 1px solid #00ff00;
            padding: 40px;
            border-radius: 5px;
            margin-bottom: 60px;
        }
        
        .check-form h2 {
            font-family: 'Orbitron', sans-serif;
            font-size: 28px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 16px;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            background: rgba(0, 10, 0, 0.7);
            border: 1px solid #00ff00;
            color: #00ff00;
            font-family: 'Share Tech Mono', monospace;
            font-size: 16px;
        }
        
        .form-group input:focus, .form-group select:focus {
            outline: none;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
        }
        
        .results {
            background: rgba(0, 20, 0, 0.5);
            border: 1px solid #00ff00;
            padding: 30px;
            border-radius: 5px;
            margin-bottom: 40px;
            display: none;
        }
        
        .risk-critical {
            border-color: #ff0000;
            background: rgba(50, 0, 0, 0.5);
        }
        
        .risk-high {
            border-color: #ff5500;
            background: rgba(50, 20, 0, 0.5);
        }
        
        .risk-medium {
            border-color: #ffff00;
            background: rgba(50, 50, 0, 0.5);
        }
        
        .risk-low {
            border-color: #00ff00;
        }
        
        .risk-safe {
            border-color: #00ff00;
            background: rgba(0, 30, 0, 0.5);
        }
        
        .risk-score {
            font-size: 24px;
            font-weight: bold;
            text-align: center;
            margin-bottom: 20px;
        }
        
        .risk-level {
            font-size: 32px;
            font-family: 'Orbitron', sans-serif;
            text-align: center;
            margin-bottom: 20px;
            text-transform: uppercase;
        }
        
        .warning-list, .recommendation-list {
            margin: 20px 0;
        }
        
        .warning-item, .recommendation-item {
            padding: 10px;
            margin: 5px 0;
            border-left: 3px solid;
        }
        
        .warning-item {
            border-left-color: #ff0000;
            background: rgba(255, 0, 0, 0.1);
        }
        
        .recommendation-item {
            border-left-color: #00ff00;
            background: rgba(0, 255, 0, 0.1);
        }
        
        .details-section {
            margin-top: 30px;
        }
        
        .details-section h4 {
            font-family: 'Orbitron', sans-serif;
            margin-bottom: 15px;
            color: #ffffff;
        }
        
        .detail-item {
            margin: 10px 0;
            padding: 10px;
            background: rgba(0, 10, 0, 0.5);
            border: 1px solid #003300;
        }
        
        .contact-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px;
            margin-bottom: 60px;
        }
        
        .contact-card {
            background: rgba(0, 20, 0, 0.5);
            border: 1px solid #00ff00;
            padding: 25px;
            border-radius: 5px;
            text-align: center;
            transition: all 0.3s;
        }
        
        .contact-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 255, 0, 0.2);
        }
        
        .contact-card h3 {
            font-family: 'Orbitron', sans-serif;
            font-size: 20px;
            margin-bottom: 15px;
            color: #ffffff;
        }
        
        .contact-card a {
            color: #00ff00;
            text-decoration: none;
            transition: all 0.3s;
        }
        
        .contact-card a:hover {
            color: #ffffff;
            text-shadow: 0 0 8px #00ff00;
        }
        
        footer {
            text-align: center;
            padding: 30px 0;
            border-top: 1px solid #00ff00;
            margin-top: 60px;
            font-size: 14px;
        }
        
        .glitch {
            position: relative;
            display: inline-block;
        }
        
        .glitch::before, .glitch::after {
            content: attr(data-text);
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }
        
        .glitch::before {
            left: 2px;
            text-shadow: -2px 0 #ff0000;
            clip: rect(44px, 450px, 56px, 0);
            animation: glitch-anim 5s infinite linear alternate-reverse;
        }
        
        .glitch::after {
            left: -2px;
            text-shadow: -2px 0 #0000ff;
            clip: rect(44px, 450px, 56px, 0);
            animation: glitch-anim2 5s infinite linear alternate-reverse;
        }
        
        @keyframes glitch-anim {
            0% {
                clip: rect(42px, 9999px, 44px, 0);
            }
            5% {
                clip: rect(12px, 9999px, 59px, 0);
            }
            10% {
                clip: rect(48px, 9999px, 29px, 0);
            }
            15% {
                clip: rect(42px, 9999px, 73px, 0);
            }
            20% {
                clip: rect(63px, 9999px, 27px, 0);
            }
            25% {
                clip: rect(34px, 9999px, 55px, 0);
            }
            30% {
                clip: rect(86px, 9999px, 73px, 0);
            }
            35% {
                clip: rect(20px, 9999px, 20px, 0);
            }
            40% {
                clip: rect(26px, 9999px, 60px, 0);
            }
            45% {
                clip: rect(25px, 9999px, 66px, 0);
            }
            50% {
                clip: rect(57px, 9999px, 98px, 0);
            }
            55% {
                clip: rect(5px, 9999px, 46px, 0);
            }
            60% {
                clip: rect(82px, 9999px, 31px, 0);
            }
            65% {
                clip: rect(54px, 9999px, 27px, 0);
            }
            70% {
                clip: rect(28px, 9999px, 99px, 0);
            }
            75% {
                clip: rect(45px, 9999px, 69px, 0);
            }
            80% {
                clip: rect(23px, 9999px, 85px, 0);
            }
            85% {
                clip: rect(54px, 9999px, 84px, 0);
            }
            90% {
                clip: rect(45px, 9999px, 47px, 0);
            }
            95% {
                clip: rect(37px, 9999px, 20px, 0);
            }
            100% {
                clip: rect(4px, 9999px, 91px, 0);
            }
        }
        
        @keyframes glitch-anim2 {
            0% {
                clip: rect(65px, 9999px, 100px, 0);
            }
            5% {
                clip: rect(52px, 9999px, 74px, 0);
            }
            10% {
                clip: rect(79px, 9999px, 85px, 0);
            }
            15% {
                clip: rect(75px, 9999px, 5px, 0);
            }
            20% {
                clip: rect(67px, 9999px, 61px, 0);
            }
            25% {
                clip: rect(14px, 9999px, 79px, 0);
            }
            30% {
                clip: rect(1px, 9999px, 66px, 0);
            }
            35% {
                clip: rect(86px, 9999px, 30px, 0);
            }
            40% {
                clip: rect(23px, 9999px, 98px, 0);
            }
            45% {
                clip: rect(85px, 9999px, 72px, 0);
            }
            50% {
                clip: rect(71px, 9999px, 75px, 0);
            }
            55% {
                clip: rect(2px, 9999px, 48px, 0);
            }
            60% {
                clip: rect(30px, 9999px, 16px, 0);
            }
            65% {
                clip: rect(59px, 9999px, 50px, 0);
            }
            70% {
                clip: rect(41px, 9999px, 62px, 0);
            }
            75% {
                clip: rect(2px, 9999px, 82px, 0);
            }
            80% {
                clip: rect(47px, 9999px, 73px, 0);
            }
            85% {
                clip: rect(3px, 9999px, 27px, 0);
            }
            90% {
                clip: rect(26px, 9999px, 55px, 0);
            }
            95% {
                clip: rect(42px, 9999px, 97px, 0);
            }
            100% {
                clip: rect(38px, 9999px, 49px, 0);
            }
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .loading-spinner {
            border: 5px solid #003300;
            border-top: 5px solid #00ff00;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @media (max-width: 768px) {
            header {
                flex-direction: column;
                text-align: center;
            }
            
            nav ul {
                margin-top: 20px;
                justify-content: center;
            }
            
            nav ul li {
                margin: 0 10px;
            }
            
            .hero h1 {
                font-size: 36px;
            }
            
            .hero p {
                font-size: 18px;
            }
        }
    </style>
</head>
<body>
    <div class="matrix-bg" id="matrixBg"></div>
    
    <div class="container">
        <header>
            <div class="logo">Chowdhury<span>Vai</span></div>
            <nav>
                <ul>
                    <li><a href="#home">Home</a></li>
                    <li><a href="#services">Services</a></li>
                    <li><a href="#check">Fraud Check</a></li>
                    <li><a href="#contact">Contact</a></li>
                </ul>
            </nav>
        </header>
        
        <section class="hero" id="home">
            <h1 class="glitch" data-text="PROFESSIONAL FRAUD CHECK">PROFESSIONAL FRAUD CHECK</h1>
            <p>Advanced AI-powered tools and services to detect and prevent fraudulent activities. Protect your digital assets with our cutting-edge security solutions.</p>
            <div>
                <a href="#check" class="cta-button">Check Website Now</a>
                <a href="#services" class="cta-button">Our Services</a>
            </div>
        </section>
        
        <section class="features" id="services">
            <div class="feature-card">
                <h3>Real-time Fraud Detection</h3>
                <p>Advanced algorithms to detect fraudulent activities across various platforms and services. Our system analyzes patterns and behaviors to identify potential threats in real-time.</p>
            </div>
            <div class="feature-card">
                <h3>Comprehensive Security Audits</h3>
                <p>Professional security audits for websites, applications, and networks. We identify vulnerabilities and provide solutions to strengthen your security posture.</p>
            </div>
            <div class="feature-card">
                <h3>Blacklist Monitoring</h3>
                <p>Continuous monitoring of global security blacklists to protect your domains and IP addresses from being flagged by security services.</p>
            </div>
        </section>
        
        <section class="check-form" id="check">
            <h2>Professional Fraud Check Tool</h2>
            <form id="fraudCheckForm">
                <div class="form-group">
                    <label for="url">Website URL</label>
                    <input type="text" id="url" name="url" placeholder="Enter website URL to check (e.g., https://example.com)" required>
                </div>
                <div class="form-group">
                    <label for="type">Check Type</label>
                    <select id="type" name="type" required>
                        <option value="">Select check type</option>
                        <option value="comprehensive">Comprehensive Security Analysis</option>
                        <option value="phishing">Phishing Detection</option>
                        <option value="malware">Malware Scan</option>
                        <option value="fraud">Fraud Analysis</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="email">Email (Optional - for detailed report)</label>
                    <input type="email" id="email" name="email" placeholder="Enter your email for detailed results">
                </div>
                <button type="submit" class="cta-button" style="width: 100%;">Run Professional Security Check</button>
            </form>
            
            <div class="loading" id="loading">
                <div class="loading-spinner"></div>
                <p>Analyzing website security... This may take up to 30 seconds</p>
            </div>
            
            <div class="results" id="results">
                <!-- Results will be displayed here -->
            </div>
        </section>
        
        <section class="contact-info" id="contact">
            <div class="contact-card">
                <h3>Telegram ID</h3>
                <p><a href="https://t.me/darkvaiadmin" target="_blank">@darkvaiadmin</a></p>
            </div>
            <div class="contact-card">
                <h3>Telegram Channel</h3>
                <p><a href="https://t.me/windowspremiumkey" target="_blank">Windows Premium Key</a></p>
            </div>
            <div class="contact-card">
                <h3>Hacking/Cracking Website</h3>
                <p><a href="https://crackyworld.com/" target="_blank">CrackyWorld.com</a></p>
            </div>
        </section>
        
        <footer>
            <p>&copy; 2023 ChowdhuryVai. All rights reserved. | Professional Security & Fraud Prevention Services</p>
        </footer>
    </div>
    
    <script>
        // Matrix background effect
        function createMatrix() {
            const matrixBg = document.getElementById('matrixBg');
            const chars = '01010101010101010101010101010101ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            
            for (let i = 0; i < 100; i++) {
                const char = document.createElement('div');
                char.className = 'matrix-char';
                char.textContent = chars.charAt(Math.floor(Math.random() * chars.length));
                char.style.left = Math.random() * 100 + 'vw';
                char.style.animationDuration = (Math.random() * 10 + 5) + 's';
                char.style.animationDelay = Math.random() * 5 + 's';
                matrixBg.appendChild(char);
            }
        }
        
        // Form submission
        document.getElementById('fraudCheckForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const url = document.getElementById('url').value;
            const type = document.getElementById('type').value;
            const email = document.getElementById('email').value;
            
            // Show loading
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            
            try {
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `url=${encodeURIComponent(url)}&type=${encodeURIComponent(type)}&email=${encodeURIComponent(email)}`
                });
                
                const data = await response.json();
                
                // Hide loading
                document.getElementById('loading').style.display = 'none';
                
                // Display results
                displayResults(data);
                
            } catch (error) {
                document.getElementById('loading').style.display = 'none';
                alert('Error: ' + error.message);
            }
        });
        
        function displayResults(data) {
            const resultsDiv = document.getElementById('results');
            resultsDiv.style.display = 'block';
            
            if (data.error) {
                resultsDiv.innerHTML = `
                    <div class="risk-level" style="color: #ff0000;">ERROR</div>
                    <p>${data.error}</p>
                `;
                return;
            }
            
            // Set risk class
            resultsDiv.className = 'results risk-' + data.risk_level.toLowerCase();
            
            let warningsHTML = '';
            if (data.warnings && data.warnings.length > 0) {
                warningsHTML = `
                    <div class="warning-list">
                        <h4>Security Warnings:</h4>
                        ${data.warnings.map(warning => `<div class="warning-item">${warning}</div>`).join('')}
                    </div>
                `;
            }
            
            let recommendationsHTML = '';
            if (data.recommendations && data.recommendations.length > 0) {
                recommendationsHTML = `
                    <div class="recommendation-list">
                        <h4>Recommendations:</h4>
                        ${data.recommendations.map(rec => `<div class="recommendation-item">${rec}</div>`).join('')}
                    </div>
                `;
            }
            
            let detailsHTML = '';
            if (data.details) {
                detailsHTML = `
                    <div class="details-section">
                        <h4>Detailed Analysis:</h4>
                        ${Object.entries(data.details).map(([key, value]) => `
                            <div class="detail-item">
                                <strong>${key.replace(/_/g, ' ').toUpperCase()}:</strong> 
                                ${typeof value === 'object' ? JSON.stringify(value, null, 2) : value}
                            </div>
                        `).join('')}
                    </div>
                `;
            }
            
            // Risk level color
            let riskColor = '#00ff00';
            if (data.risk_level === 'CRITICAL') riskColor = '#ff0000';
            else if (data.risk_level === 'HIGH') riskColor = '#ff5500';
            else if (data.risk_level === 'MEDIUM') riskColor = '#ffff00';
            else if (data.risk_level === 'LOW') riskColor = '#00ff00';
            
            resultsDiv.innerHTML = `
                <div class="risk-score">Risk Score: ${data.risk_score}/100</div>
                <div class="risk-level" style="color: ${riskColor};">${data.risk_level} RISK</div>
                <p><strong>Domain:</strong> ${data.domain}</p>
                <p><strong>Analysis Time:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
                ${warningsHTML}
                ${recommendationsHTML}
                ${detailsHTML}
            `;
            
            // Scroll to results
            resultsDiv.scrollIntoView({ behavior: 'smooth' });
        }
        
        // Initialize matrix effect
        createMatrix();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/check', methods=['POST'])
def check_fraud():
    url = request.form.get('url')
    check_type = request.form.get('type')
    email = request.form.get('email')
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Perform fraud analysis
    results = analyzer.analyze_domain(url)
    
    # Save to database
    conn = sqlite3.connect('fraud_check.db')
    c = conn.cursor()
    c.execute('''INSERT INTO checks (url, check_type, email, risk_score, status, results)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (url, check_type, email, results.get('risk_score', 0), 
               'completed', json.dumps(results)))
    conn.commit()
    conn.close()
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
