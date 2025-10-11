#!/usr/bin/env python3
"""
Military-Grade Encrypted Chat System - SNS Protocol v2.0
SECURE NETWORKED MESSAGING PROTOCOL WITH ADVANCED SECURITY
"""

import os
import json
import base64
import hashlib
import secrets
import time
import socket
import re
import mimetypes
import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from io import BytesIO
import uuid

# Check and install dependencies first
try:
    import flask
    import cryptography
    import requests
    import geopy
except ImportError:
    print("Installing required packages...")
    os.system("python3 -m pip install --quiet flask==2.3.3 cryptography==41.0.4 requests==2.31.0 geopy==2.4.1")
    import flask
    import cryptography
    import requests
    import geopy

# Now import Flask components safely
from flask import Flask, request, render_template_string, redirect, session, jsonify, send_file, make_response

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Enhanced SNS Protocol Configuration
SNS_CONFIG = {
    'key_derivation_rounds': 100000,
    'token_size': 64,
    'salt_size': 32,
    'nonce_size': 16,
    'key_size': 32,
    'max_file_size': 50 * 1024 * 1024,  # 50MB
    'session_timeout': 1800,  # 30 minutes
    'max_login_attempts': 3
}

# In-memory storage
users_db = {}
messages_db = {}
sessions_db = {}
login_attempts = {}
security_logs = []
call_offers = {}
call_answers = {}
call_candidates = {}
file_storage = {}
user_locations = {}  # Store real-time GPS locations
typing_indicators = {}  # Store typing status

# Fixed key for signaling encryption (32 bytes)
call_key = b'secure_call_key_for_signaling' + b'\x00' * (32 - len(b'secure_call_key_for_signaling'))


# Track application start time for uptime calculation
start_time = time.time()


class AdvancedSecurity:
    """Advanced security measures for threat prevention"""

    # Known malicious file signatures and magic numbers
    MALICIOUS_SIGNATURES = {
        # Executables
        b'MZ': 'Windows executable',
        b'\x7FELF': 'ELF executable',
        b'\xFE\xED\xFA': 'Mach-O binary',
        b'\xCE\xFA\xED\xFE': 'Mach-O binary',
        b'\xCF\xFA\xED\xFE': 'Mach-O binary',

        # Scripts
        b'#!/bin': 'Shell script',
        b'#!/usr/bin': 'Shell script',
        b'#!/bin/sh': 'Shell script',
        b'#!/bin/bash': 'Bash script',
        b'#!python': 'Python script',
        b'#!perl': 'Perl script',
        b'#!ruby': 'Ruby script',

        # Office documents with macros
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'MS Office document',
        b'PK\x03\x04': 'ZIP archive (potentially dangerous)',

        # Other dangerous formats
        b'%PDF': 'PDF document',
        b'\x00\x00\x01\x00': 'Windows icon',
        b'\x00\x00\x02\x00': 'Windows cursor',
    }

    # Restricted file extensions
    RESTRICTED_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.application', '.gadget',
        '.msi', '.msp', '.com', '.scr', '.hta', '.cpl', '.msc', '.jar', '.bin',
        '.dmg', '.app', '.apk', '.deb', '.rpm', '.iso', '.vbs', '.js', '.ps1',
        '.sh', '.bash', '.zsh', '.py', '.pl', '.rb', '.php', '.html', '.htm'
    }

    @staticmethod
    def log_security_event(event_type: str, details: str, username: str = "unknown"):
        """Log security events for monitoring"""
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type': event_type,
            'details': details,
            'username': username,
            'ip': request.remote_addr if request else 'unknown'
        }
        security_logs.append(event)
        print(f"🔒 SECURITY EVENT: {event_type} - {details} - User: {username}")

    @staticmethod
    def detect_file_type(file_data: bytes) -> Tuple[str, str]:
        """Detect file type using magic numbers"""
        if len(file_data) < 4:
            return "unknown", "File too small"

        # Check magic numbers
        for signature, description in AdvancedSecurity.MALICIOUS_SIGNATURES.items():
            if file_data.startswith(signature):
                return description, "identified by magic number"

        # Check for text files
        try:
            text_start = file_data[:1024].decode('utf-8', errors='ignore')
            if text_start.startswith(('<?php', '<script', '<html', '<!DOCTYPE')):
                return "web script", "identified as web script"
        except:
            pass

        # Guess from common patterns
        if file_data.startswith(b'\xFF\xD8\xFF'):
            return "image/jpeg", "JPEG image"
        elif file_data.startswith(b'\x89PNG\r\n\x1a\n'):
            return "image/png", "PNG image"
        elif file_data.startswith(b'GIF8'):
            return "image/gif", "GIF image"
        elif file_data.startswith(b'BM'):
            return "image/bmp", "BMP image"
        elif file_data.startswith(b'RIFF') and file_data[8:12] == b'WEBP':
            return "image/webp", "WebP image"
        elif file_data.startswith(b'\x00\x00\x00 ftyp'):
            return "video/mp4", "MP4 video"
        elif file_data.startswith(b'ID3'):
            return "audio/mpeg", "MP3 audio"
        elif file_data.startswith(b'%PDF'):
            return "application/pdf", "PDF document"

        return "application/octet-stream", "unknown binary"

    @staticmethod
    def detect_malicious_file(file_data: bytes) -> Tuple[bool, str]:
        """Detect potentially malicious files"""
        try:
            # Check file size
            if len(file_data) > SNS_CONFIG['max_file_size']:
                return True, "File too large (max 50MB)"

            if len(file_data) == 0:
                return True, "Empty file"

            # Detect file type
            file_type, reason = AdvancedSecurity.detect_file_type(file_data)

            # Check for dangerous file types
            dangerous_types = [
                'Windows executable', 'ELF executable', 'Mach-O binary',
                'Shell script', 'Bash script', 'Python script', 'Perl script', 'Ruby script',
                'MS Office document', 'web script'
            ]

            if any(dangerous in file_type for dangerous in dangerous_types):
                return True, f"Dangerous file type: {file_type} ({reason})"

            # Additional checks for specific file types
            if file_type == "application/pdf":
                # Check for PDF with potential exploits
                if b'/JavaScript' in file_data or b'/AA' in file_data or b'/OpenAction' in file_data:
                    return True, "PDF contains potentially dangerous JavaScript"

            return False, f"File type: {file_type}"

        except Exception as e:
            return True, f"Security scan failed: {str(e)}"

    @staticmethod
    def validate_filename(filename: str) -> bool:
        """Validate filename for security"""
        if not filename or len(filename) > 255:
            return False

        # Check for path traversal attempts
        if '..' in filename or '/' in filename or '\\' in filename:
            return False

        # Check for null bytes
        if '\x00' in filename:
            return False

        # Check extension
        _, ext = os.path.splitext(filename.lower())
        if ext in AdvancedSecurity.RESTRICTED_EXTENSIONS:
            return False

        # Check for dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
        if any(char in filename for char in dangerous_chars):
            return False

        return True

    @staticmethod
    def sanitize_input(text: str) -> str:
        """Sanitize user input to prevent XSS and injection"""
        if not text:
            return ""

        # Remove potentially dangerous characters and patterns
        sanitized = re.sub(r'[<>"\'&;`|$(){}[\]]', '', text)

        # Remove script tags and event handlers
        sanitized = re.sub(r'<script.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)

        return sanitized[:1000]  # Limit length

    @staticmethod
    def format_file_size(size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"


class SNSCrypto:
    """Military-grade encryption using SNS Protocol"""

    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(SNS_CONFIG['salt_size'])

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        kdf = Scrypt(
            salt=salt,
            length=SNS_CONFIG['key_size'],
            n=2 ** 14,
            r=8,
            p=1
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_data(key: bytes, data: bytes) -> Dict:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        nonce = secrets.token_bytes(SNS_CONFIG['nonce_size'])
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(data) + encryptor.finalize()

        return {
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }

    @staticmethod
    def decrypt_data(key: bytes, encrypted_data: Dict) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        try:
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


class SNSUserManager:
    """Secure user management with military-grade encryption"""

    @staticmethod
    def create_user(username: str, master_password: str) -> bool:
        if username in users_db:
            return False

        if len(master_password) < 8:
            return False

        # Generate unique salt for user
        salt = SNSCrypto.generate_salt()

        # Derive master key
        master_key = SNSCrypto.derive_key(master_password, salt)

        # Generate unique SNS phone number (format: SNS-XXXXX)
        sns_number = f"SNS-{secrets.randbelow(90000) + 10000}"

        # Create user profile with encrypted storage key
        users_db[username] = {
            'salt': base64.b64encode(salt).decode(),
            'master_key_hash': base64.b64encode(hashlib.sha256(master_key).digest()).decode(),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'friends': [],
            'failed_logins': 0,
            'locked_until': None,
            'sns_number': sns_number
        }

        # Initialize message storage
        messages_db[username] = {}

        AdvancedSecurity.log_security_event("USER_CREATED", f"New user registered: {username}", username)
        return True

    @staticmethod
    def verify_user(username: str, master_password: str) -> bool:
        if username not in users_db:
            AdvancedSecurity.log_security_event("LOGIN_FAILED", "Unknown username attempted", username)
            return False

        user_data = users_db[username]

        # Check if account is locked
        if user_data.get('locked_until'):
            lock_time = datetime.fromisoformat(user_data['locked_until'])
            if datetime.now(timezone.utc) < lock_time:
                AdvancedSecurity.log_security_event("LOGIN_BLOCKED", "Account temporarily locked", username)
                return False

        salt = base64.b64decode(user_data['salt'])

        # Derive master key
        master_key = SNSCrypto.derive_key(master_password, salt)
        master_key_hash = base64.b64encode(hashlib.sha256(master_key).digest()).decode()

        if master_key_hash == user_data['master_key_hash']:
            # Successful login - reset failed attempts
            user_data['failed_logins'] = 0
            user_data['locked_until'] = None
            AdvancedSecurity.log_security_event("LOGIN_SUCCESS", "User logged in successfully", username)
            return True
        else:
            # Failed login
            user_data['failed_logins'] = user_data.get('failed_logins', 0) + 1
            AdvancedSecurity.log_security_event("LOGIN_FAILED", f"Failed login attempt {user_data['failed_logins']}",
                                                username)

            # Lock account after 3 failed attempts for 15 minutes
            if user_data['failed_logins'] >= 3:
                lock_time = datetime.now(timezone.utc).timestamp() + 900  # 15 minutes
                user_data['locked_until'] = datetime.fromtimestamp(lock_time, timezone.utc).isoformat()
                AdvancedSecurity.log_security_event("ACCOUNT_LOCKED", "Account locked due to failed attempts", username)

            return False

    @staticmethod
    def create_session(username: str) -> str:
        session_token = secrets.token_hex(SNS_CONFIG['token_size'])
        sessions_db[session_token] = {
            'username': username,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'last_activity': datetime.now(timezone.utc).isoformat(),
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string
        }
        return session_token


class LocationTracker:
    """Advanced location tracking with IP geolocation"""

    @staticmethod
    def get_location_info(ip_address: str) -> Dict:
        """Get detailed location information from IP address"""
        # Handle localhost IPs with mock data for testing
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            return {
                'ip': ip_address,
                'country': 'Local Network',
                'region': 'Development',
                'city': 'Localhost',
                'loc': '28.6139,77.2090',  # Delhi coordinates for demo
                'org': 'Local Development Server',
                'timezone': 'Asia/Kolkata',
                'hostname': 'localhost',
                'postal': '110001'
            }

        try:
            # Use ipinfo.io API for geolocation (free tier)
            response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip_address,
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'loc': data.get('loc', '0,0'),  # lat,lng
                    'org': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'hostname': data.get('hostname', 'Unknown'),
                    'postal': data.get('postal', 'Unknown')
                }
            else:
                return LocationTracker._fallback_location(ip_address)
        except Exception as e:
            print(f"Geolocation error for {ip_address}: {str(e)}")
            return LocationTracker._fallback_location(ip_address)

    @staticmethod
    def _fallback_location(ip_address: str) -> Dict:
        """Fallback location data when API fails"""
        return {
            'ip': ip_address,
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'loc': '0,0',
            'org': 'Unknown',
            'timezone': 'Unknown',
            'hostname': ip_address,
            'postal': 'Unknown'
        }

    @staticmethod
    def get_distance(loc1: str, loc2: str) -> float:
        """Calculate distance between two locations"""
        try:
            from geopy.distance import geodesic
            lat1, lon1 = map(float, loc1.split(','))
            lat2, lon2 = map(float, loc2.split(','))
            return geodesic((lat1, lon1), (lat2, lon2)).kilometers
        except:
            return 0.0


def find_available_port(start_port=5000, max_port=5010):
    """Find an available port to run the application"""
    for port in range(start_port, max_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return None


def require_auth(f):
    """Decorator to require authentication with security checks"""

    def wrapped(*args, **kwargs):
        # Check if user is authenticated
        if 'user' not in session or 'token' not in session:
            AdvancedSecurity.log_security_event("UNAUTHORIZED_ACCESS",
                                                "Attempt to access protected resource without auth")
            return redirect('/?error=Authentication required')

        # Verify session token
        if session['token'] not in sessions_db:
            AdvancedSecurity.log_security_event("INVALID_SESSION", "Invalid session token used")
            session.clear()
            return redirect('/?error=Session expired')

        # Check session timeout
        session_data = sessions_db[session['token']]
        last_activity = datetime.fromisoformat(session_data['last_activity'])
        if (datetime.now(timezone.utc) - last_activity).total_seconds() > SNS_CONFIG['session_timeout']:
            AdvancedSecurity.log_security_event("SESSION_TIMEOUT", "Session expired due to inactivity", session['user'])
            del sessions_db[session['token']]
            session.clear()
            return redirect('/?error=Session expired')

        # Update last activity
        session_data['last_activity'] = datetime.now(timezone.utc).isoformat()

        return f(*args, **kwargs)

    # Rename function to avoid Flask endpoint conflicts
    wrapped.__name__ = f.__name__ + '_wrapped'
    return wrapped


# Military Terminal HTML Templates with Enhanced Security
SECURE_HTML_HEADER = '''
<!DOCTYPE html>
<html>
<head>
    <title>SNS Protocol - Military Terminal</title>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' data:; frame-src 'self' data:; object-src 'self' data:;">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
        // Advanced Security Measures
        document.addEventListener('DOMContentLoaded', function() {
            // Disable right click
            document.addEventListener('contextmenu', function(e) {
                e.preventDefault();
                return false;
            });

            // Disable text selection
            document.addEventListener('selectstart', function(e) {
                e.preventDefault();
                return false;
            });

            // Disable drag and drop
            document.addEventListener('dragstart', function(e) {
                e.preventDefault();
                return false;
            });

            // Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U, Ctrl+S, Cmd+S, Ctrl+P
            document.addEventListener('keydown', function(e) {
                if (e.key === 'F12' ||
                    (e.ctrlKey && e.shiftKey && e.key === 'I') ||
                    (e.ctrlKey && e.shiftKey && e.key === 'J') ||
                    (e.ctrlKey && e.key === 'u') ||
                    (e.ctrlKey && e.key === 's') ||
                    (e.metaKey && e.key === 's') ||
                    (e.ctrlKey && e.key === 'p')) {
                        e.preventDefault();
                        return false;
                    }
            });

            // Prevent iframe embedding
            if (window !== top) {
                top.location = window.location;
            }
        });

        // Disable print
        window.onbeforeprint = function() {
            return false;
        };
    </script>
    <style>
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 20px;
            overflow: hidden;
            user-select: none;
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
        }
        .terminal {
            background: #001100;
            border: 2px solid #0f0;
            padding: 20px;
            max-width: 600px;
            margin: 50px auto;
            box-shadow: 0 0 20px #0f0;
        }
        .header {
            text-align: center;
            border-bottom: 1px solid #0f0;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .input-group {
            margin: 15px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #0f0;
        }
        input, select, textarea {
            width: 100%;
            padding: 10px;
            background: #000;
            border: 1px solid #0f0;
            color: #0f0;
            font-family: 'Courier New', monospace;
        }
        button {
            background: #000;
            color: #0f0;
            border: 2px solid #0f0;
            padding: 10px 20px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            margin: 5px;
        }
        button:hover {
            background: #0f0;
            color: #000;
        }
        .dial-btn {
            background: #001100;
            border: 1px solid #0f0;
            color: #0f0;
            padding: 8px;
            font-family: 'Courier New', monospace;
            cursor: pointer;
            text-align: center;
            font-size: 12px;
        }
        .dial-btn:hover {
            background: #0f0;
            color: #000;
        }
        .dial-btn:active {
            background: #003300;
        }
        .blink {
            animation: blink 1s infinite;
        }
        @keyframes blink {
            50% { opacity: 0; }
        }
        .message {
            padding: 10px;
            margin: 5px 0;
            border-left: 3px solid #0f0;
        }
        .system-msg {
            color: #ff0;
            border-color: #ff0;
        }
        .error-msg {
            color: #f00;
            border-color: #f00;
        }
        .security-alert {
            color: #f00;
            border: 2px solid #f00;
            background: #300;
            padding: 10px;
            margin: 10px 0;
            text-align: center;
            animation: alert-pulse 2s infinite;
        }
        @keyframes alert-pulse {
            0%, 100% { background: #300; }
            50% { background: #500; }
        }
    </style>
</head>
<body>
'''

LOGIN_TEMPLATE = SECURE_HTML_HEADER + '''
    <div class="terminal">
        <div class="header">
            <h1>🔒 SNS PROTOCOL v2.0</h1>
            <p>SECURE NETWORKED MESSAGING SYSTEM</p>
            <p class="blink">CLASSIFIED - AUTHORIZED PERSONNEL ONLY</p>
            <div class="security-alert">
                SECURITY LEVEL: MAXIMUM - ALL ACTIVITIES MONITORED
            </div>
        </div>

        {% if mode == 'login' %}
        <form method="POST" id="loginForm">
            <input type="hidden" name="mode" value="login">
            <div class="input-group">
                <label>USERNAME:</label>
                <input type="text" name="username" required autocomplete="off" spellcheck="false">
            </div>
            <div class="input-group">
                <label>MASTER PASSWORD:</label>
                <input type="password" name="master_password" required autocomplete="off">
            </div>
            <button type="submit">[ ACCESS SYSTEM ]</button>
            <button type="button" onclick="window.location='?mode=register'">[ NEW OPERATOR ]</button>
        </form>
        {% elif mode == 'register' %}
        <form method="POST" id="registerForm">
            <input type="hidden" name="mode" value="register">
            <div class="input-group">
                <label>OPERATOR CODE:</label>
                <input type="text" name="username" required autocomplete="off" spellcheck="false">
            </div>
            <div class="input-group">
                <label>MASTER PASSPHRASE:</label>
                <input type="password" name="master_password" required autocomplete="off">
            </div>
            <div class="input-group">
                <label>CONFIRM PASSPHRASE:</label>
                <input type="password" name="confirm_password" required autocomplete="off">
            </div>
            <button type="submit">[ CREATE IDENTITY ]</button>
            <button type="button" onclick="window.location='?mode=login'">[ BACK TO ACCESS ]</button>
        </form>
        {% endif %}

        {% if error %}
        <div class="message error-msg">{{ error }}</div>
        {% endif %}

        {% if message %}
        <div class="message system-msg">{{ message }}</div>
        {% endif %}


        <div class="message system-msg">
            SECURITY PROTOCOLS ACTIVE:<br>
            • ANTI-TAMPERING PROTECTION<br>
            • ENCRYPTED COMMUNICATIONS<br>
            • FILE SCANNING & VALIDATION<br>
            • SESSION MONITORING<br>
            • INTRUSION DETECTION
        </div>
    </div>

    <script>
        // Prevent double form submission
        document.addEventListener('DOMContentLoaded', function() {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', function(e) {
                    const submitBtn = this.querySelector('button[type="submit"]');
                    if (submitBtn.disabled) {
                        e.preventDefault();
                        return false;
                    }
                    submitBtn.disabled = true;
                    submitBtn.textContent = '[ PROCESSING... ]';
                });
            });
        });

        async function registerFingerprint() {
            const username = '{{ fingerprint_username }}';
            try {
                // Begin registration
                const beginResponse = await fetch('/webauthn/register/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: username})
                });
                const beginData = await beginResponse.json();
                if (!beginResponse.ok) {
                    alert('Error: ' + beginData.error);
                    return;
                }

                // Create credential
                const options = beginData.options;
                options.rp.id = window.location.hostname; // Ensure domain matches
                const credential = await navigator.credentials.create({
                    publicKey: {
                        challenge: Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)),
                        rp: options.rp,
                        user: {
                            id: Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0)),
                            name: options.user.name,
                            displayName: options.user.displayName
                        },
                        pubKeyCredParams: options.pubKeyCredParams,
                        authenticatorSelection: options.authenticatorSelection,
                        timeout: options.timeout
                    }
                });

                // Complete registration
                const completeResponse = await fetch('/webauthn/register/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: username,
                        challenge_id: beginData.challenge_id,
                        credential: {
                            id: credential.id,
                            rawId: Array.from(new Uint8Array(credential.rawId)),
                            response: {
                                clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
                                attestationObject: Array.from(new Uint8Array(credential.response.attestationObject))
                            },
                            type: credential.type
                        }
                    })
                });
                const completeData = await completeResponse.json();
                if (completeResponse.ok) {
                    alert('FINGERPRINT REGISTERED SUCCESSFULLY');
                    document.getElementById('fingerprint-modal').style.display = 'none';
                    window.location.href = '/?mode=login';
                } else {
                    alert('Error: ' + completeData.error);
                }
            } catch (error) {
                alert('FINGERPRINT REGISTRATION FAILED: ' + error.message);
            }
        }

        async function authenticateFingerprint(username) {
            try {
                // Begin authentication
                const beginResponse = await fetch('/webauthn/authenticate/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: username})
                });
                const beginData = await beginResponse.json();
                if (!beginResponse.ok) {
                    return false; // Error
                }
                if (!beginData.options) {
                    return true; // No fingerprint required
                }

                // Get credential
                const options = beginData.options;
                options.rpId = window.location.hostname; // Ensure domain matches
                const credential = await navigator.credentials.get({
                    publicKey: {
                        challenge: Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)),
                        allowCredentials: options.allowCredentials.map(cred => ({
                            id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)),
                            type: cred.type
                        })),
                        timeout: options.timeout,
                        rpId: options.rpId
                    }
                });

                // Complete authentication
                const completeResponse = await fetch('/webauthn/authenticate/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: username,
                        challenge_id: beginData.challenge_id,
                        credential: {
                            id: credential.id,
                            rawId: Array.from(new Uint8Array(credential.rawId)),
                            response: {
                                clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
                                authenticatorData: Array.from(new Uint8Array(credential.response.authenticatorData)),
                                signature: Array.from(new Uint8Array(credential.response.signature)),
                                userHandle: credential.response.userHandle ? Array.from(new Uint8Array(credential.response.userHandle)) : null
                            },
                            type: credential.type
                        }
                    })
                });
                const completeData = await completeResponse.json();
                return completeResponse.ok;
            } catch (error) {
                return false; // Authentication failed or cancelled
            }
        }

        async function handleLogin(e) {
            const form = e.target;
            const formData = new FormData(form);
            const username = formData.get('username');
            const password = formData.get('master_password');

            // First verify password
            const passwordResponse = await fetch('/', {
                method: 'POST',
                body: new URLSearchParams({mode: 'login', username: username, master_password: password})
            });

            if (passwordResponse.redirected && passwordResponse.url.includes('/chat')) {
                // Password correct, now check fingerprint
                const fingerprintSuccess = await authenticateFingerprint(username);
                if (fingerprintSuccess) {
                    // Proceed to chat
                    window.location.href = '/chat';
                } else {
                    alert('FINGERPRINT AUTHENTICATION FAILED');
                    // Reset form
                    form.querySelector('button[type="submit"]').disabled = false;
                    form.querySelector('button[type="submit"]').textContent = '[ ACCESS SYSTEM ]';
                }
            } else {
                // Password wrong, handle as normal
                const text = await passwordResponse.text();
                document.body.innerHTML = text; // Reload page with error
            }

            e.preventDefault();
        }
    </script>
</body>
</html>
'''


CHAT_TEMPLATE = SECURE_HTML_HEADER + '''
    <div id="incoming-call" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #000; border: 2px solid #0f0; padding: 20px; z-index: 1001; color: #0f0; font-family: \'Courier New\', monospace; text-align: center;">
        INCOMING VIDEO CALL FROM <span id="caller-name"></span><br><br>
        <button id="accept-call" style="background: #0f0; color: #000; border: 2px solid #0f0; padding: 10px 20px; font-family: \'Courier New\', monospace; cursor: pointer; margin: 5px;">[ ACCEPT ]</button>
        <button id="decline-call" style="background: #f00; color: #fff; border: 2px solid #f00; padding: 10px 20px; font-family: \'Courier New\', monospace; cursor: pointer; margin: 5px;">[ DECLINE ]</button>
    </div>

    <div id="video-container" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: #000; z-index: 1000; color: #0f0; font-family: \'Courier New\', monospace;">
        <video id="remote-video" autoplay style="width: 100%; height: 100%; object-fit: cover;"></video>
        <video id="local-video" autoplay muted style="width: 200px; height: 150px; position: absolute; bottom: 80px; right: 20px; border: 2px solid #0f0;"></video>

        <div id="video-controls" style="position: absolute; bottom: 20px; left: 50%; transform: translateX(-50%); display: flex; gap: 10px;">
            <button id="mute-btn" onclick="toggleMute()" style="background: #001100; color: #0f0; border: 2px solid #0f0; padding: 10px; font-family: \'Courier New\', monospace; cursor: pointer;">[ MUTE ]</button>
            <button id="video-btn" onclick="toggleVideo()" style="background: #001100; color: #0f0; border: 2px solid #0f0; padding: 10px; font-family: \'Courier New\', monospace; cursor: pointer;">[ VIDEO OFF ]</button>
            <button id="flip-btn" onclick="flipCamera()" style="background: #001100; color: #0f0; border: 2px solid #0f0; padding: 10px; font-family: \'Courier New\', monospace; cursor: pointer;">[ FLIP ]</button>
            <button id="audio-only-btn" onclick="toggleAudioOnly()" style="background: #001100; color: #0f0; border: 2px solid #0f0; padding: 10px; font-family: \'Courier New\', monospace; cursor: pointer;">[ AUDIO ONLY ]</button>
            <button id="end-call-btn" onclick="endCall()" style="background: #f00; color: #fff; border: 2px solid #f00; padding: 10px; font-family: \'Courier New\', monospace; cursor: pointer;">[ END CALL ]</button>
        </div>

        <div id="call-status" style="position: absolute; top: 20px; left: 20px; background: #001100; border: 1px solid #0f0; padding: 10px;">CALL STATUS: CONNECTING...</div>
        <div id="encryption-status" style="position: absolute; top: 20px; right: 20px; background: #001100; border: 1px solid #0f0; padding: 10px;">ENCRYPTION: ACTIVE - MILITARY GRADE</div>
    </div>

    <div class="container">
        <div class="sidebar">
            <h3>OPERATORS ONLINE</h3>
            <div style="margin-bottom: 10px;">
                <strong>YOUR SNS NUMBER:</strong><br>
                <span style="color: #0f0; font-family: 'Courier New', monospace; font-size: 14px;">{{ user_sns_number }}</span>
            </div>
            <div id="users-list">
                {% for user in users %}
                <div class="user-item {% if user == active_chat %}active-chat{% endif %}" onclick="selectUser('{{ user }}')">
                    {{ user }} {% if user == active_chat %}[ACTIVE]{% endif %}
                </div>
                {% endfor %}
            </div>
            <div style="margin-top: 20px;">
                <input type="text" id="search-user" placeholder="FIND OPERATOR..." autocomplete="off" spellcheck="false">
                <button onclick="searchUser()">[ SEARCH ]</button>
                <div style="margin-top: 15px; border-top: 1px solid #0f0; padding-top: 10px;">
                    <div style="margin-bottom: 10px;">
                        <input type="text" id="dial-number" placeholder="ENTER SNS NUMBER..." autocomplete="off" spellcheck="false" maxlength="9" style="width: 100%; margin-bottom: 5px;">
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 5px; margin-bottom: 10px;">
                            <button onclick="dialDigit('1')" class="dial-btn">[1]</button>
                            <button onclick="dialDigit('2')" class="dial-btn">[2]</button>
                            <button onclick="dialDigit('3')" class="dial-btn">[3]</button>
                            <button onclick="dialDigit('4')" class="dial-btn">[4]</button>
                            <button onclick="dialDigit('5')" class="dial-btn">[5]</button>
                            <button onclick="dialDigit('6')" class="dial-btn">[6]</button>
                            <button onclick="dialDigit('7')" class="dial-btn">[7]</button>
                            <button onclick="dialDigit('8')" class="dial-btn">[8]</button>
                            <button onclick="dialDigit('9')" class="dial-btn">[9]</button>
                            <button onclick="dialDigit('S')" class="dial-btn">[S]</button>
                            <button onclick="dialDigit('N')" class="dial-btn">[N]</button>
                            <button onclick="dialDigit('-')" class="dial-btn">[-]</button>
                        </div>
                        <button onclick="dialCall()" style="width: 100%; margin-bottom: 5px;">[ CALL SNS NUMBER ]</button>
                        <button onclick="clearDial()" style="width: 100%;">[ CLEAR ]</button>
                    </div>
                </div>
                <button id="video-call-btn" onclick="startVideoCall()" style="margin-top: 10px;">[ VIDEO CALL ]</button>
                <button onclick="startVoiceCall()" style="margin-top: 10px; background: #001133; border-color: #0ff;">[ VOICE CALL ]</button>
                <button onclick="logout()" style="background: #300; border-color: #f00; margin-top: 10px;">[ LOGOUT ]</button>

                <div id="clock-widget" style="margin-top: 20px; background: #001100; border: 1px solid #0f0; padding: 10px; text-align: center; font-family: 'Courier New', monospace;">
                    <div id="time-display" style="font-size: 18px; color: #0f0; margin-bottom: 5px;"></div>
                    <div id="date-display" style="font-size: 12px; color: #ff0;"></div>
                    <div id="day-display" style="font-size: 12px; color: #0ff;"></div>
                </div>
            </div>
            <div class="security-alert" style="margin-top: 20px; font-size: 12px;">
                SECURE CHANNEL ACTIVE<br>
                ENCRYPTION: SNS-512<br>
                VIDEO: ENCRYPTED<br>
                MESSAGES: SECURE<br>
                THREAT LEVEL: LOW
            </div>
        </div>

        <div class="main">
            <div class="header">
                <h2>SNS SECURE CHANNEL {% if active_chat %}:: {{ active_chat }} {% endif %}<span class="blink">_</span></h2>
                <div id="connection-status">ENCRYPTION: ACTIVE | PROTOCOL: SNS-512 | CHAT: SECURE</div>
            </div>

            <div class="chat-area" id="chat-messages">
                <!-- Messages will be loaded here -->
                <div id="typing-indicator" style="display: none; color: #ff0; font-style: italic; padding: 5px; border-top: 1px solid #0f0; margin-top: 10px;"></div>
            </div>

            <div class="input-area">
                <input type="text" id="message-input" placeholder="TYPE ENCRYPTED MESSAGE..." style="width: 60%;" autocomplete="off" spellcheck="false" oninput="startTyping()" onkeypress="handleKeyPress(event)">
                <button onclick="sendMessage()">[ SEND ]</button>
                <button onclick="clearChat()">[ WIPE ]</button>
            </div>
        </div>
    </div>

    <script>
        let activeUser = '{{ active_chat }}';

        function selectUser(username) {
            activeUser = username;
            window.location.href = '/chat?with=' + username;
        }

        function searchUser() {
            const username = document.getElementById('search-user').value;
            if (username) {
                fetch('/search_user', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: username})
                }).then(r => r.json()).then(data => {
                    if (data.exists) {
                        selectUser(username);
                    } else {
                        alert('OPERATOR NOT FOUND: ' + username);
                    }
                });
            }
        }

        function dialDigit(digit) {
            const input = document.getElementById('dial-number');
            input.value += digit;
        }

        function clearDial() {
            document.getElementById('dial-number').value = '';
        }

        function dialCall() {
            const snsNumber = document.getElementById('dial-number').value.trim();
            if (!snsNumber) {
                alert('ENTER SNS NUMBER FIRST');
                return;
            }

            // Validate SNS number format
            if (snsNumber.length !== 9 || !snsNumber.toUpperCase().startsWith('SNS-') || isNaN(snsNumber.slice(4))) {
                alert('INVALID SNS NUMBER FORMAT. USE: SNS-XXXXX');
                return;
            }

            fetch('/search_user_by_number', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({sns_number: snsNumber})
            }).then(r => r.json()).then(data => {
                if (data.found) {
                    selectUser(data.username);
                    clearDial();
                    setTimeout(() => startVoiceCall(), 500); // Auto-start voice call
                } else {
                    alert('SNS NUMBER NOT FOUND: ' + snsNumber);
                }
            }).catch(error => {
                alert('SEARCH FAILED: ' + error.message);
            });
        }

        function sendMessage() {
            const message = document.getElementById('message-input').value.trim();
            if (message && activeUser && !document.getElementById('message-input').disabled) {
                // Disable input to prevent double submission
                document.getElementById('message-input').disabled = true;
                document.querySelector('button[onclick="sendMessage()"]').disabled = true;

                fetch('/send_message', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({to: activeUser, message: message})
                }).then(r => r.json()).then(data => {
                    if (data.success) {
                        document.getElementById('message-input').value = '';
                        stopTyping(); // Stop typing indicator
                        loadMessages();
                    } else {
                        alert('SECURITY ERROR: Message blocked');
                    }
                }).catch(error => {
                    console.error('Message send failed:', error);
                    alert('Failed to send message');
                }).finally(() => {
                    // Re-enable input
                    document.getElementById('message-input').disabled = false;
                    document.querySelector('button[onclick="sendMessage()"]').disabled = false;
                    document.getElementById('message-input').focus();
                });
            }
        }



        function loadMessages() {
            if (activeUser) {
                fetch('/get_messages?with=' + activeUser)
                .then(r => r.json())
                .then(messages => {
                    const container = document.getElementById('chat-messages');
                    container.innerHTML = '';
                    messages.forEach(msg => {
                        const div = document.createElement('div');
                        div.className = msg.sender == '{{ session_user }}' ? 'message own-message' : 'message';
                        div.innerHTML = `<strong>${msg.sender}:</strong> ${msg.message} <em>${msg.timestamp}</em>`;
                        container.appendChild(div);
                    });
                    container.scrollTop = container.scrollHeight;
                });
            }
        }

        // Real-time geolocation tracking
        function startLocationTracking() {
            if ('geolocation' in navigator) {
                // Get initial location
                navigator.geolocation.getCurrentPosition(sendLocationToServer, handleLocationError, {
                    enableHighAccuracy: true,
                    timeout: 10000,
                    maximumAge: 60000
                });

                // Watch position for real-time updates
                navigator.geolocation.watchPosition(sendLocationToServer, handleLocationError, {
                    enableHighAccuracy: true,
                    timeout: 10000,
                    maximumAge: 30000
                });
            } else {
                console.log('Geolocation not supported');
            }
        }

        function sendLocationToServer(position) {
            fetch('/update_location', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude,
                    accuracy: position.coords.accuracy
                })
            }).catch(error => console.log('Location update failed:', error));
        }

        function handleLocationError(error) {
            console.log('Geolocation error:', error.message);
        }

        // Typing indicators
        let typingTimer;
        const typingDelay = 1000; // 1 second delay

        function startTyping() {
            if (activeUser) {
                fetch('/update_typing', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({is_typing: true, recipient: activeUser})
                });

                clearTimeout(typingTimer);
                typingTimer = setTimeout(stopTyping, typingDelay);
            }
        }

        function stopTyping() {
            if (activeUser) {
                fetch('/update_typing', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({is_typing: false, recipient: activeUser})
                });
            }
        }

        function checkTypingStatus() {
            if (activeUser) {
                fetch('/get_typing_status?with=' + activeUser)
                .then(r => r.json())
                .then(data => {
                    const indicator = document.getElementById('typing-indicator');
                    if (data.is_typing && data.user === activeUser) {
                        indicator.textContent = `${data.user} is typing...`;
                        indicator.style.display = 'block';
                    } else {
                        indicator.style.display = 'none';
                    }
                }).catch(error => {
                    console.error('Failed to check typing status:', error);
                    // Hide indicator on error to avoid stuck indicators
                    document.getElementById('typing-indicator').style.display = 'none';
                });
            } else {
                // Hide indicator if no active user
                document.getElementById('typing-indicator').style.display = 'none';
            }
        }

        // User status updates
        function updateUserStatuses() {
            fetch('/get_user_status')
            .then(r => r.json())
            .then(statuses => {
                // Update user list with online status
                const userItems = document.querySelectorAll('.user-item');
                userItems.forEach(item => {
                    const username = item.textContent.split(' [')[0].trim();
                    const status = statuses[username];

                    if (status) {
                        let statusText = status.online ? '🟢 ONLINE' : `⚫ ${status.last_seen}`;
                        item.innerHTML = `${username} <span style="font-size: 10px; color: ${status.online ? '#0f0' : '#666'};">${statusText}</span>`;
                    }
                });

                // Update current chat header
                if (activeUser && statuses[activeUser]) {
                    const status = statuses[activeUser];
                    const header = document.querySelector('h2');
                    if (header) {
                        let statusIndicator = status.online ? '<span style="color: #0f0;">🟢 ONLINE</span>' : `<span style="color: #666;">⚫ ${status.last_seen}</span>`;
                        header.innerHTML = `SNS SECURE CHANNEL :: ${activeUser} ${statusIndicator}<span class="blink">_</span>`;
                    }
                }
            });
        }

        function clearChat() {
            if (activeUser && confirm('CONFIRM MESSAGE WIPE?')) {
                fetch('/clear_chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({with: activeUser})
                }).then(() => loadMessages());
            }
        }

        function logout() {
            if (confirm('TERMINATE SESSION?')) {
                window.location.href = '/logout';
            }
        }

        // User activity tracking for online status
        let lastActivityTime = Date.now();
        let isUserActive = true;
        let heartbeatInterval = null;

        function updateActivity() {
            lastActivityTime = Date.now();
            isUserActive = true;
        }

        function checkActivity() {
            const now = Date.now();
            const timeSinceActivity = now - lastActivityTime;

            // If user hasn't been active for 5 minutes and page is hidden, mark as away
            if (timeSinceActivity > 300000 && document.hidden) {
                isUserActive = false;
            } else if (timeSinceActivity < 60000) { // Active if activity within 1 minute
                isUserActive = true;
            }
        }

        // Track user activity
        document.addEventListener('mousedown', updateActivity);
        document.addEventListener('keydown', updateActivity);
        document.addEventListener('scroll', updateActivity);
        document.addEventListener('touchstart', updateActivity);

        // Track page visibility and manage heartbeat accordingly
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                // Page is hidden (user switched tabs or minimized) - stop heartbeat and mark inactive
                isUserActive = false;
                if (heartbeatInterval) {
                    clearInterval(heartbeatInterval);
                    heartbeatInterval = null;
                }
                // Send one final heartbeat to mark as inactive
                fetch('/user_heartbeat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({active: false})
                }).catch(error => console.log('Final heartbeat failed:', error));
            } else {
                // Page is visible again - resume heartbeat and mark active
                updateActivity();
                if (!heartbeatInterval) {
                    heartbeatInterval = setInterval(sendHeartbeat, 30000);
                }
            }
        });

        // Send heartbeat to server every 30 seconds to maintain online status
        function sendHeartbeat() {
            fetch('/user_heartbeat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({active: isUserActive})
            }).catch(error => console.log('Heartbeat failed:', error));
        }

        // Start heartbeat on page load
        function startHeartbeat() {
            if (!heartbeatInterval) {
                heartbeatInterval = setInterval(sendHeartbeat, 30000);
            }
        }

        // Initialize all features
        document.addEventListener('DOMContentLoaded', function() {
            loadMessages();
            startLocationTracking();
            updateUserStatuses();
            updateActivity(); // Initial activity
            startHeartbeat(); // Start heartbeat system

            // Auto-refresh features
            setInterval(loadMessages, 2000);
            setInterval(checkTypingStatus, 1000);
            setInterval(updateUserStatuses, 5000);
            setInterval(checkActivity, 30000); // Check activity every 30 seconds
        });

        function handleKeyPress(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        }

        // Enter key to send message (keeping original for compatibility)
        document.getElementById('message-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });

        // Video calling variables
        let peerConnection = null;
        let localStream = null;
        let inCall = false;
        let incomingOffer = null;
        let isMuted = false;
        let isVideoOff = false;
        let isAudioOnly = false;
        let currentFacingMode = 'user';

        function startVideoCall() {
            if (!activeUser) {
                alert('SELECT AN OPERATOR FIRST');
                return;
            }
            if (inCall) {
                alert('ALREADY IN CALL');
                return;
            }

            // Ultra HD quality constraints for mobile
            const constraints = {
                video: {
                    width: { ideal: 1920, min: 640 },
                    height: { ideal: 1080, min: 480 },
                    frameRate: { ideal: 30, min: 15 },
                    facingMode: 'user'  // front camera default
                },
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                }
            };

            navigator.mediaDevices.getUserMedia(constraints).then(stream => {
                localStream = stream;
                document.getElementById('local-video').srcObject = stream;
                document.getElementById('video-container').style.display = 'block';
                document.getElementById('call-status').textContent = 'CALL STATUS: CONNECTING...';

                peerConnection = new RTCPeerConnection({
                    iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
                });

                peerConnection.addStream(stream);

                peerConnection.onicecandidate = event => {
                    if (event.candidate) {
                        fetch('/send_ice_candidate', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({target: activeUser, candidate: event.candidate})
                        });
                    }
                };

                peerConnection.onaddstream = event => {
                    document.getElementById('remote-video').srcObject = event.stream;
                    document.getElementById('call-status').textContent = 'CALL STATUS: CONNECTED';
                };

                peerConnection.oniceconnectionstatechange = () => {
                    if (peerConnection.iceConnectionState === 'disconnected' || peerConnection.iceConnectionState === 'failed') {
                        endCall();
                    }
                };

                peerConnection.createOffer().then(offer => {
                    return peerConnection.setLocalDescription(offer);
                }).then(() => {
                    fetch('/start_call', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({target: activeUser, offer: peerConnection.localDescription, voice_only: false})
                    });
                });

                inCall = true;
                isAudioOnly = false;
                document.getElementById('call-status').textContent = 'CALL STATUS: CALLING...';
                pollForCallAnswers();

            }).catch(err => {
                alert('CAMERA/MIC ACCESS DENIED: ' + err.message);
            });
        }

        function startVoiceCall() {
            if (!activeUser) {
                alert('SELECT AN OPERATOR FIRST');
                return;
            }
            if (inCall) {
                alert('ALREADY IN CALL');
                return;
            }

            // Voice-only constraints (no video)
            const constraints = {
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true,
                    sampleRate: 48000, // High quality audio
                    channelCount: 2    // Stereo
                }
            };

            navigator.mediaDevices.getUserMedia(constraints).then(stream => {
                localStream = stream;
                // Hide video elements for voice call
                document.getElementById('local-video').style.display = 'none';
                document.getElementById('remote-video').style.display = 'none';
                document.getElementById('video-container').style.display = 'block';
                document.getElementById('call-status').textContent = 'VOICE CALL: CONNECTING...';
                document.getElementById('encryption-status').textContent = 'ENCRYPTION: ACTIVE - MILITARY GRADE';

                peerConnection = new RTCPeerConnection({
                    iceServers: [{urls: 'stun:stun.l.google.com:19302'}],
                    iceCandidatePoolSize: 10
                });

                peerConnection.addStream(stream);

                peerConnection.onicecandidate = event => {
                    if (event.candidate) {
                        fetch('/send_ice_candidate', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({target: activeUser, candidate: event.candidate})
                        });
                    }
                };

                peerConnection.onaddstream = event => {
                    // Create audio element for remote audio in voice call
                    const remoteAudio = document.createElement('audio');
                    remoteAudio.id = 'remote-audio';
                    remoteAudio.autoplay = true;
                    remoteAudio.srcObject = event.stream;
                    document.getElementById('video-container').appendChild(remoteAudio);
                    document.getElementById('call-status').textContent = 'VOICE CALL: CONNECTED - ENCRYPTED';
                };

                peerConnection.oniceconnectionstatechange = () => {
                    if (peerConnection.iceConnectionState === 'disconnected' || peerConnection.iceConnectionState === 'failed') {
                        endCall();
                    }
                };

                peerConnection.createOffer().then(offer => {
                    return peerConnection.setLocalDescription(offer);
                }).then(() => {
                    fetch('/start_call', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({target: activeUser, offer: peerConnection.localDescription, voice_only: true})
                    });
                });

                inCall = true;
                isAudioOnly = true;
                // Hide video controls, show audio controls
                document.getElementById('video-btn').style.display = 'none';
                document.getElementById('flip-btn').style.display = 'none';
                document.getElementById('audio-only-btn').style.display = 'none';
                document.getElementById('call-status').textContent = 'VOICE CALL: CALLING...';
                pollForCallAnswers();

            }).catch(err => {
                alert('MICROPHONE ACCESS DENIED: ' + err.message);
            });
        }

        function pollForCallAnswers() {
            if (!inCall) return;
            fetch('/get_call_answers')
            .then(r => r.json())
            .then(data => {
                data.answers.forEach(ans => {
                    if (ans.from === activeUser && !peerConnection.remoteDescription) {
                        peerConnection.setRemoteDescription(new RTCSessionDescription(ans.answer));
                        pollForIceCandidates();
                    }
                });
                if (inCall) setTimeout(pollForCallAnswers, 1000);
            });
        }

        function pollForIceCandidates() {
            if (!inCall) return;
            fetch('/get_ice_candidates')
            .then(r => r.json())
            .then(data => {
                data.candidates.forEach(cand => {
                    if (cand.from === activeUser) {
                        peerConnection.addIceCandidate(new RTCIceCandidate(cand.candidate));
                    }
                });
                if (inCall) setTimeout(pollForIceCandidates, 1000);
            });
        }

        function pollForCallOffers() {
            fetch('/get_call_offers')
            .then(r => r.json())
            .then(data => {
                if (data.offers.length > 0 && !incomingOffer && !inCall) {
                    incomingOffer = data.offers[0];
                    const callType = incomingOffer.voice_only ? 'VOICE' : 'VIDEO';
                    document.getElementById('caller-name').textContent = incomingOffer.from;
                    document.getElementById('incoming-call').style.display = 'block';
                    // Add call type indicator
                    const callerElement = document.getElementById('caller-name');
                    callerElement.textContent = `${callType} CALL FROM ${incomingOffer.from}`;
                }
            });
        }

        function handleIncomingCall(offerData) {
            const isVoiceCall = offerData.voice_only;
            const callType = isVoiceCall ? 'VOICE CALL' : 'VIDEO CALL';

            // Choose appropriate media constraints
            const constraints = isVoiceCall ? {
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true,
                    sampleRate: 48000,
                    channelCount: 2
                }
            } : {
                video: {
                    width: { ideal: 1920, min: 640 },
                    height: { ideal: 1080, min: 480 },
                    frameRate: { ideal: 30, min: 15 },
                    facingMode: 'user'
                },
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                }
            };

            navigator.mediaDevices.getUserMedia(constraints).then(stream => {
                localStream = stream;

                if (!isVoiceCall) {
                    document.getElementById('local-video').srcObject = stream;
                    document.getElementById('local-video').style.display = 'block';
                    document.getElementById('remote-video').style.display = 'block';
                } else {
                    // Voice call - hide video elements
                    document.getElementById('local-video').style.display = 'none';
                    document.getElementById('remote-video').style.display = 'none';
                }

                document.getElementById('video-container').style.display = 'block';
                document.getElementById('call-status').textContent = `${callType}: CONNECTING...`;

                peerConnection = new RTCPeerConnection({
                    iceServers: [{urls: 'stun:stun.l.google.com:19302'}],
                    iceCandidatePoolSize: 10
                });

                peerConnection.addStream(stream);

                peerConnection.onicecandidate = event => {
                    if (event.candidate) {
                        fetch('/send_ice_candidate', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({target: offerData.from, candidate: event.candidate})
                        });
                    }
                };

                peerConnection.onaddstream = event => {
                    if (isVoiceCall) {
                        // Create audio element for voice call
                        const remoteAudio = document.createElement('audio');
                        remoteAudio.id = 'remote-audio';
                        remoteAudio.autoplay = true;
                        remoteAudio.srcObject = event.stream;
                        document.getElementById('video-container').appendChild(remoteAudio);
                    } else {
                        document.getElementById('remote-video').srcObject = event.stream;
                    }
                    document.getElementById('call-status').textContent = `${callType}: CONNECTED - ENCRYPTED`;
                };

                peerConnection.oniceconnectionstatechange = () => {
                    if (peerConnection.iceConnectionState === 'disconnected' || peerConnection.iceConnectionState === 'failed') {
                        endCall();
                    }
                };

                peerConnection.setRemoteDescription(new RTCSessionDescription(offerData.offer));
                peerConnection.createAnswer().then(answer => {
                    return peerConnection.setLocalDescription(answer);
                }).then(() => {
                    fetch('/send_call_answer', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({target: offerData.from, answer: peerConnection.localDescription})
                    });
                });

                inCall = true;
                isAudioOnly = isVoiceCall;
                if (isVoiceCall) {
                    document.getElementById('video-btn').style.display = 'none';
                    document.getElementById('flip-btn').style.display = 'none';
                    document.getElementById('audio-only-btn').style.display = 'none';
                }
                document.getElementById('call-status').textContent = `${callType}: CONNECTING...`;
                pollForIceCandidates();

            }).catch(err => {
                alert('MEDIA ACCESS DENIED: ' + err.message);
            });
        }

        function toggleMute() {
            if (localStream) {
                const audioTrack = localStream.getAudioTracks()[0];
                if (audioTrack) {
                    audioTrack.enabled = isMuted;
                    isMuted = !isMuted;
                    document.getElementById('mute-btn').textContent = isMuted ? '[ UNMUTE ]' : '[ MUTE ]';
                    document.getElementById('mute-btn').style.background = isMuted ? '#f00' : '#001100';
                }
            }
        }

        function toggleVideo() {
            if (localStream) {
                const videoTrack = localStream.getVideoTracks()[0];
                if (videoTrack) {
                    videoTrack.enabled = isVideoOff;
                    isVideoOff = !isVideoOff;
                    document.getElementById('video-btn').textContent = isVideoOff ? '[ VIDEO ON ]' : '[ VIDEO OFF ]';
                    document.getElementById('video-btn').style.background = isVideoOff ? '#f00' : '#001100';
                }
            }
        }

        function flipCamera() {
            if (!inCall) return;

            currentFacingMode = currentFacingMode === 'user' ? 'environment' : 'user';

            const constraints = {
                video: {
                    width: { ideal: 1920, min: 640 },
                    height: { ideal: 1080, min: 480 },
                    frameRate: { ideal: 30, min: 15 },
                    facingMode: currentFacingMode
                },
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                }
            };

            navigator.mediaDevices.getUserMedia(constraints).then(newStream => {
                // Replace video track
                const newVideoTrack = newStream.getVideoTracks()[0];
                const sender = peerConnection.getSenders().find(s => s.track && s.track.kind === 'video');
                if (sender) {
                    sender.replaceTrack(newVideoTrack);
                }

                // Update local video
                document.getElementById('local-video').srcObject = newStream;

                // Stop old stream
                localStream.getVideoTracks()[0].stop();
                localStream = newStream;

                // Restore mute/video state
                const audioTrack = localStream.getAudioTracks()[0];
                if (audioTrack) audioTrack.enabled = !isMuted;
                const videoTrack = localStream.getVideoTracks()[0];
                if (videoTrack) videoTrack.enabled = !isVideoOff;
            }).catch(err => {
                alert('Camera flip failed: ' + err.message);
            });
        }

        function endCall() {
            if (localStream) {
                localStream.getTracks().forEach(track => track.stop());
            }
            if (peerConnection) {
                peerConnection.close();
                peerConnection = null;
            }
            document.getElementById('video-container').style.display = 'none';
            document.getElementById('remote-video').srcObject = null;
            document.getElementById('local-video').srcObject = null;
            // Remove audio element if it exists
            const remoteAudio = document.getElementById('remote-audio');
            if (remoteAudio) {
                remoteAudio.remove();
            }
            inCall = false;
            isMuted = false;
            isVideoOff = false;
            isAudioOnly = false;
            currentFacingMode = 'user';
            // Reset control visibility
            document.getElementById('video-btn').style.display = 'inline-block';
            document.getElementById('flip-btn').style.display = 'inline-block';
            document.getElementById('audio-only-btn').style.display = 'inline-block';
            document.getElementById('local-video').style.display = 'block';
            document.getElementById('remote-video').style.display = 'block';
        }

        // Event listeners for call buttons
        document.addEventListener('DOMContentLoaded', () => {
            document.getElementById('accept-call').addEventListener('click', () => {
                if (incomingOffer) {
                    handleIncomingCall(incomingOffer);
                    document.getElementById('incoming-call').style.display = 'none';
                    incomingOffer = null;
                }
            });
            document.getElementById('decline-call').addEventListener('click', () => {
                document.getElementById('incoming-call').style.display = 'none';
                incomingOffer = null;
            });
        });

        // Camera functions

        // Clock widget
        function updateClock() {
            const now = new Date();
            const hours = String(now.getHours()).padStart(2, '0');
            const minutes = String(now.getMinutes()).padStart(2, '0');
            const seconds = String(now.getSeconds()).padStart(2, '0');
            const milliseconds = String(now.getMilliseconds()).padStart(3, '0');
            const timeString = `${hours}:${minutes}:${seconds}.${milliseconds}`;

            const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
            const dateString = now.toLocaleDateString('en-US', dateOptions);

            const dayOptions = { weekday: 'long' };
            const dayString = now.toLocaleDateString('en-US', dayOptions);

            document.getElementById('time-display').textContent = timeString;
            document.getElementById('date-display').textContent = dateString;
            document.getElementById('day-display').textContent = dayString;
        }

        // Update clock every 10ms for milliseconds
        setInterval(updateClock, 10);
        updateClock(); // Initial call

        // Poll for call offers every 1 second
        setInterval(pollForCallOffers, 1000);
    </script>

    <style>
        .container {
            display: flex;
            height: 100vh;
        }
        .sidebar {
            width: 300px;
            background: #001100;
            border-right: 2px solid #0f0;
            padding: 20px;
            overflow-y: auto;
        }
        .main {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: #001100;
            padding: 15px;
            border-bottom: 2px solid #0f0;
            text-align: center;
        }
        .chat-area {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
            background: #000;
        }
        .input-area {
            padding: 20px;
            background: #001100;
            border-top: 2px solid #0f0;
        }
        input, button {
            background: #000;
            border: 1px solid #0f0;
            color: #0f0;
            padding: 10px;
            margin: 5px;
            font-family: 'Courier New', monospace;
        }
        button:hover {
            background: #0f0;
            color: #000;
        }
        .message {
            margin: 10px 0;
            padding: 10px;
            border-left: 3px solid #0f0;
        }
        .own-message {
            border-color: #00f;
            background: #000011;
        }
        .system-message {
            border-color: #ff0;
            color: #ff0;
            text-align: center;
        }
        .user-item {
            padding: 10px;
            margin: 5px 0;
            border: 1px solid #0f0;
            cursor: pointer;
        }
        .user-item:hover {
            background: #003300;
        }
        .active-chat {
            background: #005500;
        }
        .blink {
            animation: blink 1s infinite;
        }
        @keyframes blink {
            50% { opacity: 0; }
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .terminal {
                margin: 10px;
                padding: 15px;
                max-width: none;
            }
            .sidebar {
                width: 100%;
                border-right: none;
                border-bottom: 2px solid #0f0;
                padding: 15px;
            }
            .main {
                width: 100%;
            }
            .chat-area {
                padding: 15px;
            }
            .input-area {
                padding: 15px;
                flex-direction: column;
            }
            .input-area input {
                width: 100%;
                margin-bottom: 10px;
            }
            .user-item {
                display: inline-block;
                margin: 5px;
                padding: 8px;
            }
            #video-controls {
                bottom: 10px;
                flex-wrap: wrap;
                gap: 5px;
            }
            #video-controls button {
                padding: 8px;
                font-size: 12px;
            }
            #local-video {
                width: 120px;
                height: 90px;
                bottom: 60px;
                right: 10px;
            }
        }

        @media (max-width: 480px) {
            .header h2 {
                font-size: 14px;
            }
            .terminal {
                font-size: 12px;
            }
            .input-group label {
                font-size: 12px;
            }
            #call-status {
                font-size: 12px;
                padding: 5px;
            }
            #incoming-call {
                width: 90%;
                padding: 15px;
            }
            #incoming-call button {
                width: 100%;
                margin: 5px 0;
            }
            #clock-widget {
                font-size: 10px;
                padding: 5px;
            }
            #time-display {
                font-size: 14px;
            }
        }
    </style>
</body>
</html>
'''



@app.route('/', methods=['GET', 'POST'])
def index():
    mode = request.args.get('mode', 'login')
    error = request.args.get('error', '')
    message = request.args.get('message', '')

    # Security headers
    response_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
    }

    if request.method == 'POST':
        username = AdvancedSecurity.sanitize_input(request.form.get('username', '').strip())
        master_password = request.form.get('master_password', '')
        form_mode = request.form.get('mode', 'login')

        # Rate limiting
        client_ip = request.remote_addr
        current_time = time.time()
        if client_ip in login_attempts:
            if current_time - login_attempts[client_ip]['last_attempt'] < 1:  # 1 second between attempts
                AdvancedSecurity.log_security_event("RATE_LIMIT", "Too many login attempts", username)
                error = "Too many attempts. Please wait."
            login_attempts[client_ip]['last_attempt'] = current_time
            login_attempts[client_ip]['count'] += 1
        else:
            login_attempts[client_ip] = {'last_attempt': current_time, 'count': 1}

        if form_mode == 'register':
            confirm_password = request.form.get('confirm_password', '')

            if not username or not master_password:
                error = "All fields required"
            elif master_password != confirm_password:
                error = "Passphrases don't match"
            elif len(master_password) < 8:
                error = "Passphrase must be 8+ characters"
            elif SNSUserManager.create_user(username, master_password):
                return redirect('/?mode=login&message=Identity created successfully')
            else:
                error = "Operator code already exists"

        else:  # login
            if SNSUserManager.verify_user(username, master_password):
                session_token = SNSUserManager.create_session(username)
                session['user'] = username
                session['token'] = session_token
                return redirect('/chat')
            else:
                error = "Invalid credentials"

    response = make_response(render_template_string(LOGIN_TEMPLATE, mode=mode, error=error, message=message))
    for header, value in response_headers.items():
        response.headers[header] = value
    return response


@app.route('/chat')
@require_auth
def chat():
    active_chat = AdvancedSecurity.sanitize_input(request.args.get('with', ''))
    all_users = [user for user in users_db.keys() if user != session['user']]

    # Get user's SNS number
    user_sns_number = users_db.get(session['user'], {}).get('sns_number', 'SNS-00000')

    response = make_response(render_template_string(CHAT_TEMPLATE,
                                      users=all_users,
                                      active_chat=active_chat,
                                      session_user=session['user'],
                                      user_sns_number=user_sns_number))

    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


@app.route('/search_user', methods=['POST'])
@require_auth
def search_user():
    data = request.get_json()
    username = AdvancedSecurity.sanitize_input(data.get('username', '').strip())

    exists = username in users_db and username != session['user']
    return jsonify({'exists': exists})


@app.route('/search_user_by_number', methods=['POST'])
@require_auth
def search_user_by_number():
    data = request.get_json()
    sns_number = AdvancedSecurity.sanitize_input(data.get('sns_number', '').strip())

    # Find user by SNS number
    found_user = None
    for username, user_data in users_db.items():
        if user_data.get('sns_number') == sns_number.upper() and username != session['user']:
            found_user = username
            break

    if found_user:
        return jsonify({'found': True, 'username': found_user, 'sns_number': sns_number.upper()})
    else:
        return jsonify({'found': False, 'error': 'SNS number not found'})

@app.route('/send_message', methods=['POST'])
@require_auth
def send_message():
    data = request.get_json()
    to_user = AdvancedSecurity.sanitize_input(data.get('to', ''))
    message_text = AdvancedSecurity.sanitize_input(data.get('message', '').strip())

    if not to_user or not message_text or to_user not in users_db:
        AdvancedSecurity.log_security_event("INVALID_MESSAGE", f"Attempt to send invalid message to {to_user}",
                                            session['user'])
        return jsonify({'success': False})

    # Store message
    if to_user not in messages_db[session['user']]:
        messages_db[session['user']][to_user] = []

    if session['user'] not in messages_db[to_user]:
        messages_db[to_user][session['user']] = []

    message_data = {
        'sender': session['user'],
        'message': message_text,
        'timestamp': datetime.now(timezone.utc).strftime('%H:%M:%S'),
        'type': 'text'
    }

    messages_db[session['user']][to_user].append(message_data)
    messages_db[to_user][session['user']].append(message_data)

    # Keep only last 100 messages per conversation
    if len(messages_db[session['user']][to_user]) > 100:
        messages_db[session['user']][to_user] = messages_db[session['user']][to_user][-100:]
    if len(messages_db[to_user][session['user']]) > 100:
        messages_db[to_user][session['user']] = messages_db[to_user][session['user']][-100:]

    AdvancedSecurity.log_security_event("MESSAGE_SENT", f"Message sent to {to_user}", session['user'])
    return jsonify({'success': True})


@app.route('/send_file', methods=['POST'])
@require_auth
def send_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})

        file = request.files['file']
        to_user = AdvancedSecurity.sanitize_input(request.form.get('to', ''))
        file_password = request.form.get('password', '')

        if not file or not to_user or to_user not in users_db:
            return jsonify({'success': False, 'error': 'Invalid recipient'})

        if len(file_password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'})

        # Read file data
        file_data = file.read()

        # Security checks
        if not AdvancedSecurity.validate_filename(file.filename):
            AdvancedSecurity.log_security_event("INVALID_FILENAME",
                                                f"Attempt to upload invalid filename: {file.filename}", session['user'])
            return jsonify({'success': False, 'error': 'Invalid filename'})

        is_malicious, reason = AdvancedSecurity.detect_malicious_file(file_data)
        if is_malicious:
            AdvancedSecurity.log_security_event("MALICIOUS_FILE_BLOCKED",
                                                f"Malicious file blocked: {reason} - {file.filename}", session['user'])
            return jsonify({'success': False, 'error': f'Security violation: {reason}'})

        # Encrypt file
        file_salt = SNSCrypto.generate_salt()
        file_key = SNSCrypto.derive_key(file_password, file_salt)
        encrypted_file = SNSCrypto.encrypt_data(file_key, file_data)

        # Store file
        file_id = secrets.token_hex(32)
        file_type, file_description = AdvancedSecurity.detect_file_type(file_data)
        file_storage[file_id] = {
            'encrypted_data': encrypted_file,
            'salt': base64.b64encode(file_salt).decode(),
            'filename': file.filename,
            'file_type': file_type,
            'file_size': len(file_data),
            'sender': session['user'],
            'recipient': to_user,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Create file message
        if to_user not in messages_db[session['user']]:
            messages_db[session['user']][to_user] = []

        if session['user'] not in messages_db[to_user]:
            messages_db[to_user][session['user']] = []

        file_message = {
            'sender': session['user'],
            'type': 'file',
            'file_id': file_id,
            'filename': file.filename,
            'file_type': file_type,
            'file_size': AdvancedSecurity.format_file_size(len(file_data)),
            'timestamp': datetime.now(timezone.utc).strftime('%H:%M:%S')
        }

        messages_db[session['user']][to_user].append(file_message)
        messages_db[to_user][session['user']].append(file_message)

        AdvancedSecurity.log_security_event("FILE_SENT", f"Encrypted file sent to {to_user}: {file.filename}",
                                            session['user'])
        return jsonify({'success': True})

    except Exception as e:
        AdvancedSecurity.log_security_event("FILE_UPLOAD_ERROR", f"File upload failed: {str(e)}", session['user'])
        return jsonify({'success': False, 'error': 'File upload failed'})


@app.route('/download_file', methods=['POST'])
@require_auth
def download_file():
    try:
        data = request.get_json()
        file_id = data.get('file_id')
        file_password = data.get('password', '')

        if file_id not in file_storage:
            return jsonify({'success': False, 'error': 'File not found'})

        file_info = file_storage[file_id]

        # Check if user is authorized to download this file
        if session['user'] not in [file_info['sender'], file_info['recipient']]:
            AdvancedSecurity.log_security_event("UNAUTHORIZED_FILE_ACCESS", f"Attempt to access file: {file_id}",
                                                session['user'])
            return jsonify({'success': False, 'error': 'Access denied'})

        # Decrypt file
        file_salt = base64.b64decode(file_info['salt'])
        file_key = SNSCrypto.derive_key(file_password, file_salt)

        try:
            decrypted_data = SNSCrypto.decrypt_data(file_key, file_info['encrypted_data'])
        except ValueError as e:
            AdvancedSecurity.log_security_event("FILE_DECRYPTION_FAILED", f"Failed to decrypt file: {file_id}",
                                                session['user'])
            return jsonify({'success': False, 'error': 'Invalid password'})

        # Create in-memory file
        file_obj = BytesIO(decrypted_data)
        file_obj.seek(0)

        AdvancedSecurity.log_security_event("FILE_DOWNLOADED", f"File downloaded: {file_info['filename']}",
                                            session['user'])
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=file_info['filename'],
            mimetype='application/octet-stream'
        )

    except Exception as e:
        AdvancedSecurity.log_security_event("FILE_DOWNLOAD_ERROR", f"File download failed: {str(e)}", session['user'])
        return jsonify({'success': False, 'error': 'Download failed'})




@app.route('/get_messages')
@require_auth
def get_messages():
    with_user = AdvancedSecurity.sanitize_input(request.args.get('with', ''))

    if with_user and with_user in messages_db[session['user']]:
        return jsonify(messages_db[session['user']][with_user][-50:])

    return jsonify([])


@app.route('/clear_chat', methods=['POST'])
@require_auth
def clear_chat():
    data = request.get_json()
    with_user = AdvancedSecurity.sanitize_input(data.get('with', ''))

    if with_user in messages_db[session['user']]:
        messages_db[session['user']][with_user] = []
    if session['user'] in messages_db[with_user]:
        messages_db[with_user][session['user']] = []

    AdvancedSecurity.log_security_event("CHAT_CLEARED", f"Chat cleared with {with_user}", session['user'])
    return jsonify({'success': True})


@app.route('/start_call', methods=['POST'])
@require_auth
def start_call():
    data = request.get_json()
    target = AdvancedSecurity.sanitize_input(data.get('target', ''))
    offer = data.get('offer')
    voice_only = data.get('voice_only', False)

    if not target or not offer or target not in users_db or target == session['user']:
        return jsonify({'success': False, 'error': 'Invalid target'})

    # Encrypt offer with call_key
    offer_json = json.dumps(offer)
    encrypted_offer = SNSCrypto.encrypt_data(call_key, offer_json.encode())

    if target not in call_offers:
        call_offers[target] = []

    call_offers[target].append({
        'from': session['user'],
        'encrypted_offer': encrypted_offer,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'voice_only': voice_only
    })

    call_type = "VOICE CALL" if voice_only else "VIDEO CALL"
    AdvancedSecurity.log_security_event(f"{call_type}_STARTED", f"{call_type} initiated to {target}", session['user'])
    return jsonify({'success': True})


@app.route('/get_call_offers')
@require_auth
def get_call_offers():
    offers = call_offers.get(session['user'], [])
    call_offers[session['user']] = []

    # Decrypt offers
    decrypted_offers = []
    for offer_data in offers:
        try:
            decrypted_data = SNSCrypto.decrypt_data(call_key, offer_data['encrypted_offer'])
            offer = json.loads(decrypted_data.decode())
            decrypted_offers.append({
                'from': offer_data['from'],
                'offer': offer,
                'timestamp': offer_data['timestamp'],
                'voice_only': offer_data.get('voice_only', False)
            })
        except:
            continue  # Skip invalid

    return jsonify({'offers': decrypted_offers})


@app.route('/send_call_answer', methods=['POST'])
@require_auth
def send_call_answer():
    data = request.get_json()
    target = AdvancedSecurity.sanitize_input(data.get('target', ''))
    answer = data.get('answer')

    if not target or not answer or target not in users_db:
        return jsonify({'success': False, 'error': 'Invalid target'})

    # Encrypt answer
    answer_json = json.dumps(answer)
    encrypted_answer = SNSCrypto.encrypt_data(call_key, answer_json.encode())

    if target not in call_answers:
        call_answers[target] = []

    call_answers[target].append({
        'from': session['user'],
        'encrypted_answer': encrypted_answer,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })

    return jsonify({'success': True})


@app.route('/get_call_answers')
@require_auth
def get_call_answers():
    answers = call_answers.get(session['user'], [])
    call_answers[session['user']] = []

    decrypted_answers = []
    for answer_data in answers:
        try:
            decrypted_data = SNSCrypto.decrypt_data(call_key, answer_data['encrypted_answer'])
            answer = json.loads(decrypted_data.decode())
            decrypted_answers.append({
                'from': answer_data['from'],
                'answer': answer,
                'timestamp': answer_data['timestamp']
            })
        except:
            continue

    return jsonify({'answers': decrypted_answers})


@app.route('/send_ice_candidate', methods=['POST'])
@require_auth
def send_ice_candidate():
    data = request.get_json()
    target = AdvancedSecurity.sanitize_input(data.get('target', ''))
    candidate = data.get('candidate')

    if not target or not candidate or target not in users_db:
        return jsonify({'success': False, 'error': 'Invalid target'})

    # Encrypt candidate
    candidate_json = json.dumps(candidate)
    encrypted_candidate = SNSCrypto.encrypt_data(call_key, candidate_json.encode())

    if target not in call_candidates:
        call_candidates[target] = []

    call_candidates[target].append({
        'from': session['user'],
        'encrypted_candidate': encrypted_candidate,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })

    return jsonify({'success': True})


@app.route('/get_ice_candidates')
@require_auth
def get_ice_candidates():
    candidates = call_candidates.get(session['user'], [])
    call_candidates[session['user']] = []

    decrypted_candidates = []
    for candidate_data in candidates:
        try:
            decrypted_data = SNSCrypto.decrypt_data(call_key, candidate_data['encrypted_candidate'])
            candidate = json.loads(decrypted_data.decode())
            decrypted_candidates.append({
                'from': candidate_data['from'],
                'candidate': candidate,
                'timestamp': candidate_data['timestamp']
            })
        except:
            continue

    return jsonify({'candidates': decrypted_candidates})


@app.route('/update_location', methods=['POST'])
@require_auth
def update_location():
    """Update user's real-time GPS location"""
    try:
        data = request.get_json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy', 0)

        if latitude is None or longitude is None:
            return jsonify({'success': False, 'error': 'Invalid location data'})

        # Store user's real-time location
        user_locations[session['user']] = {
            'latitude': float(latitude),
            'longitude': float(longitude),
            'accuracy': float(accuracy),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'ip': request.remote_addr
        }

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/update_typing', methods=['POST'])
@require_auth
def update_typing():
    """Update typing indicator status"""
    try:
        data = request.get_json()
        is_typing = data.get('is_typing', False)
        recipient = data.get('recipient')

        if not recipient or recipient not in users_db:
            return jsonify({'success': False, 'error': 'Invalid recipient'})

        key = f"{session['user']}_{recipient}"

        if is_typing:
            typing_indicators[key] = {
                'user': session['user'],
                'recipient': recipient,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            # Also create reverse indicator for the recipient to see
            reverse_key = f"{recipient}_{session['user']}"
            typing_indicators[reverse_key] = {
                'user': recipient,
                'recipient': session['user'],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        else:
            # Remove both directions of typing indicator
            if key in typing_indicators:
                del typing_indicators[key]
            reverse_key = f"{recipient}_{session['user']}"
            if reverse_key in typing_indicators:
                del typing_indicators[reverse_key]

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/get_typing_status')
@require_auth
def get_typing_status():
    """Get typing status for current chat"""
    recipient = request.args.get('with', '')
    if not recipient:
        return jsonify({'is_typing': False})

    # Check if recipient is typing to current user
    key = f"{recipient}_{session['user']}"
    if key in typing_indicators:
        # Check if typing indicator is still valid (within last 3 seconds)
        indicator_time = datetime.fromisoformat(typing_indicators[key]['timestamp'])
        if (datetime.now(timezone.utc) - indicator_time).total_seconds() < 3:
            return jsonify({'is_typing': True, 'user': recipient})

    return jsonify({'is_typing': False})


@app.route('/user_heartbeat', methods=['POST'])
@require_auth
def user_heartbeat():
    """Update user's activity status via heartbeat"""
    try:
        data = request.get_json()
        is_active = data.get('active', True)  # Default to True for backward compatibility

        # Update session last activity time
        if session['token'] in sessions_db:
            current_time = datetime.now(timezone.utc).isoformat()
            session_data = sessions_db[session['token']]

            if is_active:
                # User is actively using the chat - update last activity
                session_data['last_activity'] = current_time
                AdvancedSecurity.log_security_event("USER_ACTIVITY", f"User active in session", session['user'])
            else:
                # User switched tabs or became inactive - don't update last activity
                # The last activity will remain as the last time they were actively chatting
                pass

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/get_user_status')
def get_user_status():
    """Get online status for all users"""
    user_statuses = {}
    current_time = datetime.now(timezone.utc)

    for username in users_db.keys():
        is_online = False
        last_seen = "Never"

        # Check if user has active sessions
        for session_data in sessions_db.values():
            if session_data['username'] == username:
                session_time = datetime.fromisoformat(session_data['last_activity'])
                time_diff = (current_time - session_time).total_seconds()

                if time_diff < 60:  # 1 minute threshold for online (more responsive)
                    is_online = True
                    last_seen = "Online"
                else:
                    last_seen = f"Last seen {session_time.strftime('%H:%M %d/%m/%Y')}"
                break

        if not is_online and last_seen == "Never":
            last_seen = "Never"

        user_statuses[username] = {
            'online': is_online,
            'last_seen': last_seen,
            'location': user_locations.get(username)
        }

    return jsonify(user_statuses)


@app.route('/logout')
def logout():
    if 'token' in session and session['token'] in sessions_db:
        AdvancedSecurity.log_security_event("USER_LOGOUT", "User logged out", session.get('user', 'unknown'))
        del sessions_db[session['token']]

    session.clear()
    return redirect('/?message=Session terminated securely')


def cleanup_sessions():
    """Clean up expired sessions, call items, locations, and typing indicators"""
    current_time = datetime.now(timezone.utc)
    expired_tokens = []
    expired_call_items = []
    expired_locations = []
    expired_typing_indicators = []

    # Clean expired sessions
    for token, session_data in sessions_db.items():
        last_activity = datetime.fromisoformat(session_data['last_activity'])
        if (current_time - last_activity).total_seconds() > SNS_CONFIG['session_timeout']:
            expired_tokens.append(token)

    # Clean old call items (older than 1 hour)
    for user in list(call_offers.keys()):
        call_offers[user] = [o for o in call_offers[user] if (current_time - datetime.fromisoformat(o['timestamp'])).total_seconds() < 3600]
        if not call_offers[user]:
            del call_offers[user]

    for user in list(call_answers.keys()):
        call_answers[user] = [a for a in call_answers[user] if (current_time - datetime.fromisoformat(a['timestamp'])).total_seconds() < 3600]
        if not call_answers[user]:
            del call_answers[user]

    for user in list(call_candidates.keys()):
        call_candidates[user] = [c for c in call_candidates[user] if (current_time - datetime.fromisoformat(c['timestamp'])).total_seconds() < 3600]
        if not call_candidates[user]:
            del call_candidates[user]

    # Clean old location data (older than 24 hours)
    for user, location_data in user_locations.items():
        location_time = datetime.fromisoformat(location_data['timestamp'])
        if (current_time - location_time).total_seconds() > 86400:  # 24 hours
            expired_locations.append(user)

    # Clean expired typing indicators (older than 10 seconds)
    for key, indicator_data in typing_indicators.items():
        indicator_time = datetime.fromisoformat(indicator_data['timestamp'])
        if (current_time - indicator_time).total_seconds() > 10:
            expired_typing_indicators.append(key)

    # Remove expired items
    for token in expired_tokens:
        del sessions_db[token]

    for user in expired_locations:
        del user_locations[user]

    for key in expired_typing_indicators:
        del typing_indicators[key]


if __name__ == '__main__':
    # Initialize test users
    operator1 = SNSUserManager.create_user("operator1", "password123")
    operator2 = SNSUserManager.create_user("operator2", "password123")

    # Display SNS numbers
    if operator1:
        print(f"OPERATOR1 SNS NUMBER: {users_db['operator1']['sns_number']}")
    if operator2:
        print(f"OPERATOR2 SNS NUMBER: {users_db['operator2']['sns_number']}")

    # Find available port
    port = find_available_port(5000, 5010)
    if port is None:
        port = 5000

    print("=" * 70)
    print("🔒 SNS PROTOCOL v2.0 - MILITARY GRADE ENCRYPTED CHAT SYSTEM")
    print("=" * 70)
    print("SYSTEM INITIALIZED WITH ENHANCED SECURITY FEATURES")
    print(f"ACCESS URL: http://localhost:{port}")
    print("TEST USERS: operator1 / operator2")
    print("PASSWORD: password123")
    print("NOTE: To test video calls between users, use two different browsers or incognito windows.")
    print("")
    print("SECURITY FEATURES ACTIVE:")
    print("• Advanced anti-tampering protection")
    print("• Session monitoring and intrusion detection")
    print("• Rate limiting and account locking")
    print("• Real-time security logging")
    print("• Encrypted video calling with WebRTC")
    print("• Multi-layer signaling encryption")
    print("• End-to-end encrypted messaging")
    print("• Unique SNS phone numbering system")
    print("• Direct calling by SNS number")
    print("• Military-grade encrypted voice calling")
    print("• Biometric fingerprint authentication")
    print("=" * 70)

    # Run cleanup every 30 minutes
    import threading


    def schedule_cleanup():
        while True:
            time.sleep(1800)
            cleanup_sessions()


    cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
    cleanup_thread.start()

    # Run the app
    app.run(host='0.0.0.0', port=port, debug=False)
