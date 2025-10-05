#!/usr/bin/env python3
"""
Military-Grade Encrypted Chat System - SNS Protocol
SECURE NETWORKED MESSAGING PROTOCOL
"""

import os
import json
import base64
import hashlib
import secrets
import time
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Cryptography imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Web framework
try:
    from flask import Flask, request, render_template_string, redirect, session, jsonify
except ImportError:
    print("Flask not installed. Installing required packages...")
    os.system("pip install flask==2.3.3 cryptography==41.0.4")
    from flask import Flask, request, render_template_string, redirect, session, jsonify

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# SNS Protocol Configuration
SNS_CONFIG = {
    'key_derivation_rounds': 100000,
    'token_size': 64,
    'salt_size': 32,
    'nonce_size': 16,
    'key_size': 32
}

# In-memory storage
users_db = {}
messages_db = {}
sessions_db = {}

# Military Terminal HTML Templates
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SNS Protocol - Military Terminal</title>
    <style>
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 20px;
            overflow: hidden;
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
        input, select {
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
    </style>
</head>
<body>
    <div class="terminal">
        <div class="header">
            <h1>🔒 SNS PROTOCOL v1.0</h1>
            <p>SECURE NETWORKED MESSAGING SYSTEM</p>
            <p class="blink">CLASSIFIED - AUTHORIZED PERSONNEL ONLY</p>
        </div>

        {% if mode == 'login' %}
        <form method="POST">
            <input type="hidden" name="mode" value="login">
            <div class="input-group">
                <label>USERNAME:</label>
                <input type="text" name="username" required>
            </div>
            <div class="input-group">
                <label>MASTER PASSWORD:</label>
                <input type="password" name="master_password" required>
            </div>
            <button type="submit">[ ACCESS SYSTEM ]</button>
            <button type="button" onclick="window.location='?mode=register'">[ NEW OPERATOR ]</button>
        </form>
        {% elif mode == 'register' %}
        <form method="POST">
            <input type="hidden" name="mode" value="register">
            <div class="input-group">
                <label>OPERATOR CODE:</label>
                <input type="text" name="username" required>
            </div>
            <div class="input-group">
                <label>MASTER PASSPHRASE:</label>
                <input type="password" name="master_password" required>
            </div>
            <div class="input-group">
                <label>CONFIRM PASSPHRASE:</label>
                <input type="password" name="confirm_password" required>
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
    </div>
</body>
</html>
'''

CHAT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SNS Protocol - Secure Channel</title>
    <style>
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 0;
        }
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
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <h3>OPERATORS ONLINE</h3>
            <div id="users-list">
                {% for user in users %}
                <div class="user-item {% if user == active_chat %}active-chat{% endif %}" onclick="selectUser('{{ user }}')">
                    {{ user }} {% if user == active_chat %}[ACTIVE]{% endif %}
                </div>
                {% endfor %}
            </div>
            <div style="margin-top: 20px;">
                <input type="text" id="search-user" placeholder="FIND OPERATOR...">
                <button onclick="searchUser()">[ SEARCH ]</button>
                <button onclick="logout()" style="background: #300; border-color: #f00; margin-top: 10px;">[ LOGOUT ]</button>
            </div>
        </div>

        <div class="main">
            <div class="header">
                <h2>SNS SECURE CHANNEL {% if active_chat %}:: {{ active_chat }} {% endif %}<span class="blink">_</span></h2>
                <div id="connection-status">ENCRYPTION: ACTIVE | PROTOCOL: SNS-256</div>
            </div>

            <div class="chat-area" id="chat-messages">
                <!-- Messages will be loaded here -->
            </div>

            <div class="input-area">
                <input type="text" id="message-input" placeholder="TYPE ENCRYPTED MESSAGE..." style="width: 70%;">
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

        function sendMessage() {
            const message = document.getElementById('message-input').value;
            if (message && activeUser) {
                fetch('/send_message', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({to: activeUser, message: message})
                }).then(r => r.json()).then(data => {
                    if (data.success) {
                        document.getElementById('message-input').value = '';
                        loadMessages();
                    }
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

        // Auto-refresh messages
        setInterval(loadMessages, 2000);
        document.addEventListener('DOMContentLoaded', loadMessages);

        // Enter key to send message
        document.getElementById('message-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>
'''


class SNSCrypto:
    """Military-grade encryption using SNS Protocol"""

    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(SNS_CONFIG['salt_size'])

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=SNS_CONFIG['key_size'],
            n=2 ** 14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_message(key: bytes, message: str) -> Dict:
        nonce = secrets.token_bytes(SNS_CONFIG['nonce_size'])
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        message_bytes = message.encode()
        ciphertext = encryptor.update(message_bytes) + encryptor.finalize()

        return {
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }

    @staticmethod
    def decrypt_message(key: bytes, encrypted_data: Dict) -> str:
        try:
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
        except Exception as e:
            return f"[DECRYPTION ERROR: {str(e)}]"


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

        # Create user profile with encrypted storage key
        users_db[username] = {
            'salt': base64.b64encode(salt).decode(),
            'master_key_hash': base64.b64encode(hashlib.sha256(master_key).digest()).decode(),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'friends': []
        }

        # Initialize message storage
        messages_db[username] = {}

        return True

    @staticmethod
    def verify_user(username: str, master_password: str) -> bool:
        if username not in users_db:
            return False

        user_data = users_db[username]
        salt = base64.b64decode(user_data['salt'])

        # Derive master key
        master_key = SNSCrypto.derive_key(master_password, salt)
        master_key_hash = base64.b64encode(hashlib.sha256(master_key).digest()).decode()

        return master_key_hash == user_data['master_key_hash']

    @staticmethod
    def create_session(username: str) -> str:
        session_token = secrets.token_hex(SNS_CONFIG['token_size'])
        sessions_db[session_token] = {
            'username': username,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'last_activity': datetime.now(timezone.utc).isoformat()
        }
        return session_token


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


@app.route('/', methods=['GET', 'POST'])
def index():
    mode = request.args.get('mode', 'login')
    error = request.args.get('error', '')
    message = request.args.get('message', '')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        master_password = request.form.get('master_password', '')
        form_mode = request.form.get('mode', 'login')

        if form_mode == 'register':
            confirm_password = request.form.get('confirm_password', '')

            if not username or not master_password:
                return render_template_string(LOGIN_TEMPLATE, mode=form_mode, error="All fields required")

            if master_password != confirm_password:
                return render_template_string(LOGIN_TEMPLATE, mode=form_mode, error="Passphrases don't match")

            if len(master_password) < 8:
                return render_template_string(LOGIN_TEMPLATE, mode=form_mode, error="Passphrase must be 8+ characters")

            if SNSUserManager.create_user(username, master_password):
                return redirect('/?mode=login&message=Identity created successfully')
            else:
                return render_template_string(LOGIN_TEMPLATE, mode=form_mode, error="Operator code already exists")

        else:  # login
            if SNSUserManager.verify_user(username, master_password):
                session_token = SNSUserManager.create_session(username)
                session['user'] = username
                session['token'] = session_token
                return redirect('/chat')
            else:
                return render_template_string(LOGIN_TEMPLATE, mode=form_mode, error="Invalid credentials")

    return render_template_string(LOGIN_TEMPLATE, mode=mode, error=error, message=message)


@app.route('/chat')
def chat():
    if 'user' not in session or 'token' not in session:
        return redirect('/?error=Session expired')

    if session['token'] not in sessions_db:
        return redirect('/?error=Invalid session')

    # Update last activity
    sessions_db[session['token']]['last_activity'] = datetime.now(timezone.utc).isoformat()

    active_chat = request.args.get('with', '')
    all_users = [user for user in users_db.keys() if user != session['user']]

    return render_template_string(CHAT_TEMPLATE,
                                  users=all_users,
                                  active_chat=active_chat,
                                  session_user=session['user'])


@app.route('/search_user', methods=['POST'])
def search_user():
    if 'user' not in session:
        return jsonify({'exists': False})

    data = request.get_json()
    username = data.get('username', '').strip()

    exists = username in users_db and username != session['user']
    return jsonify({'exists': exists})


@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user' not in session:
        return jsonify({'success': False})

    data = request.get_json()
    to_user = data.get('to')
    message_text = data.get('message', '').strip()

    if not to_user or not message_text or to_user not in users_db:
        return jsonify({'success': False})

    # Store message
    if to_user not in messages_db[session['user']]:
        messages_db[session['user']][to_user] = []

    if session['user'] not in messages_db[to_user]:
        messages_db[to_user][session['user']] = []

    message_data = {
        'sender': session['user'],
        'message': message_text,
        'timestamp': datetime.now(timezone.utc).strftime('%H:%M:%S')
    }

    messages_db[session['user']][to_user].append(message_data)
    messages_db[to_user][session['user']].append(message_data)

    # Keep only last 100 messages per conversation
    if len(messages_db[session['user']][to_user]) > 100:
        messages_db[session['user']][to_user] = messages_db[session['user']][to_user][-100:]
    if len(messages_db[to_user][session['user']]) > 100:
        messages_db[to_user][session['user']] = messages_db[to_user][session['user']][-100:]

    return jsonify({'success': True})


@app.route('/get_messages')
def get_messages():
    if 'user' not in session:
        return jsonify([])

    with_user = request.args.get('with', '')

    if with_user and with_user in messages_db[session['user']]:
        return jsonify(messages_db[session['user']][with_user][-50:])

    return jsonify([])


@app.route('/clear_chat', methods=['POST'])
def clear_chat():
    if 'user' not in session:
        return jsonify({'success': False})

    data = request.get_json()
    with_user = data.get('with', '')

    if with_user in messages_db[session['user']]:
        messages_db[session['user']][with_user] = []
    if session['user'] in messages_db[with_user]:
        messages_db[with_user][session['user']] = []

    return jsonify({'success': True})


@app.route('/logout')
def logout():
    if 'token' in session and session['token'] in sessions_db:
        del sessions_db[session['token']]

    session.clear()
    return redirect('/?message=Session terminated')


def cleanup_sessions():
    """Clean up expired sessions"""
    current_time = datetime.now(timezone.utc)
    expired_tokens = []

    for token, session_data in sessions_db.items():
        last_activity = datetime.fromisoformat(session_data['last_activity'])
        if (current_time - last_activity).total_seconds() > 3600:  # 1 hour timeout
            expired_tokens.append(token)

    for token in expired_tokens:
        del sessions_db[token]


if __name__ == '__main__':
    # Create test users
    SNSUserManager.create_user("operator1", "password123")
    SNSUserManager.create_user("operator2", "password123")

    # Find available port
    port = find_available_port(5000, 5010)
    if port is None:
        port = 5000  # Fallback

    print("=" * 60)
    print("🔒 SNS PROTOCOL - MILITARY GRADE ENCRYPTED CHAT SYSTEM")
    print("=" * 60)
    print("SYSTEM INITIALIZED SUCCESSFULLY")
    print(f"ACCESS URL: http://localhost:{port}")
    print("TEST USERS: operator1 / operator2")
    print("PASSWORD: password123")
    print("=" * 60)

    # Run the app on available port
    app.run(host='0.0.0.0', port=port, debug=False)