from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from datetime import timedelta
import requests
import random
import time
import os
import nmap
import base64
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For flashing messages
# VirusTotal API URL and API key
API_URL = 'https://www.virustotal.com/api/v3/urls'
API_KEY = '0e2137eaa2a2395599cf8a67f5ed8fe2503bf60d81085b412d4df15b6968e6df'

# Set up logging
logging.basicConfig(level=logging.DEBUG)

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/game')
def game():
    return render_template('game.html')

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data['username']
            email = data['email']
            password = data['password']
            
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
            existing_user = cursor.fetchone()
            
            if existing_user:
                if existing_user['username'] == username:
                    return jsonify({'message': 'Username already taken'}), 400
                if existing_user['email'] == email:
                    return jsonify({'message': 'Email already registered'}), 400

            password_hash = generate_password_hash(password)

            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, password_hash))
            conn.commit()
            conn.close()
            
            return jsonify({'message': 'User registered successfully'})
        except Exception as e:
            logging.error('Error during registration: %s', e)
            return jsonify({'message': 'An error occurred during registration'}), 500

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']
        remember_me = data.get('rememberMe', False)
        
        logging.debug('Login attempt for username: %s', username)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            logging.debug('User found in database: %s', user['username'])
            if check_password_hash(user['password'], password):
                logging.debug('Password check successful for username: %s', username)
                session['username'] = username
                session['email'] = user['email']
                if remember_me:
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(days=30)
                else:
                    session.permanent = False
                return jsonify({'message': 'Login successful'})
            else:
                logging.debug('Invalid password for username: %s', username)
                return jsonify({'message': 'Invalid password'}), 400
        else:
            logging.debug('Invalid username: %s', username)
            return jsonify({'message': 'Invalid username'}), 400
    except Exception as e:
        logging.error('Error during login: %s', e)
        return jsonify({'message': 'An error occurred during login'}), 500

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], email=session['email'])
    else:
        return redirect(url_for('index'))
    
@app.route('/tutorial')
def tutorial():
    return render_template('tutorial.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/tools')
def tools_page():
    return render_template('tools.html')

@app.route('/settings')
def settings():
    if 'username' in session:
        return render_template('settings.html', username=session['username'], email=session['email'])
    else:
        return redirect(url_for('index'))

@app.route('/detect_ip')
def detect_ip():
    try:
        if request.headers.get('X-Forwarded-For'):
            user_ip = request.headers.get('X-Forwarded-For').split(',')[0]
        else:
            user_ip = request.remote_addr

        response = requests.get(f'http://ipinfo.io/{user_ip}/json')
        data = response.json()
        
        return jsonify({
            'IP': data.get('ip'),
            'City': data.get('city'),
            'Region': data.get('region'),
            'Country': data.get('country'),
            'Timezone': data.get('timezone'),
            'ISP': data.get('org')  # 'org' usually contains the ISP name
        })
    except Exception as e:
        logging.error('Error fetching IP details: %s', e)
        return jsonify({'message': 'An error occurred while fetching IP details'}), 500

@app.route('/ip_detector')
def ip_detector():
    return render_template('detect_ip.html')

@app.route('/ip_tracker')
def ip_tracker():
    return render_template('ip_tracker.html')

@app.route('/track_ip', methods=['POST'])
def track_ip():
    ip = request.form.get('ip')
    url = f"http://ip-api.com/json/{ip}"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        if data['status'] == 'fail':
            return jsonify({'error': data['message']})
        
        return jsonify({
            'IP': data['query'],
            'City': data['city'],
            'Region': data['regionName'],
            'Country': data['country'],
            'Country Code': data['countryCode'],
            'Timezone': data['timezone'],
            'ISP': data['isp'],
            'Org': data['org'],
            'AS': data['as'],
            'Lat': data['lat'],
            'Lon': data['lon']
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/url_scanner')
def url_scanner():
    return render_template('url_scanner.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        url = data.get('url')
        result = check_url_safety(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)})

def check_url_safety(url):
    headers = {
        'x-apikey': API_KEY,
    }

    # Encode URL for the API request
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    full_url = f'{API_URL}/{encoded_url}'

    try:
        response = requests.get(full_url, headers=headers)
        response.raise_for_status()
        status = response.json()
        print(f"API Response: {status}")  # Debug: Print API response

        # Adjust according to actual API response
        if 'data' in status and 'attributes' in status['data']:
            last_analysis_stats = status['data']['attributes']['last_analysis_stats']
            if last_analysis_stats['malicious'] > 0:
                return {'safe': False}
            else:
                return {'safe': True}
        else:
            return {'safe': False}
    except requests.RequestException as e:
        print(f"Error: {e}")  # Debug: Print the exception
        return {'error': str(e)}

@app.route('/hackmap')
def hackmap():
    return render_template('hackmap.html')

@app.route('/get-attack-data', methods=['GET'])
def get_attack_data():
    # Simulate the number of attacks and data over time
    current_time = time.strftime('%H:%M:%S')
    attacks_today = random.randint(100, 150)
    attack_data = {
        'attack_count': attacks_today,
        'graph_data': {
            'time': current_time,
            'attacks': random.randint(1, 10)
        },
        'locations': [
            {'lat': random.uniform(-90, 90), 'lng': random.uniform(-180, 180), 'time': current_time, 'severity': random.choice(['Low', 'Medium', 'High'])}
            for _ in range(random.randint(1, 5))
        ]
    }
    return jsonify(attack_data)

# Set up logging
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

@app.route('/network_vulnerability_analyzer')
def network_vulnerability_analyzer():
    return render_template('network_vulnerability_analyzer.html')

@app.route('/network_scan', methods=['POST'])
def network_scan():
    target = request.form.get('target')
    nm = nmap.PortScanner()
    result = ""

    try:
        app.logger.info(f"Scanning target: {target}")
        scan_result = nm.scan(hosts=target, arguments='-sS')
        app.logger.info(f"Scan result: {scan_result}")

        host = list(scan_result['scan'].keys())[0]
        
        if 'scan' in scan_result and host in scan_result['scan']:
            result += f"Host: {host}\n"
            result += f"State: {scan_result['scan'][host]['status']['state']}\n\n"

            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = nm[host][proto][port]
                    if port_info['state'] == 'open':
                        result += f"Port: {port}\tState: {port_info['state']}\tService: {port_info['name']}\n"
        else:
            result = "No open ports found or host seems down."
            
    except Exception as e:
        app.logger.error(f"Error occurred: {str(e)}")
        result = f"Error: {str(e)}"

    return render_template('network_vulnerability_analyzer_results.html', result=result)

@app.route('/suggestions_reports', methods=['GET', 'POST'])
def suggestions_reports():
    if request.method == 'POST':
        suggestion = request.form.get('suggestion')
        report = request.form.get('report')
        
        # Process suggestion/report (e.g., save to database, send email)
        # For now, we'll just print it to the console
        print(f"Suggestion: {suggestion}")
        print(f"Report: {report}")

        return jsonify({'message': 'Thank you for your feedback!'})
    
    return render_template('suggestions_reports.html')

@app.route('/password_strengthner')
def password():
    return render_template('password.html')

# Extended FAQ data
faqs = [
    {"question": "What is cybersecurity?", "answer": "Cybersecurity refers to the practice of protecting systems, networks, and programs from digital attacks."},
    {"question": "What are the common types of cyber threats?", "answer": "Common types include malware, phishing, ransomware, denial of service (DoS), and man-in-the-middle (MITM) attacks."},
    {"question": "What is phishing?", "answer": "Phishing is a type of cyber attack where attackers impersonate legitimate organizations via email or other communication methods to steal sensitive data."},
    {"question": "How can I protect myself from phishing attacks?", "answer": "Be cautious of unsolicited emails, don’t click on suspicious links, and verify the authenticity of requests for sensitive information."},
    {"question": "What is malware?", "answer": "Malware is malicious software designed to disrupt, damage, or gain unauthorized access to computer systems."},
    {"question": "How does ransomware work?", "answer": "Ransomware encrypts the victim’s data and demands payment, typically in cryptocurrency, for the decryption key."},
    {"question": "What is a firewall?", "answer": "A firewall is a security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules."},
    {"question": "Why is two-factor authentication important?", "answer": "Two-factor authentication adds an extra layer of security by requiring not only a password and username but also something that only the user has on them, like a physical token or a mobile device."},
    {"question": "What is a VPN, and how does it work?", "answer": "A VPN (Virtual Private Network) encrypts your internet traffic and masks your online identity, making it more difficult for third parties to track your activities."},
    {"question": "What is social engineering?", "answer": "Social engineering is the use of deception to manipulate individuals into divulging confidential or personal information that may be used for fraudulent purposes."},
    {"question": "What is the dark web?", "answer": "The dark web is a part of the internet that is not indexed by search engines and is often used for illegal activities."},
    {"question": "What are the signs of a compromised account?", "answer": "Signs include unexpected password changes, unfamiliar login locations, unauthorized transactions, and receiving alerts about unusual activity."},
    {"question": "What is a DDoS attack?", "answer": "A Distributed Denial of Service (DDoS) attack overwhelms a system with traffic, causing it to become slow or completely inaccessible."},
    {"question": "How do I secure my home Wi-Fi network?", "answer": "Use strong passwords, enable WPA3 encryption, change the default router settings, and regularly update firmware."},
    {"question": "What are the best practices for password management?", "answer": "Use unique passwords for different accounts, enable two-factor authentication, and consider using a password manager."},
    {"question": "What is encryption?", "answer": "Encryption is the process of converting information into a code to prevent unauthorized access."},
    {"question": "How can I prevent identity theft online?", "answer": "Use strong passwords, avoid sharing personal information, monitor your accounts, and be cautious of phishing attempts."},
    {"question": "What is SSL/TLS?", "answer": "SSL (Secure Sockets Layer) and TLS (Transport Layer Security) are cryptographic protocols designed to provide secure communication over a computer network."},
    {"question": "What should I do if my account is hacked?", "answer": "Change your passwords immediately, enable two-factor authentication, and contact the service provider to report the incident."},
    {"question": "How do I create a form in Flask?", "answer": "You can create forms in Flask using HTML and handle the form data using Flask's request object."},
]

@app.route("/faq", methods=["GET", "POST"])
def faq():
    query = request.form.get("query", "").lower()
    if query:
        filtered_faqs = [faq for faq in faqs if query in faq["question"].lower()]
    else:
        filtered_faqs = faqs

    return render_template("faq.html", faqs=filtered_faqs, query=query)

if __name__ == '__main__':
    app.run(debug=True)