from flask import Flask, request, jsonify
import jwt
import datetime
import re
import hashlib
import os
import requests
import logging
from functools import wraps
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads/'
ALLOWED_EXTENSIONS = {'exe', 'bin', 'dll', 'zip', 'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])
logging.basicConfig(filename='security_logs.log', level=logging.INFO)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    if auth and auth['username'] == 'admin' and auth['password'] == 'password':
        token = jwt.encode({'user': auth['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, 
                           app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/scan/url', methods=['POST'])
@token_required
def scan_url():
    data = request.json
    url = data.get('url')
    phishing_patterns = [r'http:\/\/.*free-money.*', r'http:\/\/.*lottery-win.*']
    for pattern in phishing_patterns:
        if re.search(pattern, url):
            return jsonify({'url': url, 'status': 'Phishing detected'})
    return jsonify({'url': url, 'status': 'Safe'})

@app.route('/scan/file', methods=['POST'])
@token_required
def scan_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        file_hash = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
        return jsonify({'file': filename, 'hash': file_hash})
    return jsonify({'message': 'File type not allowed'}), 400

@app.route('/scan/ip', methods=['POST'])
@token_required
def scan_ip():
    data = request.json
    ip = data.get('ip')
    suspicious_ips = {"192.168.1.1": "Malicious", "8.8.8.8": "Safe"}
    status = suspicious_ips.get(ip, "Unknown")
    return jsonify({'ip': ip, 'status': status})

@app.route('/scan/email', methods=['POST'])
@token_required
def scan_email():
    data = request.json
    email = data.get('email')
    leaked_emails = {"test@example.com": ["Breach1", "Breach2"]}
    breaches = leaked_emails.get(email, [])
    if breaches:
        return jsonify({'email': email, 'status': 'Compromised', 'breaches': breaches})
    return jsonify({'email': email, 'status': 'Safe'})

if __name__ == '__main__':
    app.run(debug=True)
