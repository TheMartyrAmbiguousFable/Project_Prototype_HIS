from flask import Flask, request, jsonify
import sqlite3
import hashlib
import jwt
import datetime

import security

app = Flask(__name__)
app.config['SECRET_KEY'] = 'key_for_token'
DATABASE = '/opt/auth/healthcare_workers.db'

# Database connection
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Authentication endpoint
@app.route('/api/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    try:
        staff_id = int(security.decrypt_message(data['id']))
        password = security.decrypt_message(data['password'])
        
        conn = get_db()
        user = conn.execute('SELECT * FROM staff WHERE id=? AND passwd=?', 
                          (staff_id, password)).fetchone()
        conn.close()        
        if user:
            token = jwt.encode({
                'id': user['id'],
                'duty': user['duty'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'token': token,
                'duty': user['duty']
            })        
        return jsonify({'error': 'Invalid credentials'}), 401        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Authorization verification endpoint
@app.route('/api/verify', methods=['POST'])
def verify_access():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token missing'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'duty': data['duty']})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
