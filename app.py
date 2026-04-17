from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import json
from datetime import datetime, timedelta
from email_analyzer import analyze_email_content
from supabase_client import init_supabase

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

jwt = JWTManager(app)
supabase = init_supabase()

# ==================== AUTHENTICATION ====================

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        # Validation
        if not all([data.get('name'), data.get('email'), data.get('password')]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Check if user exists
        existing = supabase.table('users').select('*').eq('email', data['email']).execute()
        if existing.data:
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create user
        hashed_password = generate_password_hash(data['password'])
        user_data = {
            'name': data['name'],
            'email': data['email'],
            'password_hash': hashed_password,
            'college': data.get('college', ''),
            'created_at': datetime.utcnow().isoformat(),
            'analyses_count': 0
        }
        
        response = supabase.table('users').insert(user_data).execute()
        user = response.data[0]
        
        # Create token
        access_token = create_access_token(identity=user['id'])
        
        return jsonify({
            'token': access_token,
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email']
            }
        }), 201
        
    except Exception as e:
        print(f"Signup error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing email or password'}), 400
        
        # Get user
        response = supabase.table('users').select('*').eq('email', data['email']).execute()
        
        if not response.data:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        user = response.data[0]
        
        # Check password
        if not check_password_hash(user['password_hash'], data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Create token
        access_token = create_access_token(identity=user['id'])
        
        return jsonify({
            'token': access_token,
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email']
            }
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# ==================== EMAIL ANALYSIS ====================

@app.route('/api/analyze', methods=['POST'])
@jwt_required()
def analyze():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        email_content = data.get('emailContent', '').strip()
        
        if not email_content or len(email_content) < 50:
            return jsonify({'error': 'Email content too short'}), 400
        
        if len(email_content) > 5000:
            return jsonify({'error': 'Email content too long'}), 400
        
        # Analyze email
        analysis_result = analyze_email_content(email_content)
        
        # Save to database
        record = {
            'user_id': user_id,
            'email_content': email_content[:500],  # Store first 500 chars
            'verdict': analysis_result['verdict'],
            'confidence': analysis_result['confidence'],
            'company': analysis_result['company'],
            'risk_factors': json.dumps(analysis_result['riskFactors']),
            'recommendation': analysis_result['recommendation'],
            'analyzed_at': datetime.utcnow().isoformat()
        }
        
        supabase.table('analyses').insert(record).execute()
        
        # Update user analyses count
        user_response = supabase.table('users').select('analyses_count').eq('id', user_id).execute()
        current_count = user_response.data[0]['analyses_count'] if user_response.data else 0
        supabase.table('users').update({'analyses_count': current_count + 1}).eq('id', user_id).execute()
        
        return jsonify(analysis_result), 200
        
    except Exception as e:
        print(f"Analysis error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/history', methods=['GET'])
@jwt_required()
def get_history():
    try:
        user_id = get_jwt_identity()
        limit = request.args.get('limit', 20, type=int)
        
        response = supabase.table('analyses').select('*').eq('user_id', user_id).order('analyzed_at', desc=True).limit(limit).execute()
        
        history = []
        for record in response.data:
            history.append({
                'id': record['id'],
                'company': record['company'],
                'verdict': record['verdict'],
                'confidence': record['confidence'],
                'timestamp': record['analyzed_at'],
                'recommendation': record['recommendation'],
                'riskFactors': json.loads(record['risk_factors'])
            })
        
        return jsonify({'history': history}), 200
        
    except Exception as e:
        print(f"History error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        user_id = get_jwt_identity()
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        
        if not response.data:
            return jsonify({'error': 'User not found'}), 404
        
        user = response.data[0]
        return jsonify({
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'college': user.get('college', ''),
            'analyses_count': user.get('analyses_count', 0),
            'created_at': user.get('created_at')
        }), 200
        
    except Exception as e:
        print(f"Profile error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)