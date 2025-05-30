from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import hashlib, jwt, datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///geo_data.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'
db = SQLAlchemy(app)

encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

class GeoData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_data = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()
def generate_token(user): return jwt.encode({
    'username': user.username,
    'role': user.role,
    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
}, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token): 
    try: return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: return None

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user = User(username=data['username'], password_hash=hash_password(data['password']), role=data.get('role', 'user'))
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and user.password_hash == hash_password(data['password']):
        return jsonify({'token': generate_token(user)})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/upload', methods=['POST'])
def upload_geo_data():
    token = request.headers.get('Authorization')
    user_data = verify_token(token)
    if not user_data: return jsonify({'message': 'Unauthorized'}), 403
    data = request.json.get('geo_data')
    encrypted_data = cipher_suite.encrypt(data.encode()).decode()
    user = User.query.filter_by(username=user_data['username']).first()
    geo_entry = GeoData(encrypted_data=encrypted_data, owner_id=user.id)
    db.session.add(geo_entry)
    db.session.commit()
    return jsonify({'message': 'Geo-data uploaded successfully'})

@app.route('/retrieve', methods=['GET'])
def retrieve_geo_data():
    token = request.headers.get('Authorization')
    user_data = verify_token(token)
    if not user_data: return jsonify({'message': 'Unauthorized'}), 403
    user = User.query.filter_by(username=user_data['username']).first()
    entries = GeoData.query.filter_by(owner_id=user.id).all()
    decrypted_data = [cipher_suite.decrypt(entry.encrypted_data.encode()).decode() for entry in entries]
    return jsonify({'geo_data': decrypted_data})

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
