from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
from flask_cors import CORS
from flask_httpauth import current_user as auth_user

app = Flask(__name__)
app.secret_key = 'your_secret_key' 

CORS(app, origins=["http://localhost:5173"])

login_manager = LoginManager()
login_manager.init_app(app)


auth = HTTPBasicAuth()


users = {
    'admin': {'password': generate_password_hash('password123')}  
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users[username]['password'], password):
        return username  
    return None


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  
    return redirect(url_for('login')) 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username]['password'], password):
            user = User(username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            error_message = "Invalid credentials. Please try again."

    return render_template('login.html', error_message=error_message)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error_message = None
    success_message = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            error_message = "Username already exists. Please choose another."
        else:
            hashed_password = generate_password_hash(password)
            users[username] = {'password': hashed_password}
            success_message = "Account created successfully! You can now log in."
            return redirect(url_for('login'))

    return render_template('signup.html', error_message=error_message, success_message=success_message)

@app.route('/dashboard')
@login_required
def dashboard():
    return f'''
    <div style="text-align:center; font-family: Arial, sans-serif;">
        <h1>Welcome {current_user.id}!</h1>
        <p><a href="/logout" style="color: white; background-color: #4CAF50; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Logout</a></p>
    </div>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/protected', methods=['GET'])
@auth.login_required
def api_protected():
    return jsonify(message=f'Hello {auth.current_user()}, you have accessed a protected API route!')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
