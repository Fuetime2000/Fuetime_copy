from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
from flask_socketio import SocketIO, emit, join_room, leave_room
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import re
import razorpay
import hmac
import hashlib
import json
from flask_wtf.csrf import CSRFProtect, CSRFError
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from flask_babel import Babel, gettext as _
from sqlalchemy import text
from sqlalchemy import inspect
from flask_caching import Cache
import time

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'o3#7n4@43y0ry5j4@2me+nn@vbu32rr=w7mz)1yzz7egy^)qn*'  # Secret key for secure sessions
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fuetime.db'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable SQLALCHEMY_TRACK_MODIFICATIONS
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 10,
    'max_overflow': 20
}
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')  # Upload folder path
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit for CSRF tokens
app.config['WTF_CSRF_SSL_STRICT'] = False  # Disable SSL-only for CSRF tokens
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SESSION_TYPE'] = 'filesystem'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'fuetimeapp@gmail.com'  # App email
app.config['MAIL_PASSWORD'] = 'fzlg ztxo vxmq lmhp'  # App-specific password

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, async_mode='threading', ping_timeout=10)  # Remove async_mode for now
login_manager = LoginManager(app)
login_manager.login_view = 'login'
babel = Babel(app)
cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 300
})

# Initialize serializer for password reset tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Razorpay configuration
RAZORPAY_KEY_ID = 'rzp_live_NJ0w2ONEt4sOwV'
RAZORPAY_KEY_SECRET = 't8s0UF9M35FPHMCJob2G9mwH'
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Configure supported languages
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_LANGUAGES'] = ['en', 'hi', 'mr', 'gu', 'ta', 'te']

def get_locale():
    # Try to get the language from the session
    if 'language' in session:
        return session['language']
    # Otherwise, try to guess the language from the user accept header
    return request.accept_languages.best_match(app.config['BABEL_LANGUAGES'])

babel.init_app(app, locale_selector=get_locale)

# Make sure the translation function is available in templates
app.jinja_env.globals['_'] = _

def csrf_exempt(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        return view(*args, **kwargs)
    return csrf.exempt(wrapped)

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash(_('Access denied. Admin privileges required.'), 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Models
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    worker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ContactRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requested_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128))
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    full_name = db.Column(db.String(100), nullable=False)
    mother_name = db.Column(db.String(100))
    father_name = db.Column(db.String(100))
    live_location = db.Column(db.String(200))
    current_location = db.Column(db.String(200))
    work = db.Column(db.String(100))
    experience = db.Column(db.String(50))
    education = db.Column(db.String(200))
    age = db.Column(db.Integer)
    photo = db.Column(db.String(200))
    bio = db.Column(db.Text)
    payment_type = db.Column(db.String(20))
    payment_charge = db.Column(db.Float)
    skills = db.Column(db.String(500))
    categories = db.Column(db.String(200))
    availability = db.Column(db.String(20), default="available")
    average_rating = db.Column(db.Float, default=0.0)
    total_reviews = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    profile_views = db.Column(db.Integer, default=0)
    wallet_balance = db.Column(db.Float, default=0.0)
    is_admin = db.Column(db.Boolean, default=False)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    
    # Reviews - worker perspective (reviews received)
    reviews_received = db.relationship('Review',
        foreign_keys='Review.worker_id',
        backref='reviewed_user',
        lazy='dynamic'
    )
    
    # Reviews - reviewer perspective (reviews given)
    reviews_given = db.relationship('Review',
        foreign_keys='Review.reviewer_id',
        backref='reviewer_user',
        lazy='dynamic'
    )
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def update_rating(self):
        reviews = self.reviews_received.all()
        if reviews:
            total_rating = sum(review.rating for review in reviews)
            self.average_rating = round(total_rating / len(reviews), 1)
        else:
            self.average_rating = 0.0
        db.session.commit()

    def update_last_seen(self):
        self.last_active = datetime.utcnow()
        self.is_online = True

    def get_unread_messages_count(self):
        return Message.query.filter_by(recipient_id=self.id, is_read=False).count()

# Helper Functions
def generate_username(full_name):
    # Convert full name to lowercase and replace spaces with underscores
    base_username = full_name.lower().replace(' ', '_')
    
    # Remove any special characters
    base_username = re.sub(r'[^a-z0-9_]', '', base_username)
    
    # If username exists, add a random number
    username = base_username
    while User.query.filter_by(username=username).first():
        username = f"{base_username}_{random.randint(1, 9999)}"
    
    return username

def send_reset_email(user_email, reset_url):
    msg = MIMEMultipart()
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = user_email
    msg['Subject'] = 'Password Reset Request'
    
    body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.
'''
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Wallet Routes
@app.route('/wallet')
@login_required
def wallet():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template('wallet.html', transactions=transactions)

@app.route('/create-recharge-order', methods=['POST'])
@login_required
@csrf_exempt
def create_recharge_order():
    try:
        amount = float(request.form.get('amount', 0))
        if amount < 20 or amount > 500:
            return jsonify({'success': False, 'message': 'Amount must be between ₹20 and ₹500'})

        # Amount should be in paise
        amount_in_paise = int(amount * 100)
        
        order_data = {
            'amount': amount_in_paise,
            'currency': 'INR',
            'receipt': f'recharge_{current_user.id}_{datetime.now().timestamp()}',
            'notes': {
                'user_id': current_user.id,
                'type': 'wallet_recharge'
            }
        }
        
        razorpay_order = razorpay_client.order.create(data=order_data)
        
        return jsonify({
            'success': True,
            'order_id': razorpay_order['id'],
            'amount': amount_in_paise,
            'key_id': RAZORPAY_KEY_ID,
            'user_email': current_user.email,
            'user_phone': current_user.phone,
            'user_name': current_user.full_name
        })
        
    except Exception as e:
        print(f"Error in create_recharge_order: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to create payment order'})

@app.route('/verify-recharge-payment', methods=['POST'])
@login_required
@csrf_exempt
def verify_recharge_payment():
    try:
        # Get payment verification data
        payment_id = request.form.get('razorpay_payment_id')
        order_id = request.form.get('razorpay_order_id')
        signature = request.form.get('razorpay_signature')
        
        # Verify payment signature
        params_dict = {
            'razorpay_payment_id': payment_id,
            'razorpay_order_id': order_id,
            'razorpay_signature': signature
        }
        
        try:
            razorpay_client.utility.verify_payment_signature(params_dict)
        except Exception:
            return jsonify({
                'success': False,
                'message': 'Invalid payment signature'
            })
        
        # Get payment details
        payment = razorpay_client.payment.fetch(payment_id)
        amount = float(payment['amount']) / 100  # Convert paise to rupees
        
        # Update wallet balance
        current_user.wallet_balance += amount
        
        # Create transaction record
        transaction = Transaction(
            user_id=current_user.id,
            amount=amount,
            description=f'Wallet recharge via Razorpay (ID: {payment_id})'
        )
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully added ₹{amount} to your wallet',
            'new_balance': current_user.wallet_balance
        })
            
    except Exception as e:
        print(f"Error in verify_recharge_payment: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Failed to verify payment'
        })

@app.route('/add-wallet-balance', methods=['POST'])
@login_required
def add_wallet_balance():
    try:
        amount = float(request.form.get('amount', 0))
        if amount < 20 or amount > 500:
            return jsonify({'success': False, 'message': 'Amount must be between ₹20 and ₹500'})

        # Update wallet balance
        current_user.wallet_balance += amount
        
        # Create transaction record
        transaction = Transaction(
            user_id=current_user.id,
            amount=amount,
            description=f'Wallet recharge of ₹{amount}'
        )
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully added ₹{amount} to your wallet',
            'new_balance': current_user.wallet_balance
        })
            
    except Exception as e:
        print(f"Error in add_wallet_balance: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while processing your request'})

# Routes
@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('index'))
        
    # Search for users based on various fields
    users = User.query.filter(
        db.or_(
            User.full_name.ilike(f'%{query}%'),
            User.username.ilike(f'%{query}%'),
            User.work.ilike(f'%{query}%'),
            User.skills.ilike(f'%{query}%'),
            User.categories.ilike(f'%{query}%'),
            User.bio.ilike(f'%{query}%'),
            User.current_location.ilike(f'%{query}%')
        )
    ).all()
    
    return render_template('search_results.html', users=users, query=query)

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', '')
    location = request.args.get('location', '')
    q = request.args.get('q', '')
    
    # Start with all users
    users = User.query
    
    # Apply filters
    if q:
        users = users.filter(
            db.or_(
                db.func.lower(User.skills).like(f'%{q.lower()}%'),
                db.func.lower(User.work).like(f'%{q.lower()}%'),
                db.func.lower(User.full_name).like(f'%{q.lower()}%')
            )
        )
    
    if category:
        users = users.filter(db.func.lower(User.categories).like(f'%{category.lower()}%'))
    
    if location:
        users = users.filter(
            db.or_(
                db.func.lower(User.current_location).like(f'%{location.lower()}%'),
                db.func.lower(User.live_location).like(f'%{location.lower()}%')
            )
        )
    
    # Order by rating and paginate
    pagination = users.order_by(User.average_rating.desc()).paginate(
        page=page,
        per_page=9,
        error_out=False
    )
    users = pagination.items
    
    # Get unique categories and locations for filters
    categories = db.session.query(User.categories).distinct()
    categories = [cat[0] for cat in categories if cat[0]]
    categories = sorted(set(','.join(categories).split(',')))
    
    locations = db.session.query(User.current_location).distinct()
    locations = [loc[0] for loc in locations if loc[0]]
    locations = sorted(set(locations))
    
    # Print debug info
    print("Total users:", len(users))
    for user in users:
        print(f"User: {user.full_name}, Email: {user.email}")
    
    return render_template('index.html',
                         users=users,
                         pagination=pagination,
                         categories=categories,
                         locations=locations)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        # Get form data
        form_data = {
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'full_name': request.form.get('full_name'),
            'password': request.form.get('password'),
            'work': request.form.get('work'),
            'experience': request.form.get('experience'),
            'education': request.form.get('education'),
            'live_location': request.form.get('live_location'),
            'current_location': request.form.get('current_location'),
            'payment_type': request.form.get('payment_type'),
            'payment_charge': request.form.get('payment_charge'),
            'skills': request.form.get('skills', ''),  # Add skills with empty default
            'categories': request.form.get('categories', '')  # Add categories with empty default
        }
        
        # Store form data in session for repopulating the form
        session['registration_data'] = {k: v for k, v in form_data.items() if k != 'password'}
        
        # Validate required fields
        if not all(form_data.values()):
            flash('All fields marked with * are required', 'danger')
            return redirect(url_for('register'))
            
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", form_data['email']):
            flash('Invalid email format', 'danger')
            return redirect(url_for('register'))
            
        # Validate phone format (10 digits)
        phone = ''.join(filter(str.isdigit, form_data['phone']))
        if len(phone) != 10:
            flash('Invalid phone number format. Please enter 10 digits', 'danger')
            return redirect(url_for('register'))
            
        # Check if email already exists
        if User.query.filter_by(email=form_data['email']).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
            
        # Check if phone already exists
        if User.query.filter_by(phone=phone).first():
            flash('Phone number already registered', 'danger')
            return redirect(url_for('register'))

        # Handle photo upload
        photo = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename:
                # Secure the filename
                filename = secure_filename(file.filename)
                # Add timestamp to make filename unique
                name, ext = os.path.splitext(filename)
                filename = f"{name}_{int(datetime.utcnow().timestamp())}{ext}"
                # Save the file
                try:
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    photo = filename
                except Exception as e:
                    print(f"Error saving photo: {str(e)}")
                    flash('Error uploading photo. Please try again.', 'danger')
                    return redirect(url_for('register'))
        
        # Generate username from full name
        username = generate_username(form_data['full_name'])
        
        # Create new user
        try:
            user = User(
                email=form_data['email'],
                phone=phone,
                full_name=form_data['full_name'],
                username=username,
                password_hash=generate_password_hash(form_data['password']),
                work=form_data['work'],
                experience=form_data['experience'],
                education=form_data['education'],
                live_location=form_data['live_location'],
                current_location=form_data['current_location'],
                payment_type=form_data['payment_type'],
                payment_charge=float(form_data['payment_charge']),
                skills=form_data['skills'],  # Add skills
                categories=form_data['categories'],  # Add categories
                photo=photo
            )
            db.session.add(user)
            db.session.commit()
            
            # Clear stored form data after successful registration
            session.pop('registration_data', None)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            db.session.rollback()
            flash('Error creating account. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    # For GET request, get stored form data if it exists
    form_data = session.pop('registration_data', {})
    return render_template('register.html', form_data=form_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember', False) == 'on'
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.is_online = True
            user.availability = "available"
            user.last_active = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('index')
            
            flash('Logged in successfully!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Update user status before logging out
    current_user.availability = "unavailable"
    current_user.is_online = False
    current_user.last_active = datetime.utcnow()
    db.session.commit()
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

profile_cache = {}
def get_cached_profile(user_id, max_age=300):  # 5 minutes cache
    cache_key = f'profile_{user_id}'
    cached = profile_cache.get(cache_key)
    if cached and (datetime.utcnow() - cached['timestamp']).seconds < max_age:
        return cached['data']
    return None

@app.route('/profile/<int:user_id>')
def profile(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.is_authenticated and current_user.id == user_id:
        return redirect(url_for('account'))
    
    cached_profile = get_cached_profile(user_id)
    if cached_profile:
        return cached_profile
    
    reviews = user.reviews_received.order_by(Review.created_at.desc()).limit(5).all()
    
    response = render_template('profile.html', user=user, reviews=reviews)
    profile_cache[user_id] = {
        'content': response,
        'timestamp': time.time()
    }
    return response

@app.route('/handle-contact-request/<int:request_id>/<string:action>')
@login_required
def handle_contact_request(request_id, action):
    contact_request = ContactRequest.query.get_or_404(request_id)
    
    # Verify the current user is the one who received the request
    if contact_request.requested_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    
    if action == 'accept':
        contact_request.status = 'accepted'
        flash('Contact request accepted!', 'success')
    elif action == 'reject':
        contact_request.status = 'rejected'
        flash('Contact request rejected.', 'info')
    
    db.session.commit()
    return redirect(url_for('profile', user_id=contact_request.requester_id))

@app.route('/review/<int:worker_id>', methods=['GET', 'POST'])
@login_required
def review(worker_id):
    worker = User.query.get_or_404(worker_id)
    
    # Check if user is trying to review themselves
    if current_user.id == worker_id:
        flash('You cannot review yourself.', 'error')
        return redirect(url_for('profile', user_id=worker_id))
    
    # Check if user has already reviewed this worker
    existing_review = Review.query.filter_by(
        worker_id=worker_id,
        reviewer_id=current_user.id
    ).first()
    
    if request.method == 'POST':
        if existing_review:
            flash('You have already reviewed this worker.', 'error')
            return redirect(url_for('profile', user_id=worker_id))
        
        rating = request.form.get('rating', type=int)
        comment = request.form.get('comment', '').strip()
        
        if not rating or not 1 <= rating <= 5:
            flash('Please provide a valid rating between 1 and 5.', 'error')
            return redirect(url_for('review', worker_id=worker_id))
        
        if not comment:
            flash('Please provide a review comment.', 'error')
            return redirect(url_for('review', worker_id=worker_id))
        
        # Create new review
        review = Review(
            worker_id=worker_id,
            reviewer_id=current_user.id,
            rating=rating,
            comment=comment
        )
        db.session.add(review)
        
        try:
            # Update worker's average rating and total reviews count
            worker.total_reviews += 1
            total_rating = sum(r.rating for r in worker.reviews_received.all())
            worker.average_rating = round((total_rating + rating) / worker.total_reviews, 1)
            
            db.session.commit()
            flash('Your review has been submitted successfully!', 'success')
            return redirect(url_for('profile', user_id=worker_id))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting your review. Please try again.', 'error')
            return redirect(url_for('review', worker_id=worker_id))
    
    return render_template('review.html', worker=worker, existing_review=existing_review)

@app.route('/message/<int:user_id>', methods=['GET', 'POST'])
@login_required
def message(user_id):
    recipient = User.query.get_or_404(user_id)
    if recipient.id == current_user.id:
        flash('You cannot message yourself', 'danger')
        return redirect(url_for('profile', user_id=user_id))
    
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            message = Message(
                sender_id=current_user.id,
                recipient_id=recipient.id,
                content=content
            )
            db.session.add(message)
            db.session.commit()
            flash('Message sent successfully', 'success')
            return redirect(url_for('messages'))
    
    messages = Message.query.filter(
        db.or_(
            db.and_(Message.sender_id == current_user.id, Message.recipient_id == recipient.id),
            db.and_(Message.sender_id == recipient.id, Message.recipient_id == current_user.id)
        )
    ).order_by(Message.created_at.desc()).all()
    
    return render_template('chat.html', recipient=recipient, messages=messages)

@app.route('/messages')
@login_required
def messages():
    messages_received = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.created_at.desc()).all()
    messages_sent = Message.query.filter_by(sender_id=current_user.id).order_by(Message.created_at.desc()).all()
    return render_template('message_list.html', messages_received=messages_received, messages_sent=messages_sent)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            try:
                # Check if email or phone is being changed and verify uniqueness
                new_email = request.form.get('email')
                new_phone = request.form.get('phone')
                
                if new_email != current_user.email:
                    if User.query.filter_by(email=new_email).first():
                        flash('Email already exists', 'danger')
                        return redirect(url_for('account'))
                
                if new_phone != current_user.phone:
                    if User.query.filter_by(phone=new_phone).first():
                        flash('Phone number already exists', 'danger')
                        return redirect(url_for('account'))
                
                # Required fields validation
                if not new_email or not new_phone or not request.form.get('full_name'):
                    flash('Name, email and phone are required fields', 'danger')
                    return redirect(url_for('account'))
                
                # Update user information with proper type conversion
                current_user.full_name = request.form.get('full_name')
                current_user.phone = new_phone
                current_user.email = new_email
                current_user.mother_name = request.form.get('mother_name')
                current_user.father_name = request.form.get('father_name')
                current_user.live_location = request.form.get('live_location')
                current_user.current_location = request.form.get('current_location')
                current_user.work = request.form.get('work')
                current_user.experience = request.form.get('experience')
                current_user.education = request.form.get('education')
                
                # Convert age to integer if provided
                age = request.form.get('age')
                current_user.age = int(age) if age else None
                
                current_user.payment_type = request.form.get('payment_type')
                
                # Convert payment_charge to float if provided
                payment_charge = request.form.get('payment_charge')
                current_user.payment_charge = float(payment_charge) if payment_charge else None
                
                current_user.skills = request.form.get('skills')
                current_user.categories = request.form.get('categories')
                current_user.bio = request.form.get('bio')
                
                if 'photo' in request.files:
                    photo = request.files['photo']
                    if photo.filename:
                        # Validate file type
                        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                        if '.' in photo.filename and photo.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                            filename = secure_filename(photo.filename)
                            # Delete old photo if exists
                            if current_user.photo:
                                try:
                                    old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.photo)
                                    if os.path.exists(old_photo_path):
                                        os.remove(old_photo_path)
                                except Exception as e:
                                    print(f"Error deleting old photo: {e}")
                            current_user.photo = filename
                            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        else:
                            flash('Invalid file type. Please upload an image file.', 'danger')
                            return redirect(url_for('account'))
                
                db.session.commit()
                flash('Profile updated successfully!', 'success')
                
            except ValueError:
                db.session.rollback()
                flash('Invalid input for age or payment charge. Please enter valid numbers.', 'danger')
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while updating your profile. Please try again.', 'danger')
                print(f"Error updating profile: {e}")
        
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'danger')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password changed successfully!', 'success')
        
        elif action == 'delete_account':
            password = request.form.get('confirm_delete_password')
            if current_user.check_password(password):
                # Delete user's photo if exists
                if current_user.photo:
                    try:
                        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.photo)
                        if os.path.exists(photo_path):
                            os.remove(photo_path)
                    except Exception as e:
                        print(f"Error deleting photo: {e}")
                
                # Delete user's reviews
                Review.query.filter(
                    db.or_(
                        Review.reviewer_id == current_user.id,
                        Review.worker_id == current_user.id
                    )
                ).delete()
                
                # Delete user's messages
                Message.query.filter(
                    db.or_(
                        Message.sender_id == current_user.id,
                        Message.recipient_id == current_user.id
                    )
                ).delete()
                
                # Delete the user
                db.session.delete(current_user)
                db.session.commit()
                logout_user()
                flash('Your account has been deleted', 'success')
                return redirect(url_for('index'))
            else:
                flash('Incorrect password', 'danger')
        
        return redirect(url_for('account'))
    
    return render_template('account.html', user=current_user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please enter your email address.', 'danger')
            return render_template('forgot_password.html')

        user = User.query.filter_by(email=email).first()
        
        if user:
            try:
                # Generate token
                token = serializer.dumps(user.email, salt='password-reset-salt')
                
                # Create reset URL
                reset_url = url_for('reset_password', token=token, _external=True)
                
                # Send email
                if send_reset_email(user.email, reset_url):
                    flash('Password reset instructions have been sent to your email.', 'success')
                else:
                    flash('Error sending reset email. Please try again later.', 'danger')
            except Exception as e:
                app.logger.error(f"Password reset error for {email}: {str(e)}")
                flash('An error occurred. Please try again later.', 'danger')
        else:
            # Don't reveal if email exists or not for security
            flash('If an account exists with that email, you will receive password reset instructions.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid reset link. Please try again.', 'danger')
            return redirect(url_for('forgot_password'))
        
        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if not password or not confirm_password:
                flash('Please fill in all fields.', 'danger')
                return render_template('reset_password.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('reset_password.html')
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return render_template('reset_password.html')
            
            user.set_password(password)
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
            
            flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset_password.html')
        
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request_error(error):
    if 'csrf_token' in str(error):
        return jsonify({
            'success': False,
            'message': 'Invalid CSRF token. Please refresh the page and try again.'
        }), 400
    return jsonify({
        'success': False,
        'message': 'Bad request. Please try again.'
    }), 400

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.is_json:
        return jsonify({
            'success': False,
            'message': 'Invalid CSRF token. Please refresh the page and try again.'
        }), 400
    flash('Session expired. Please try again.', 'danger')
    return redirect(request.referrer or url_for('login'))

# Admin Routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_transactions = Transaction.query.count()
    total_contact_requests = ContactRequest.query.count()
    total_reviews = Review.query.count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_transactions=total_transactions,
                         total_contact_requests=total_contact_requests,
                         total_reviews=total_reviews,
                         recent_users=recent_users,
                         recent_transactions=recent_transactions)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<username>')
@login_required
@admin_required
def admin_user_detail(username):
    user = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST':
        user.is_admin = 'is_admin' in request.form
        user.availability = request.form.get('availability')
        db.session.commit()
        flash(_('User updated successfully'), 'success')
    return render_template('admin/user_detail.html', user=user)

@app.route('/admin/transactions')
@login_required
@admin_required
def admin_transactions():
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    return render_template('admin/transactions.html', transactions=transactions)

@app.route('/admin/contact-requests')
@login_required
@admin_required
def admin_contact_requests():
    requests = ContactRequest.query.order_by(ContactRequest.created_at.desc()).all()
    return render_template('admin/contact_requests.html', requests=requests)

@app.route('/admin/reviews')
@login_required
@admin_required
def admin_reviews():
    reviews = Review.query.order_by(Review.created_at.desc()).all()
    datatable_translations = {
        'search': _('Search'),
        'lengthMenu': _('Show _MENU_ entries'),
        'info': _('Showing _START_ to _END_ of _TOTAL_ entries'),
        'infoEmpty': _('Showing 0 to 0 of 0 entries'),
        'infoFiltered': _('(filtered from _MAX_ total entries)'),
        'emptyTable': _('No data available in table'),
        'zeroRecords': _('No matching records found'),
        'first': _('First'),
        'last': _('Last'),
        'next': _('Next'),
        'previous': _('Previous')
    }
    return render_template('admin/reviews.html', reviews=reviews, translations=datatable_translations)

@app.route('/admin/review/<int:review_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    worker = User.query.get(review.worker_id)
    db.session.delete(review)
    worker.update_rating()
    db.session.commit()
    flash(_('Review deleted successfully'), 'success')
    return redirect(url_for('admin_reviews'))

# Add these Socket.IO event handlers before the if __name__ == '__main__': block
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)

@socketio.on('send_message')
def handle_message(data):
    receiver_id = data['receiver_id']
    message_content = data['message']
    
    # Save message to database
    message = Message(
        sender_id=current_user.id,
        recipient_id=receiver_id,
        content=message_content
    )
    db.session.add(message)
    db.session.commit()
    
    # Emit to receiver's room
    receiver_room = f'user_{receiver_id}'
    emit('new_message', {
        'content': message_content,
        'sender_id': current_user.id,
        'timestamp': message.created_at.strftime('%H:%M')
    }, room=receiver_room)

@socketio.on('heartbeat')
def handle_heartbeat():
    if current_user.is_authenticated:
        current_user.last_active = datetime.utcnow()
        current_user.is_online = True
        db.session.commit()
        return {'status': 'ok'}

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.is_online = True
        current_user.last_active = datetime.utcnow()
        db.session.commit()
        # Broadcast to all clients that this user is online
        emit('user_status_change', {
            'user_id': current_user.id,
            'is_online': True
        }, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        current_user.is_online = False
        current_user.last_active = datetime.utcnow()
        db.session.commit()
        # Broadcast to all clients that this user is offline
        emit('user_status_change', {
            'user_id': current_user.id,
            'is_online': False
        }, broadcast=True)

@login_manager.user_loader
@cache.memoize(timeout=300)
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    if not hasattr(g, 'start_time'):
        g.start_time = time.time()

@app.after_request
def after_request(response):
    if hasattr(g, 'start_time'):
        elapsed = time.time() - g.start_time
        app.logger.info(f'Request completed in {elapsed:.2f}s')
    return response

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

@cache.memoize(timeout=300)
def get_user_profile(user_id):
    return User.query.get_or_404(user_id)

@cache.memoize(timeout=300)
def get_user_reviews(user_id):
    return Review.query.filter_by(worker_id=user_id).order_by(Review.created_at.desc()).all()

@app.route('/api/check_contact_payment/<int:user_id>/<contact_type>')
def check_contact_payment(user_id, contact_type):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    target_user = User.query.get_or_404(user_id)
    
    if contact_type == 'chat':
        # For chat, check payment required
        payment_required = True
        amount = target_user.payment_charge if target_user.payment_charge else 0
    else:
        # For email and call, no payment required
        payment_required = False
        amount = 0
    
    return jsonify({
        'payment_required': payment_required,
        'amount': amount,
        'email': target_user.email if not payment_required else None,
        'phone': target_user.phone if not payment_required else None
    })

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('fuetime.db'):
            db.create_all()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
