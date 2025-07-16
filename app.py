import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify , send_file , make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import case, distinct, func
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from io import BytesIO
import pdfkit
import traceback
import smtplib
import random
from email.message import EmailMessage
from dotenv import load_dotenv
import zipfile
from werkzeug.utils import secure_filename # Import secure_filename

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:5539@localhost/sakecha')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads' # Define an upload folder

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# SMTP Configuration - directly in code
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
EMAIL_FROM = os.getenv('EMAIL_FROM', SMTP_USERNAME)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ROLE_ADMIN = 'admin'
ROLE_FRANCHISEE = 'franchisee'

class Booth(db.Model):
    __tablename__ = 'booths'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    location = db.Column(db.String(255), nullable=True)
    users = db.relationship('User', back_populates='booth', lazy='dynamic')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    booth_id = db.Column(db.Integer, db.ForeignKey('booths.id'), nullable=True)
    approved = db.Column(db.Boolean, default=False, nullable=False)
    booth = db.relationship('Booth', back_populates='users')
    reset_token = db.Column(db.String(6), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def send_reset_email(to_email, token):
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Password Reset Token for SAKECHA'
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        msg.set_content(f'''Dear User,
You requested a password reset.
Please use the following 6-digit token to reset your password:
{token}
This token will expire in 15 minutes.
If you did not request this, please ignore this email.
Best regards,
SAKECHA Team
''')
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

class SalesEntry(db.Model):
    __tablename__ = 'sales_entries'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    date = db.Column(db.Date, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False) # New timestamp field
    drink_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    booth_id = db.Column(db.Integer, db.ForeignKey('booths.id'), nullable=False)

    booth = db.relationship('Booth', backref='sales_entries')

class AttendanceLog(db.Model):
    __tablename__ = 'attendance_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    date = db.Column(db.Date, nullable=False)
    present = db.Column(db.Boolean, nullable=False)
    booth_id = db.Column(db.Integer, db.ForeignKey('booths.id'), nullable=False)
    booth = db.relationship('Booth')

class IngredientReorder(db.Model):
    __tablename__ = 'ingredient_reorders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    booth_id = db.Column(db.Integer, db.ForeignKey('booths.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    ingredient_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    cost = db.Column(db.Float, nullable=False)  # New cost field
    status = db.Column(db.String(50), default='Pending')
    receipt_filepath = db.Column(db.String(255), nullable=True)
    booth = db.relationship('Booth', backref='ingredient_reorders')


class BoothChangeRequest(db.Model):
    __tablename__ = 'booth_change_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    requested_booth_id = db.Column(db.Integer, db.ForeignKey('booths.id'), nullable=False)
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')
    requested_booth = db.relationship('Booth')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.approved:
                message = 'Your account is awaiting admin approval and cannot be used yet.'
            else:
                login_user(user)
                flash('Logged in successfully.', 'success')
                return redirect(url_for('dashboard'))
        else:
            message = 'Invalid username or password'
    return render_template('login.html', message=message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    username_exists = False
    email_exists = False
    booths = Booth.query.order_by(Booth.name).all()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        booth_id = request.form.get('booth_id')
        username_exists = User.query.filter_by(username=username).first() is not None
        email_exists = User.query.filter_by(email=email).first() is not None
        if username_exists or email_exists:
            return render_template(
                'register.html',
                username_exists=username_exists,
                email_exists=email_exists,
                username=username,
                email=email,
                booths=booths,
                selected_booth_id=booth_id
            )
        else:
            new_user = User(username=username, email=email, role=ROLE_FRANCHISEE, approved=False)
            if booth_id and booth_id.isdigit():
                booth = Booth.query.get(int(booth_id))
                if booth:
                    new_user.booth = booth
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Awaiting admin approval before you can log in.', 'info')
            return redirect(url_for('login'))
    return render_template(
        'register.html',
        username_exists=False,
        email_exists=False,
        username='',
        email='',
        booths=booths,
        selected_booth_id=None
    )

@app.route('/approve_user', methods=['POST'])
@login_required
def approve_user():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Missing user ID'}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    user.approved = True
    db.session.commit()
    return jsonify({'success': True, 'message': 'User approved successfully'})

@app.route('/reject_user', methods=['POST'])
@login_required
def reject_user():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Missing user ID'}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'User rejected and deleted'})

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate 6-digit token
            token = f"{random.randint(0, 999999):06d}"
            user.reset_token = token
            user.reset_token_expiration = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
            # Send reset email with token
            send_reset_email(user.email, token)
            flash('A 6-digit password reset token has been sent to your email.', 'info')
            return redirect(url_for('reset_password'))
        else:
            message = 'Email not found.'
    return render_template('forgot_password.html', message=message)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    message = ''
    if request.method == 'POST':
        email = request.form.get('email')
        token = request.form.get('token')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not email or not token or not new_password or not confirm_password:
            message = 'Please fill in all fields.'
        elif new_password != confirm_password:
            message = 'Passwords do not match.'
        else:
            user = User.query.filter_by(email=email).first()
            if not user:
                message = 'Invalid email.'
            elif not user.reset_token or not user.reset_token_expiration:
                message = 'No reset token found for this user. Please request a new password reset.'
            elif user.reset_token != token:
                message = 'Invalid token.'
            elif datetime.utcnow() > user.reset_token_expiration:
                message = 'Token has expired. Please request a new password reset.'
            else:
                # Token valid, reset password
                user.set_password(new_password)
                user.reset_token = None
                user.reset_token_expiration = None
                db.session.commit()
                flash('Password reset successful! You can now log in.', 'success')
                return redirect(url_for('login'))
    return render_template('reset_password.html', message=message)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    message = ''
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not current_password or not new_password or not confirm_password:
            message = 'Please fill in all password fields.'
        elif new_password != confirm_password:
            message = 'New passwords do not match.'
        elif not current_user.check_password(current_password):
            message = 'Current password is incorrect.'
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully.', 'success')
            return redirect(url_for('profile'))

    all_booths = Booth.query.order_by(Booth.name).all()

    return render_template('profile.html',
                                  user=current_user,
                                  message=message,
                                  is_admin=(current_user.role == ROLE_ADMIN),
                                  active_page='profile',
                                  all_booths=all_booths,
                                  is_franchisee=(current_user.role == ROLE_FRANCHISEE))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    from sqlalchemy import func
    from datetime import datetime
    today = datetime.utcnow().date()

    if current_user.role == ROLE_ADMIN:
        last_month = today.replace(day=1)

        # Sales summary: total sales per booth in last month
        sales_summary = db.session.query(
            Booth.name,
            func.sum(SalesEntry.quantity).label('total_sales')
        ).join(Booth, SalesEntry.booth_id == Booth.id) \
         .filter(SalesEntry.date >= last_month) \
         .group_by(Booth.name) \
         .order_by(func.sum(SalesEntry.quantity).desc()) \
         .limit(5).all()

        # Late reporters: franchisees who have not submitted sales today
        subquery = db.session.query(SalesEntry.user_id).filter(SalesEntry.date == today).subquery()
        late_users = User.query.filter(
            User.role == ROLE_FRANCHISEE,
            ~User.id.in_(subquery),
            User.booth_id.isnot(None)
        ).all()
        late_booth_ids = set(user.booth_id for user in late_users if user.booth_id)
        late_reporters = Booth.query.filter(Booth.id.in_(late_booth_ids)).order_by(Booth.name).all()

        # Total sales this month
        total_sales = db.session.query(func.sum(SalesEntry.quantity)).filter(SalesEntry.date >= last_month).scalar() or 0

        # Ingredient reorder requests this month with stored usernames
        ingredient_requests = db.session.query(
            IngredientReorder.id,
            Booth.name,
            IngredientReorder.date,
            IngredientReorder.username,
            IngredientReorder.ingredient_name,
            IngredientReorder.quantity,
            IngredientReorder.cost,  # Include cost
            IngredientReorder.status,
            IngredientReorder.receipt_filepath
        ).join(Booth, IngredientReorder.booth_id == Booth.id) \
        .filter(IngredientReorder.date >= last_month) \
        .order_by(IngredientReorder.date.desc(), IngredientReorder.id.desc()) \
        .all()

        # Pending account creations awaiting approval
        pending_accounts = User.query.filter_by(approved=False).order_by(User.username).all()

        # Pending booth change requests
        pending_booth_changes = db.session.query(
            BoothChangeRequest.id,
            User.username,
            Booth.name.label('requested_booth_name')
        ).join(User, BoothChangeRequest.user_id == User.id) \
         .join(Booth, BoothChangeRequest.requested_booth_id == Booth.id) \
         .filter(BoothChangeRequest.status == 'Pending') \
         .order_by(User.username) \
         .all()

        # Render admin dashboard with clean, elegant UI
        return render_template('admin_dashboard.html',
                                      sales_summary=sales_summary,
                                      late_reporters=late_reporters,
                                      total_sales=total_sales,
                                      ingredient_requests=ingredient_requests,
                                      pending_accounts=pending_accounts,
                                      pending_booth_changes=pending_booth_changes,
                                      active_page='dashboard')

    else:
        # Franchisee dashboard
        sales_entered = SalesEntry.query.filter_by(user_id=current_user.id, date=today).first() is not None
        attendance_logged = AttendanceLog.query.filter_by(user_id=current_user.id, date=today).first() is not None

        # Ingredient reorder requests by booth without joining User (using stored username)
        ingredient_requests = IngredientReorder.query.filter_by(booth_id=current_user.booth_id) \
                                                        .order_by(IngredientReorder.date.desc(), IngredientReorder.id.desc()) \
                                                        .all()

        booth_name = current_user.booth.name if current_user.booth else None

        # Render franchisee dashboard with existing UI and data
        return render_template('franchisee_dashboard.html',
                                      sales_entered=sales_entered,
                                      attendance_logged=attendance_logged,
                                      booth_name=booth_name,
                                      ingredient_requests=ingredient_requests,
                                      active_page='dashboard')

@app.route('/sales_entry', methods=['GET', 'POST'])
@login_required
def sales_entry():
    if current_user.role != ROLE_FRANCHISEE:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('dashboard'))

    message = ''
    if request.method == 'POST':
        drink_names = request.form.getlist('drink_name[]')
        quantities = request.form.getlist('quantity[]')

        if not drink_names or not quantities or len(drink_names) != len(quantities):
            message = 'Please enter at least one valid drink and quantity.'
        else:
            valid_entries = []
            for drink, qty in zip(drink_names, quantities):
                drink = drink.strip()
                if not drink:
                    continue
                if not qty.isdigit() or int(qty) < 0:
                    continue
                valid_entries.append((drink, int(qty)))

            if not valid_entries:
                message = 'Please enter at least one valid drink with a non-negative quantity.'
            else:
                booth_id = current_user.booth_id
                if booth_id is None:
                    message = 'No booth assigned to your account; cannot submit sales entry.'
                else:
                    for drink, qty in valid_entries:
                        # Always create a new entry for each sale
                        new_entry = SalesEntry(
                            user_id=current_user.id,
                            date=datetime.utcnow().date(), # Date of the sale
                            timestamp=datetime.utcnow(), # Timestamp of the sale
                            drink_name=drink,
                            quantity=qty,
                            booth_id=booth_id
                        )
                        db.session.add(new_entry)
                    db.session.commit()
                    flash('Sales entries recorded.', 'success')
                    return redirect(url_for('dashboard'))
    return render_template('sales_entry_form.html', message=message, today=datetime.utcnow().date().isoformat())

@app.route('/attendance_log', methods=['GET', 'POST'])
@login_required
def attendance_log():
    message = ''
    if request.method == 'POST':
        try:
            entry_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        except Exception:
            entry_date = datetime.utcnow().date()
        present = request.form.get('present') == 'on'
        booth_id = current_user.booth_id
        if not booth_id:
            message = "No booth assigned to your account; cannot log attendance."
        else:
            existing_log = AttendanceLog.query.filter_by(user_id=current_user.id, date=entry_date).first()
            if existing_log:
                existing_log.present = present
            else:
                new_log = AttendanceLog(
                    user_id=current_user.id,
                    username=current_user.username,
                    date=entry_date,
                    present=present,
                    booth_id=booth_id
                )
                db.session.add(new_log)
            db.session.commit()
            flash('Attendance logged.', 'success')
            return redirect(url_for('dashboard'))
    return render_template('attendance_log_form.html', today=datetime.utcnow().date().isoformat(), message=message)

@app.route('/ingredient_reorder', methods=['GET', 'POST'])
@login_required
def ingredient_reorder():
    message = ''
    if request.method == 'POST':
        try:
            entry_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        except Exception:
            entry_date = datetime.utcnow().date()

        ingredient_name = request.form.get('ingredient_name', '').strip()
        quantity_str = request.form.get('quantity', '').strip()
        cost_str = request.form.get('cost', '').strip()  # Get cost input
        receipt_file = request.files.get('receipt_attachment')

        if not ingredient_name or not quantity_str.isdigit() or not cost_str.replace('.','',1).isdigit():
            message = 'Invalid input. Please enter an ingredient name, valid quantity, and valid cost.'
        elif not receipt_file:
            message = 'Payment receipt is required.'
        else:
            quantity = int(quantity_str)
            cost = float(cost_str)
            booth_id = current_user.booth_id
            if not booth_id:
                message = "You have no booth assigned; cannot submit reorder request."
            else:
                filename = secure_filename(receipt_file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                receipt_file.save(filepath)

                reorder = IngredientReorder(
                    user_id=current_user.id,
                    username=current_user.username,
                    booth_id=booth_id,
                    date=entry_date,
                    ingredient_name=ingredient_name,
                    quantity=quantity,
                    cost=cost,  # Include cost
                    status='Pending',
                    receipt_filepath=filepath
                )
                db.session.add(reorder)
                db.session.commit()
                flash('Ingredient reorder request submitted.', 'success')
                return redirect(url_for('dashboard'))
    return render_template('ingredient_reorder_form.html', today=datetime.utcnow().date().isoformat(), message=message)

@app.route('/view_receipt/<int:request_id>')
@login_required
def view_receipt(request_id):
    ingredient_request = IngredientReorder.query.get(request_id)
    if not ingredient_request or not ingredient_request.receipt_filepath:
        flash('Receipt not found.', 'danger')
        return redirect(url_for('dashboard')) # Or a more appropriate error page

    # Ensure the user is authorized to view the receipt
    if current_user.role == ROLE_FRANCHISEE and ingredient_request.user_id != current_user.id:
        flash('Unauthorized to view this receipt.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        return send_file(ingredient_request.receipt_filepath, as_attachment=False)
    except FileNotFoundError:
        flash('File not found on server.', 'danger')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error serving file: {e}', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/update_ingredient_status', methods=['POST'])
@login_required
def update_ingredient_status():
    if current_user.role != ROLE_ADMIN:
        return {'success': False, 'message': 'Unauthorized'}, 403

    try:
        data = request.get_json()
        request_id = data.get('request_id')
        new_status = data.get('status')

        if not request_id or not new_status:
            return {'success': False, 'message': 'Missing request ID or status'}, 400

        if new_status not in ['Approved', 'Rejected', 'Pending']:
            return {'success': False, 'message': 'Invalid status'}, 400

        ingredient_request = IngredientReorder.query.get(request_id)
        if not ingredient_request:
            return {'success': False, 'message': 'Request not found'}, 404

        ingredient_request.status = new_status
        db.session.commit()

        return {'success': True, 'message': 'Status updated successfully'}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}, 500

@app.route('/delete_ingredient_request', methods=['POST'])
@login_required
def delete_ingredient_request():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        request_id = data.get('request_id')
        if not request_id:
            return jsonify({'success': False, 'message': 'Missing request ID'}), 400

        ingredient_request = IngredientReorder.query.get(request_id)
        if not ingredient_request:
            return jsonify({'success': False, 'message': 'Request not found'}), 404

        # Optionally delete the file from the server if it exists
        if ingredient_request.receipt_filepath and os.path.exists(ingredient_request.receipt_filepath):
            os.remove(ingredient_request.receipt_filepath)

        db.session.delete(ingredient_request)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Request deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/request_booth_change', methods=['POST'])
@login_required
def request_booth_change():
    if current_user.role != ROLE_FRANCHISEE:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    new_booth_id = request.form.get('booth_id')
    if not new_booth_id or not new_booth_id.isdigit():
        return jsonify({'success': False, 'message': 'Invalid booth selection'}), 400

    booth = Booth.query.get(int(new_booth_id))
    if not booth:
        return jsonify({'success': False, 'message': 'Booth not found'}), 404

    # Check if user already has a pending request
    existing_request = BoothChangeRequest.query.filter_by(
        user_id=current_user.id,
        status='Pending'
    ).first()

    if existing_request:
        return jsonify({
            'success': False,
            'message': 'You already have a pending booth change request'
        }), 400

    # Create new request
    new_request = BoothChangeRequest(
        user_id=current_user.id,
        requested_booth_id=booth.id,
        status='Pending'
    )
    db.session.add(new_request)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Booth change request submitted for approval.'
    })

@app.route('/approve_booth_change', methods=['POST'])
@login_required
def approve_booth_change():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        request_id = data.get('request_id')
        if not request_id:
            return jsonify({'success': False, 'message': 'Missing request ID'}), 400

        booth_change_request = BoothChangeRequest.query.get(request_id)
        if not booth_change_request:
            return jsonify({'success': False, 'message': 'Request not found'}), 404

        # Update user's booth
        user = booth_change_request.user
        user.booth_id = booth_change_request.requested_booth_id

        # Update request status
        booth_change_request.status = 'Approved'

        db.session.commit()

        return jsonify({'success': True, 'message': 'Booth change approved successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/reject_booth_change', methods=['POST'])
@login_required
def reject_booth_change():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json()
    request_id = data.get('request_id')
    if not request_id:
        return jsonify({'success': False, 'message': 'Missing request ID'}), 400

    booth_change_request = BoothChangeRequest.query.get(request_id)
    if not booth_change_request:
        return jsonify({'success': False, 'message': 'Request not found'}), 404

    # Update request status
    booth_change_request.status = 'Rejected'
    db.session.commit()

    return jsonify({'success': True, 'message': 'Booth change rejected'})


@app.route('/generate_report', methods=['GET', 'POST'])
@login_required
def generate_report():
    if current_user.role != ROLE_ADMIN:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        from sqlalchemy import func
        today = datetime.utcnow().date()
        first_day = today.replace(day=1)

        # Sales summary query: join Booth only by booth_id to keep existing data even if user deleted
        sales = db.session.query(
            Booth.name,
            SalesEntry.date,
            SalesEntry.drink_name,
            func.sum(SalesEntry.quantity)
        ).join(Booth, SalesEntry.booth_id == Booth.id) \
         .filter(SalesEntry.date >= first_day) \
         .group_by(Booth.name, SalesEntry.date, SalesEntry.drink_name) \
         .order_by(Booth.name, SalesEntry.date, SalesEntry.drink_name) \
         .all()

        # Attendance records query already safe with stored username and booth relationship
        attendance = db.session.query(
            AttendanceLog.username,
            Booth.name,
            AttendanceLog.date,
            AttendanceLog.present
        ).join(Booth, AttendanceLog.booth_id == Booth.id) \
         .filter(AttendanceLog.date >= first_day) \
         .order_by(AttendanceLog.username, Booth.name, AttendanceLog.date) \
         .all()

        # Ingredient reorder requests query including stored username and booth names (already safe)
        ingredient_reorders = db.session.query(
            IngredientReorder,
            Booth.name.label('booth_name')
        ).join(Booth, IngredientReorder.booth_id == Booth.id) \
         .filter(IngredientReorder.date >= first_day) \
         .order_by(IngredientReorder.date.desc(), IngredientReorder.id.desc()) \
         .all()

        # Transform ingredient_reorders into list of objects for template ease
        reordered_list = []
        for reorder, booth_name in ingredient_reorders:
            reordered_list.append({
                'date': reorder.date,
                'ingredient_name': reorder.ingredient_name,
                'quantity': reorder.quantity,
                'status': reorder.status,
                'username': reorder.username,
                'booth_name': booth_name
            })
        
        # New logic to handle multiple report types
        reports_to_generate = request.args.get('reports', '').split(',')
        
        # If no reports are selected, return to dashboard
        if not reports_to_generate or reports_to_generate == ['']:
             flash('Please select at least one report to generate.', 'warning')
             return redirect(url_for('dashboard'))

        pdf_files = {}
        
        month_year = first_day.strftime("%B %Y")
        
        # Determine the path for wkhtmltopdf
        # This will need to be configured in your .env file or manually set
        WKHTMLTOPDF_PATH = os.getenv('WKHTMLTOPDF_PATH') or r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
        config = None
        if WKHTMLTOPDF_PATH and os.path.exists(WKHTMLTOPDF_PATH):
            config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)
        options = {
            'page-size': 'A4',
            'encoding': "UTF-8",
        }
        
        if 'sales_summary' in reports_to_generate:
            sales_html = render_template('sales_report.html', sales=sales, month=month_year)
            pdf_sales = pdfkit.from_string(sales_html, False, options=options, configuration=config)
            pdf_files['sales_summary_report.pdf'] = pdf_sales
            
        if 'attendance_summary' in reports_to_generate:
            attendance_html = render_template('attendance_report.html', attendance=attendance, month=month_year)
            pdf_attendance = pdfkit.from_string(attendance_html, False, options=options, configuration=config)
            pdf_files['attendance_summary_report.pdf'] = pdf_attendance
            
        if 'ingredients_summary' in reports_to_generate:
            ingredients_html = render_template('ingredients_summary_report.html', ingredient_reorders=reordered_list, month=month_year)
            pdf_ingredients = pdfkit.from_string(ingredients_html, False, options=options, configuration=config)
            pdf_files['ingredients_summary_report.pdf'] = pdf_ingredients
            
        if 'all_info' in reports_to_generate:
            html = render_template('report.html', sales=sales, attendance=attendance, month=month_year, ingredient_reorders=reordered_list)
            pdf_full = pdfkit.from_string(html, False, options=options, configuration=config)
            pdf_files['monthly_report_all_info.pdf'] = pdf_full
            
        if len(pdf_files) == 1:
            filename = list(pdf_files.keys())[0]
            pdf_content = list(pdf_files.values())[0]
            return send_file(BytesIO(pdf_content), download_name=filename, as_attachment=True)
        elif len(pdf_files) > 1:
            memory_file = BytesIO()
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for filename, content in pdf_files.items():
                    zf.writestr(filename, content)
            memory_file.seek(0)
            return send_file(memory_file, download_name='monthly_reports.zip', as_attachment=True, mimetype='application/zip')
        else:
            flash('No reports selected to generate.', 'warning')
            return redirect(url_for('dashboard'))
            
    except Exception:
        error_msg = traceback.format_exc()
        return f"<h2>Error generating report</h2><pre>{error_msg}</pre>"

@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    if current_user.role != ROLE_ADMIN:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('dashboard'))
    from sqlalchemy import func
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        try:
            if form_type == 'assignments':
                # Update booth assignments and emails
                for key, value in request.form.items():
                    if key.startswith('booth_'):
                        user_id_str = key.split('_', 1)[1]
                        if not user_id_str.isdigit():
                            continue
                        user_id = int(user_id_str)
                        user = User.query.get(user_id)
                        if user and user.role == ROLE_FRANCHISEE:
                            new_booth_id = value.strip()
                            if new_booth_id == '':
                                user.booth = None
                            else:
                                if new_booth_id.isdigit():
                                    booth = Booth.query.get(int(new_booth_id))
                                    if booth:
                                        user.booth = booth
                    # Update email addresses
                    if key.startswith('email_'):
                        user_id_str = key.split('_', 1)[1]
                        if not user_id_str.isdigit():
                            continue
                        user_id = int(user_id_str)
                        user = User.query.get(user_id)
                        if user:
                            new_email = value.strip()
                            if new_email and validate_email(new_email): # Ensure valid email
                                user.email = new_email
                            else:
                                flash(f'Invalid email format for user {user.username}.', 'danger')
                db.session.commit()
                flash('User assignments and emails updated successfully.', 'success')
            elif form_type == 'locations':
                # Update booth locations
                for key, value in request.form.items():
                    if key.startswith('location_'):
                        booth_id_str = key.split('_', 1)[1]
                        if not booth_id_str.isdigit():
                            continue
                        booth_id = int(booth_id_str)
                        booth = Booth.query.get(booth_id)
                        if booth:
                            booth.location = value.strip()
                db.session.commit()
                flash('Booth locations updated successfully.', 'success')
            elif form_type == 'create_booth':
                # Create a new booth
                booth_name = request.form.get('booth_name', '').strip()
                booth_location = request.form.get('booth_location', '').strip()
                if not booth_name:
                    flash('Booth name is required.', 'danger')
                else:
                    existing_booth = Booth.query.filter_by(name=booth_name).first()
                    if existing_booth:
                        flash('A booth with this name already exists.', 'danger')
                    else:
                        new_booth = Booth(name=booth_name, location=booth_location)
                        db.session.add(new_booth)
                        db.session.commit()
                        flash(f'Booth "{booth_name}" created successfully.', 'success')
            else:
                flash('Unknown form submission.', 'warning')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating data: {str(e)}', 'danger')
        return redirect(url_for('users'))

    # GET request remains unchanged
    all_users = User.query.order_by(User.role.desc(), User.username).all()
    booths = db.session.query(
        Booth,
        func.count(User.id).label('employee_count')
    ).outerjoin(User).group_by(Booth.id).order_by(Booth.name).all()
    all_booths = Booth.query.order_by(Booth.name).all()
    return render_template('users.html', users=all_users, booths_with_counts=booths, all_booths=all_booths, active_page='users')

def validate_email(email):
    import re
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'message': 'Missing user ID'}), 400
        if int(user_id) == current_user.id:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'}), 400
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        # Allow deletion of user without affecting sales entries
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/delete_booth', methods=['POST'])
@login_required
def delete_booth():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    try:
        data = request.get_json()
        booth_id = data.get('booth_id')
        if not booth_id:
            return jsonify({'success': False, 'message': 'Missing booth ID'}), 400
        booth = Booth.query.get(booth_id)
        if not booth:
            return jsonify({'success': False, 'message': 'Booth not found'}), 404
        # Check if there are sales entries associated with this booth
        sales_entries = SalesEntry.query.filter_by(booth_id=booth.id).first()
        if sales_entries:
            return jsonify({'success': False, 'message': 'Cannot delete booth with existing sales entries.'}), 400
        # Unassign users assigned to this booth
        users_assigned = User.query.filter_by(booth_id=booth.id).all()
        for user in users_assigned:
            user.booth = None
        db.session.delete(booth)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Booth deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/sales')
@login_required
def sales():
    if current_user.role != ROLE_ADMIN:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    # Query all sales entries, ordered by timestamp
    sales_data = db.session.query(
        Booth.name.label('booth_name'),
        SalesEntry.date,
        SalesEntry.timestamp,  # Include timestamp
        SalesEntry.drink_name,
        SalesEntry.quantity
    ).join(Booth, SalesEntry.booth_id == Booth.id) \
     .order_by(SalesEntry.timestamp.desc()) \
     .all()

    # You might want to filter by month or a specific period as well, similar to the original query:
    # last_month = datetime.utcnow().date().replace(day=1)
    # .filter(SalesEntry.date >= last_month) \

    return render_template('admin_sales_page.html', sales_data=sales_data, month=datetime.utcnow().strftime("%B %Y"), active_page='sales')

@app.route('/booth_health')
@login_required
def booth_health():
    if current_user.role != ROLE_ADMIN:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('dashboard'))
    from sqlalchemy import func, extract, distinct

    # Query for booth statistics including total sales and average sales per day
    booth_stats = db.session.query(
        Booth.id,
        Booth.name,
        Booth.location,
        func.count(distinct(AttendanceLog.date)).label('days_active'),
        func.max(AttendanceLog.date).label('last_active_date'),
        func.coalesce(func.sum(SalesEntry.quantity), 0).label('total_sales'),
        func.coalesce(
            func.round(
                func.sum(SalesEntry.quantity) / func.nullif(func.count(distinct(SalesEntry.date)), 0), 2
            ), 0
        ).label('avg_sales_per_day')
    ).outerjoin(
        AttendanceLog,
        AttendanceLog.booth_id == Booth.id
    ).outerjoin(
        SalesEntry,
        SalesEntry.booth_id == Booth.id
    ).group_by(
        Booth.id,
        Booth.name,
        Booth.location
    ).all()

    all_booth_performance = []
    booth_a_data = None
    booth_b_data = None

    for booth in booth_stats:
        booth_data = {
            'id': booth.id,
            'name': booth.name,
            'location': booth.location,
            'days_active': booth.days_active,
            'last_active_date': booth.last_active_date.strftime('%Y-%m-%d') if booth.last_active_date else 'N/A',
            'total_sales': booth.total_sales,
            'avg_sales_per_day': booth.avg_sales_per_day
        }
        all_booth_performance.append(booth_data)

        if booth.name == 'Booth A':
            booth_a_data = booth_data
        elif booth.name == 'Booth B':
            booth_b_data = booth_data

    underperforming_booths = []
    underperforming_comparison_message = ""

    if booth_a_data and booth_b_data:
        # Compare total sales between Booth A and Booth B
        sales_a = booth_a_data['total_sales']
        sales_b = booth_b_data['total_sales']

        if sales_a < sales_b:
            underperforming_booths.append(booth_a_data)
            underperforming_comparison_message = f"Booth A has lower sales ({sales_a}) compared to Booth B ({sales_b})."
        elif sales_b < sales_a:
            underperforming_booths.append(booth_b_data)
            underperforming_comparison_message = f"Booth B has lower sales ({sales_b}) compared to Booth A ({sales_a})."
        else:
            underperforming_comparison_message = "Booth A and Booth B have equal sales."
    elif booth_a_data and not booth_b_data:
        underperforming_comparison_message = "Only Booth A data available for comparison."
    elif not booth_a_data and booth_b_data:
        underperforming_comparison_message = "Only Booth B data available for comparison."
    else:
        underperforming_comparison_message = "Not enough data for Booth A and Booth B comparison."


    return render_template('booth_health.html',
                           all_booth_performance=all_booth_performance,
                           underperforming_booths=underperforming_booths,
                           underperforming_comparison_message=underperforming_comparison_message, # New variable
                           active_page='booth_health')

@app.route('/get_booth_attendance/<int:booth_id>')
@login_required
def get_booth_attendance(booth_id):
    if current_user.role != ROLE_ADMIN:
        return jsonify({'error': 'Unauthorized'}), 403

    booth = Booth.query.get(booth_id)
    if not booth:
        return jsonify({'error': 'Booth not found'}), 404

    attendance_records = db.session.query(
        AttendanceLog.date,
        func.string_agg(User.username, ', ').label('users'),
        func.count(distinct(AttendanceLog.user_id)).filter(AttendanceLog.present == True).label('present_count'),
        func.count(distinct(AttendanceLog.user_id)).label('total_count')
    ).join(User, AttendanceLog.user_id == User.id) \
    .filter(AttendanceLog.booth_id == booth_id) \
    .group_by(
        AttendanceLog.date
    ).order_by(
        AttendanceLog.date.desc()
    ).all()

    records = [{
        'date': record.date.strftime('%Y-%m-%d'),
        'users': record.users.split(', ') if record.users else [],
        'present_count': record.present_count,
        'total_count': record.total_count
    } for record in attendance_records]

    return jsonify(records)

@app.cli.command('initdb')
def initdb_command():
    db.drop_all()
    db.create_all()

    # Create booths
    booth_a = Booth(name='Booth A', location='North Wing')
    booth_b = Booth(name='Booth B', location='South Food Court')
    booth_c = Booth(name='Booth C', location='Mall Entrance') # New booth for testing no sales/underperformance
    db.session.add(booth_a)
    db.session.add(booth_b)
    db.session.add(booth_c) # Add new booth
    db.session.commit()

    # Create admin user with email and approved status
    admin = User(username='admin', email='admin@example.com', role=ROLE_ADMIN, approved=True)
    admin.set_password('adminpass')
    db.session.add(admin)

    # Create franchisee users with booths assigned and approved status
    f1 = User(username='booth1', email='booth1@example.com', role=ROLE_FRANCHISEE, booth=booth_a, approved=True)
    f1.set_password('pass1')
    db.session.add(f1)

    f2 = User(username='booth2', email='booth2@example.com', role=ROLE_FRANCHISEE, booth=booth_b, approved=True)
    f2.set_password('pass2')
    db.session.add(f2)

    # Add a franchisee for Booth C (no sales initially, potentially underperforming)
    f3 = User(username='booth3', email='booth3@example.com', role=ROLE_FRANCHISEE, booth=booth_c, approved=True)
    f3.set_password('pass3')
    db.session.add(f3)

    db.session.commit()

    # Add some dummy sales and attendance data for testing booth health
    from datetime import datetime, timedelta
    today = datetime.utcnow().date()  # Corrected line
    yesterday = today - timedelta(days=1)
    two_days_ago = today - timedelta(days=2)

    # Sales for Booth A (higher performance for comparison)
    db.session.add(SalesEntry(user_id=f1.id, date=yesterday, timestamp=datetime.utcnow(), drink_name='Latte', quantity=100, booth_id=booth_a.id))
    db.session.add(SalesEntry(user_id=f1.id, date=today, timestamp=datetime.utcnow(), drink_name='Espresso', quantity=90, booth_id=booth_a.id))
    db.session.add(AttendanceLog(user_id=f1.id, username='booth1', date=yesterday, present=True, booth_id=booth_a.id))
    db.session.add(AttendanceLog(user_id=f1.id, username='booth1', date=today, present=True, booth_id=booth_a.id))

    # Sales for Booth B (lower performance for comparison)
    db.session.add(SalesEntry(user_id=f2.id, date=yesterday, timestamp=datetime.utcnow(), drink_name='Matcha', quantity=40, booth_id=booth_b.id))
    db.session.add(SalesEntry(user_id=f2.id, date=today, timestamp=datetime.utcnow(), drink_name='Americano', quantity=35, booth_id=booth_b.id))
    db.session.add(AttendanceLog(user_id=f2.id, username='booth2', date=yesterday, present=True, booth_id=booth_b.id))
    db.session.add(AttendanceLog(user_id=f2.id, username='booth2', date=today, present=True, booth_id=booth_b.id))

    # Booth C (no sales yet, but active for one day to be included in overall stats if needed, but not in A vs B)
    db.session.add(AttendanceLog(user_id=f3.id, username='booth3', date=yesterday, present=True, booth_id=booth_c.id))

    db.session.commit()

    print('Initialized the database.')

@app.route('/api/daily_sales')
@login_required
def daily_sales_api():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'error': 'Unauthorized'}), 403
    total_sales = get_total_sales_for_today()
    return jsonify({'total_sales_today': total_sales})

@app.route('/api/attendance_records')
@login_required
def attendance_records_api():
    if current_user.role != ROLE_ADMIN:
        return jsonify({'error': 'Unauthorized'}), 403

    attendance_records = db.session.query(
        AttendanceLog.date,
        func.string_agg(User.username, ', ').label('users'),
        func.count(distinct(AttendanceLog.user_id)).filter(AttendanceLog.present == True).label('present_count'),
        func.count(distinct(AttendanceLog.user_id)).label('total_count')
    ).join(User, AttendanceLog.user_id == User.id) \
    .group_by(
        AttendanceLog.date
    ).order_by(
        AttendanceLog.date.desc()
    ).all()

    records = [{
        'date': record.date.strftime('%Y-%m-%d'),
        'users': record.users.split(', ') if record.users else [],
        'present_count': record.present_count,
        'total_count': record.total_count
    } for record in attendance_records]

    return jsonify(records)


if __name__ == '__main__':
    # It's recommended to run 'flask initdb' from your terminal once to set up the database
    # and then run 'python app.py' for development.
    # If you run app.py directly, make sure to handle database creation/migration
    # or ensure your database is already set up.
    app.run(debug=True)
