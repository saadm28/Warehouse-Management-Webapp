from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')


# Connect to Database
DB_NAME = 'warehouse.db'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Database models
# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(64), nullable=False, default='user')


# Warehouse Model
class Warehouse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    address = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(150), nullable=False)


# Inventory Model
class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    # Creates a foreign key relationship with the Warehouse table
    warehouse_id = db.Column(db.Integer, db.ForeignKey(
        'warehouse.id', ondelete='CASCADE'), nullable=False)
    # Creates a relationship with Warehouse table
    warehouse = db.relationship(
        'Warehouse', backref=db.backref('inventories', lazy=True, cascade='all, delete'))


# Token Model
class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(250), nullable=False)
    user_name = db.Column(db.String(250), nullable=False)
    user_email = db.Column(db.String(250), nullable=False)


# Create an intense of the LoginManager class
login_manager = LoginManager()
login_manager.init_app(app)


# Tell Flask-Login how to load the user from the ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create the table in the database
if not os.path.exists('./instance/' + DB_NAME):
    with app.app_context():
        db.create_all()
        print("Database Created!")


# AUTHENTICATION
@app.before_request
def load_user_info():
    g.user = current_user


def require_auth_or_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        # Check if logged-in user
        if 'user' in g and g.user.is_authenticated:
            return f(*args, **kwargs)
        # Check if bearer token is provided
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            # Validate the token
            if validate_token(token):
                return f(*args, **kwargs)
        return jsonify({'Error': 'You do not have permission to access this page.'}), 401
    return decorated_function


def validate_token(token):
    # check database to see if token is valid
    valid_token = Token.query.filter_by(token=token).first()
    if valid_token:
        return True
    return False
# END OF AUTHENTICATION


# Home Route
@app.route('/')
def home():
    return render_template('home.html')


# All Warehouse Route
@app.route('/warehouse', methods=['GET', 'POST'])
# @login_required
@require_auth_or_token
def warehouse():
    warehouses = Warehouse.query.all()
    return render_template('warehouse.html', warehouses=warehouses)


# Add Warehouse Route
@app.route('/add_warehouse', methods=['GET', 'POST'])
# @login_required
@require_auth_or_token
def add_warehouse():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        description = request.form['description']
        new_warehouse = Warehouse(
            name=name, address=address, description=description)
        db.session.add(new_warehouse)
        db.session.commit()
        flash('Warehouse added successfully!')
        return redirect(url_for('warehouse'))
    return render_template('add_warehouse.html')


# Update Warehouse Route
@app.route('/update_warehouse/<int:id>', methods=['GET', 'POST'])
# @login_required
@require_auth_or_token
def update_warehouse(id):
    warehouse = Warehouse.query.get_or_404(id)
    if request.method == 'POST':
        warehouse.name = request.form['name']
        warehouse.address = request.form['address']
        warehouse.description = request.form['description']
        db.session.commit()
        flash('Warehouse updated successfully!')
        return redirect(url_for('warehouse'))
    return render_template('update_warehouse.html', warehouse=warehouse)


# Delete Warehouse Route
@app.route('/delete_warehouse/<int:id>', methods=['GET', 'POST'])
# @login_required
@require_auth_or_token
def delete_warehouse(id):
    warehouse = Warehouse.query.get_or_404(id)
    db.session.delete(warehouse)
    db.session.commit()
    flash('Warehouse deleted successfully!')
    return redirect(url_for('warehouse'))


# All Inventory Route
@app.route('/inventory', methods=['GET', 'POST'])
# @login_required
@require_auth_or_token
def inventory():
    # get warehouse id from the url
    try:
        warehouse_id = int(request.args.get('warehouse_id'))
    except TypeError:
        warehouse_id = 0
    inventories = Inventory.query.all()
    return render_template('inventory.html', inventories=inventories, warehouse_id=warehouse_id)


# Add Inventory Route
@app.route('/add_inventory', methods=['GET', 'POST'])
# @login_required
@require_auth_or_token
def add_inventory():
    warehouses = Warehouse.query.all()
    if request.method == 'POST':
        name = request.form['name']
        quantity = request.form['quantity']
        description = request.form['description']
        warehouse_id = request.form['warehouse_id']
        # check if the warehouse exists
        warehouse = Warehouse.query.filter_by(id=warehouse_id).first()
        if warehouse:
            new_inventory = Inventory(name=name, description=description,
                                      quantity=quantity, warehouse_id=warehouse_id)
            db.session.add(new_inventory)
            db.session.commit()
            flash('Inventory added successfully!')
        else:
            flash('Warehouse does not exist. Please try again.')
        return redirect(url_for('inventory'))
    return render_template('add_inventory.html', warehouses=warehouses)


# Increase Inventory Route
@app.route('/increase_inventory/<int:id>', methods=['GET', 'POST'])
# @login_required
@require_auth_or_token
def increase_inventory(id):
    inventory = Inventory.query.get_or_404(id)
    if request.method == 'POST':
        quantity_to_increase = int(request.form['quantity'])
        inventory.quantity += quantity_to_increase
        db.session.commit()
        flash('Stock added successfully!')
        return redirect(url_for('inventory'))
    return render_template('update_inventory.html', inventory=inventory, deplete=False)


# Deplete Inventory Route
@app.route('/deplete_inventory/<int:id>', methods=['GET', 'POST'])
# @login_required
@require_auth_or_token
def deplete_inventory(id):
    inventory = Inventory.query.get_or_404(id)
    if request.method == 'POST':
        quantity_to_deplete = int(request.form['quantity'])
        inventory.quantity -= quantity_to_deplete
        db.session.commit()

        # check if the inventory is 0 then delete it
        if inventory.quantity <= 0:
            db.session.delete(inventory)
            db.session.commit()

        flash('Stock depleted successfully!')
        return redirect(url_for('inventory'))
    return render_template('update_inventory.html', inventory=inventory, deplete=True)


# Register User Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first-name']
        last_name = request.form['last-name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        # check if the email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('The email is already registered. Please login instead.')
            return redirect(url_for('login'))

        # check if the password is at least 8 characters long
        if len(password) < 8:
            flash('The password must be at least 8 characters long. Please try again.')
            return redirect(url_for('register'))

        # check if the password and confirm password fields match
        if password != confirm_password:
            flash('The passwords do not match. Please try again.')
            return redirect(url_for('register'))

        # hash and salt the password before saving to the database
        hashed_password = generate_password_hash(
            password, method='sha256', salt_length=8)

        # create a new user instance and add to the database
        new_user = User(first_name=first_name, last_name=last_name,
                        email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # log in the user and flash a success message
        login_user(new_user)
        flash('Your account has been created successfully! You are now logged in.')
        return redirect(url_for('warehouse'))
    return render_template('register.html')


# Login User Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # retrieve the values submitted by the form
        email = request.form['email']
        password = request.form['password']

        # get the user with the provided email
        user = User.query.filter_by(email=email).first()

        # check if the user exists and the provided password is correct
        if not user or not check_password_hash(user.password, password):
            flash('Incorrect email or password. Please try again.')
            return redirect(url_for('login'))

        # log in the user and flash a success message
        login_user(user)
        flash(
            f"You were successfully logged in!")
        return redirect(url_for('warehouse'))
    return render_template('login.html')


# Logout User Route
@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash('You were successfully logged out!')
    else:
        return redirect(url_for('login'))
    return redirect(url_for('home'))


# Admin Route
@app.route('/admin')
@login_required
def admin():
    # Check if the user is an admin
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash('You do not have permission to access the admin page.')
        return redirect(url_for('home'))

    # Query all users and tokens from the database
    users = User.query.all()
    tokens = Token.query.all()
    return render_template('admin.html', users=users, tokens=tokens)


# Admin Page Route
@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_user(user_id):
    # Check if the user is an admin
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash('You do not have permission to access the admin page.')
        return redirect(url_for('home'))

    # Query the user from the database
    user = User.query.filter_by(id=user_id).first()

    # Update user information
    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.email = request.form['email']

        db.session.commit()
        flash('User information has been updated!')
        return redirect(url_for('admin'))

    return render_template('admin_user.html', user=user)


# Delete User Route
@app.route('/admin/user/delete/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    # Check if the user is an admin
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash('You do not have permission to access the admin page.')
        return redirect(url_for('home'))

    # Query the user from the database
    user = User.query.filter_by(id=user_id).first()

    # Delete user from the database
    db.session.delete(user)
    db.session.commit()

    flash('User has been deleted!')
    return redirect(url_for('admin'))


# CREATE ADMIN USER (Change details as needed before running)
# Going to this route (/create_admin) will automatically create the admin user accoring to the details provided
# COMMENT OUT after creating required admin user(s)
# @app.route('/create_admin')
# def create_admin():
#     # EDIT THE DETAILS BELOW BEFORE RUNNING
#     ADMIN_FIRST_NAME = 'Admin'
#     ADMIN_LAST_NAME = 'User'
#     ADMIN_EMAIL = 'admin@email.com'
#     ADMIN_PASSWORD = 'admin123'

#     admin = User(first_name=ADMIN_FIRST_NAME, last_name=ADMIN_LAST_NAME,
#                  email=ADMIN_EMAIL, password=generate_password_hash(
#                      ADMIN_PASSWORD, method='sha256', salt_length=8), role='admin')
#     db.session.add(admin)
#     db.session.commit()
#     # login the admin user
#     login_user(admin)
#     flash("Admin user created successfully!")
#     return redirect(url_for('admin'))


# show token route
@app.route('/show_token/<string:token>')
def token(token):
    return render_template('token.html', token=token)


# create token route
@app.route('/create_token', methods=['GET', 'POST'])
def create_token():
    if request.method == 'POST':
        # get username and email from the form
        username = request.form['username']
        email = request.form['email']
        # create a token using jwt
        payload = {'username': username, 'email': email}
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
        print("Token: ", token)
        # add token and user details to the database
        new_token = Token(token=token, user_name=username, user_email=email)
        db.session.add(new_token)
        db.session.commit()
        return redirect(url_for('token', token=token))
    return render_template('create_token.html', token='')


# delete token route
@app.route('/delete_token/<int:token_id>', methods=['GET', 'POST'])
@login_required
def delete_token(token_id):
    # Query the token from the database
    token = Token.query.filter_by(id=token_id).first()

    # Delete token from the database
    db.session.delete(token)
    db.session.commit()

    flash('Token deleted!')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', default=False))
