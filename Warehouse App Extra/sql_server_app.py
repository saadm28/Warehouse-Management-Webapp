from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
# from app import app, db
from werkzeug.security import generate_password_hash, check_password_hash
import os
import pyodbc


app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key'

# Connect to Database (SQLITE - change to SQL Server Express Edition later)
# DB_NAME = 'warehouse.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)

# Connect to SQL Server Express Edition
DRIVER_NAME = 'SQL Server'
SERVER_NAME = '37b1cfb4038d'
DATABASE_NAME = 'Warehouse'

connection_string = f"""
    DRIVER={DRIVER_NAME};
    SERVER={SERVER_NAME}
    DATABASE={DATABASE_NAME};
    Trust_Connection='yes';
    USERNAME='sa';
    PASSWORD='Password_400';
"""

conn = pyodbc.connect(connection_string)
print(conn)

cursor = conn.cursor()


# Create the database models
# User Model
# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(150), nullable=False)
#     email = db.Column(db.String(150), nullable=False)
#     password = db.Column(db.String(150), nullable=False)

# create user model for SQL Server Express Edition
class User():
    def __init__(self, id, name, email, password):
        self.id = id
        self.name = name
        self.email = email
        self.password = password


# Warehouse Model
# class Warehouse(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(150), nullable=False)
#     address = db.Column(db.String(150), nullable=False)
#     description = db.Column(db.String(150), nullable=False)

# create warehouse model for SQL Server Express Edition
class Warehouse():
    def __init__(self, id, name, address, description):
        self.id = id
        self.name = name
        self.address = address
        self.description = description


# Inventory Model
# class Inventory(db.Model):
    # id = db.Column(db.Integer, primary_key=True)
    # name = db.Column(db.String(150), nullable=False)
    # description = db.Column(db.String(150), nullable=False)
    # quantity = db.Column(db.Integer, nullable=False)
    # # Creates a foreign key relationship with the Warehouse table
    # warehouse_id = db.Column(db.Integer, db.ForeignKey(
    #     'warehouse.id'), nullable=False)
    # # Creates a relationship with Warehouse table
    # warehouse = db.relationship(
    #     'Warehouse', backref=db.backref('inventories', lazy=True))

# create inventory model for SQL Server Express Edition
class Inventory():
    def __init__(self, id, name, description, quantity, warehouse_id):
        self.id = id
        self.name = name
        self.description = description
        self.quantity = quantity
        self.warehouse_id = warehouse_id


# Create an intense of the LoginManager class
login_manager = LoginManager()
login_manager.init_app(app)


# Tell Flask-Login how to load the user from the ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# # Create the table in the database
# if not os.path.exists('./instance/' + DB_NAME):
#     with app.app_context():
#         db.create_all()
#         print("Database Created!")


@app.route('/')
def index():
    return 'Hello World!'


# Warehouse Routes
@app.route('/warehouse', methods=['GET', 'POST'])
def warehouse():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        description = request.form['description']
        new_warehouse = Warehouse(
            name=name, address=address, description=description)
        # db.session.add(new_warehouse)
        # db.session.commit()

        # add new warehouse to SQL Server Express Edition
        cursor.execute(f"""
            INSERT INTO Warehouse (Name, Address, Description)
            VALUES ('{name}', '{address}', '{description}')
        """)
        conn.commit()

        flash('Warehouse added successfully!')
        return redirect(url_for('warehouse'))

    # warehouses = Warehouse.query.all()

    # GET warehouses from SQL Server Express Edition
    warehouses = cursor.execute("""
        SELECT * FROM Warehouse
    """)
    warehouses = warehouses.fetchall()

    return render_template('warehouse.html', warehouses=warehouses)


# Update Warehouse Route
@app.route('/update_warehouse/<int:id>', methods=['GET', 'POST'])
def update_warehouse(id):
    # warehouse = Warehouse.query.get_or_404(id)
    warehouse = cursor.execute(f"""
        SELECT * FROM Warehouse
        WHERE Id = {id}
    """)
    warehouse = warehouse.fetchone()

    if request.method == 'POST':
        # warehouse.name = request.form['name']
        # warehouse.address = request.form['address']
        # warehouse.description = request.form['description']
        # db.session.commit()

        # update warehouse in SQL Server Express Edition
        cursor.execute(f"""
            UPDATE Warehouse
            SET Name = '{request.form['name']}', Address = '{request.form['address']}', Description = '{request.form['description']}'
            WHERE Id = {id}
        """)
        conn.commit()

        flash('Warehouse updated successfully!')
        return redirect(url_for('warehouse'))
    return render_template('update_warehouse.html', warehouse=warehouse)


# Delete Warehouse Route
@app.route('/delete_warehouse/<int:id>', methods=['POST'])
def delete_warehouse(id):
    # warehouse = Warehouse.query.get_or_404(id)
    # db.session.delete(warehouse)
    # db.session.commit()

    # delete warehouse from SQL Server Express Edition
    cursor.execute(f"""
        DELETE FROM Warehouse
        WHERE Id = {id}
    """)
    conn.commit()

    flash('Warehouse deleted successfully!')
    return redirect(url_for('warehouse'))


# Inventory Routes
@app.route('/inventory', methods=['GET', 'POST'])
def inventory():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        quantity = request.form['quantity']
        warehouse_id = request.form['warehouse_id']
        new_inventory = Inventory(name=name, description=description,
                                  quantity=quantity, warehouse_id=warehouse_id)
        # db.session.add(new_inventory)
        # db.session.commit()

        # add new inventory to SQL Server Express Edition
        cursor.execute(f"""
            INSERT INTO Inventory (Name, Description, Quantity, WarehouseId)
            VALUES ('{name}', '{description}', {quantity}, {warehouse_id})
        """)
        conn.commit()

        flash('Inventory added successfully!')
        return redirect(url_for('inventory'))
    inventories = Inventory.query.all()
    warehouses = Warehouse.query.all()
    return render_template('inventory.html', inventories=inventories, warehouses=warehouses)


# Deplete Inventory Route
@app.route('/deplete_inventory/<int:id>', methods=['POST'])
def deplete_inventory(id):
    cursor.execute(f'SELECT * FROM Inventory WHERE id={id}')
    inventory_item = cursor.fetchone()

    if request.method == 'POST':
        # Parse request data
        data = request.get_json()

        # Deplete inventory
        if 'quantity' in data:
            quantity = int(data['quantity'])

            if quantity <= inventory_item.quantity:
                new_quantity = inventory_item.quantity - quantity
                cursor.execute(
                    f'UPDATE Inventory SET quantity={new_quantity} WHERE id={id}')
                cursor.commit()
                return jsonify({'message': 'Inventory depleted successfully.'}), 200
            else:
                return jsonify({'error': 'Insufficient inventory.'}), 400
        else:
            return jsonify({'error': 'Quantity not provided.'}), 400
    else:
        return jsonify({'error': 'Invalid request method.'}), 405


# Register User Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        # check if the email is already registered
        # existing_user = User.query.filter_by(email=email).first()

        # check if the email is already registered in SQL Server Express Edition
        cursor.execute(f"""
            SELECT * FROM [User]
            WHERE Email = '{email}'
        """)
        existing_user = cursor.fetchone()

        if existing_user:
            flash('That email is already taken. Please use a different email.')
            return redirect(url_for('register'))

        # check if the password and confirm password fields match
        if password != confirm_password:
            flash('The passwords do not match. Please try again.')
            return redirect(url_for('register'))

        # hash and salt the password before saving to the database
        hashed_password = generate_password_hash(
            password, method='sha256', salt_length=8)

        # create a new user instance and add to the database
        # new_user = User(name=name, email=email, password=hashed_password)
        # db.session.add(new_user)
        # db.session.commit()

        # add new user to SQL Server Express Edition
        cursor.execute(f"""
            INSERT INTO [User] (Name, Email, Password)
            VALUES ('{name}', '{email}', '{hashed_password}')
        """)
        conn.commit()

        new_user = User(id=cursor.lastrowid, name=name,
                        email=email, password=hashed_password)

        # log in the user and flash a success message
        login_user(new_user)
        flash('Your account has been created successfully!')
        return redirect(url_for('login'))
    return render_template('register.html')


# Login User Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # retrieve the values submitted by the form
        email = request.form['email']
        password = request.form['password']

        # get the user with the provided email
        # user = User.query.filter_by(email=email).first()

        # get the user with the provided email from SQL Server Express Edition
        cursor.execute(f"""
            SELECT * FROM [User]
            WHERE Email = '{email}'
        """)
        user = cursor.fetchone()

        # check if the user exists and the provided password is correct
        if not user or not check_password_hash(user.password, password):
            flash('Incorrect email or password. Please try again.')
            return redirect(url_for('login'))

        # log in the user and flash a success message
        login_user(user)
        flash('You were successfully logged in!')
        return redirect(url_for('home'))
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)
