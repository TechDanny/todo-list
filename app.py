from flask import Flask, render_template, url_for, request, redirect, flash
from flask_login import UserMixin, login_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

todos = [{"task": "Sample todo", "done": False}]

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(20), nullable=False)
    second_name = db.Column(db.String(20), nullable=False)
    phone_no = db.Column(db.Integer, nullable=False, unique=True)
    email = db.Column(db.String(60), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    confirm_password = db.Column(db.String(60), nullable=False)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        first_name = request.form['first_name']
        second_name = request.form['second_name']
        phone_no = request.form['phone_no']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match. Please enter matching passwords.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username,
                        password=hashed_password,
                        first_name=first_name,
                        second_name=second_name,
                        phone_no=phone_no,
                        email=email,
                        confirm_password=confirm_password,
                        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            flash('Email address is already in use. Please try another one', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', user=user)

@app.route('/')
def index():
    return render_template("index.html", todos=todos)

@app.route('/add', methods=["POST"])
def add():
    todo = request.form['todo']
    todos.append({"task": todo, "done": False})
    return redirect(url_for("index"))

@app.route('/edit/<int:index>', methods=["GET", "POST"])
def edit(index):
    todo = todos[index]
    if request.method == "POST":
        todo['task'] = request.form['todo']
        return redirect(url_for("index"))
    else:
        return render_template("edit.html", todo=todo, index=index)
    
@app.route('/check/<int:index>')
def check(index):
    todos[index]['done'] = not todos[index]['done']
    return redirect(url_for("index"))

@app.route('/delete/<int:index>')
def delete(index):
    del todos[index]
    return redirect(url_for("index"))