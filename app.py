from flask import Flask, render_template, url_for, request, redirect, flash
from flask_login import UserMixin, login_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_login import current_user, login_required, LoginManager, logout_user, UserMixin, login_user
from datetime import datetime

todos = []

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost:3306/todo'

app.config['SECRET_KEY'] = 'your_secret_key'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(20), nullable=False)
    second_name = db.Column(db.String(20), nullable=False)
    phone_no = db.Column(db.String(15), nullable=False, unique=True)
    email = db.Column(db.String(60), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    confirm_password = db.Column(db.String(255), nullable=False)
    todos = db.relationship('Todo', backref='user', lazy=True)
    time_joined = db.Column(db.DateTime, default=datetime.now)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=False)
    done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



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
        hashed_confirm_password = generate_password_hash(confirm_password, method='pbkdf2:sha256')
        new_user = User(username=username,
                        password=hashed_password,
                        first_name=first_name,
                        second_name=second_name,
                        phone_no=phone_no,
                        email=email,
                        confirm_password=hashed_confirm_password,
                        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            flash('Email address is already in use. Please try another one', 'danger')

    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    user = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', user=user)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/home')
@login_required
def index():
    user = current_user
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_day = datetime.now().strftime('%A')
    user_todos = user.todos
    return render_template("index.html", todos=user_todos, user=user, current_date=current_date, current_day=current_day)

@app.route('/add', methods=["POST"])
def add():
    todo = request.form['todo']
    new_todo = Todo(task=todo, done=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for("index"))

@app.route('/edit/<int:index>', methods=["GET", "POST"])
def edit(index):
    user = current_user

    if 0 <= index < len(user.todos):
        todo = user.todos[index]

        if request.method == "POST":
            todo.task = request.form['todo']
            db.session.commit()
            return redirect(url_for("index"))
        else:
            return render_template("edit.html", todo=todo, index=index)
    else:
        return redirect(url_for("index"))
    
@app.route('/check/<int:index>')
def check(index):
    user = current_user

    if 0 <= index < len(user.todos):
        # Toggle the 'done' status of the corresponding Todo
        todo_to_check = user.todos[index]
        todo_to_check.done = not todo_to_check.done

        # Commit the changes to the database
        db.session.commit()

    return redirect(url_for("index"))

@app.route('/delete/<int:index>')
def delete(index):
    user = current_user

    if 0 <= index < len(user.todos):
        todo_to_delete = user.todos[index]

        # Delete the todo from the database
        db.session.delete(todo_to_delete)
        db.session.commit()

    return redirect(url_for("index"))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))