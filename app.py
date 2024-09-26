import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from passlib.hash import argon2
from flask_login import login_user, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired, URL, Optional
from flask_wtf.file import FileAllowed
from uuid import uuid4
from flask import abort
import requests
from io import BytesIO
from PIL import Image

# Initialize Flask app
app = Flask(__name__)

# Configurations for the app and database
app.config['SECRET_KEY'] = '6e21170d998b7e87cb3eb38324764a4c78984905a71b2b6d'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = 'a4e3f0b951e808b197c2ef8b9dda17f0c17c81df97e8c9a3365dd31ff42053d0'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Initialize the database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define models for Users and Roles
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
                       )


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=True)
    approved = db.Column(db.Boolean(), default=False)
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False, default=lambda: str(uuid4()))
    badge = db.Column(db.String(50))  # Gold, Silver, Bronze
    youtube_link = db.Column(db.String(255))
    image_filename = db.Column(db.String(255))
    description = db.Column(db.Text)
    linkedin_link = db.Column(db.String(255))
    github_link = db.Column(db.String(255))
    facebook_link = db.Column(db.String(255))
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Create the database and tables if they don't exist
with app.app_context():
    db.create_all()


# Function to create admin user if not exists
def create_admin():
    with app.app_context():
        admin_role = user_datastore.find_or_create_role(name='admin', description='Administrator')
        admin_user = user_datastore.find_user(username="admin") or user_datastore.find_user(email="admin@example.com")

        if not admin_user:
            # Hash the admin password using Argon2
            user = user_datastore.create_user(username="admin", email="admin@example.com",
                                              password=argon2.hash("adminpass"),
                                              active=True, approved=True)
            user_datastore.add_role_to_user(user, admin_role)
            db.session.commit()
            print("Admin user created successfully.")
        else:
            print("Admin user already exists.")


# Portfolio form
class PortfolioForm(FlaskForm):
    youtube_link = StringField('YouTube Video Link', validators=[DataRequired(), URL()])
    image = FileField('Upload Image', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    image_url = StringField('Image URL', validators=[URL(), Optional()])
    description = TextAreaField('Description', validators=[DataRequired()])
    linkedin_link = StringField('LinkedIn Profile', validators=[URL()])
    github_link = StringField('GitHub Profile', validators=[URL()])
    facebook_link = StringField('Facebook Profile', validators=[URL()])
    submit = SubmitField('Save Portfolio')


# Route for home page
@app.route('/')
def home():
    students = User.query.filter_by(approved=True).all()
    return render_template('home.html', students=students)


# Route for protected dashboard (after login)
@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('view_own_portfolio'))


# Route for user sign-up (registration)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = argon2.hash(request.form['password'])

        existing_user = user_datastore.find_user(username=username) or user_datastore.find_user(email=email)
        if existing_user:
            flash('Username or email already exists. Please choose a different one.', 'error')
            return redirect(url_for('signup'))

        user = user_datastore.create_user(username=username, email=email, password=password, approved=False)
        student_role = user_datastore.find_or_create_role(name='student', description='Student')
        user_datastore.add_role_to_user(user, student_role)
        db.session.commit()

        flash('Your account has been created. Please wait for admin approval.', 'info')
        return redirect(url_for('home'))

    return render_template('signup.html')


# Route for user sign-in (login)
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = user_datastore.find_user(email=email)

        try:
            if user and argon2.verify(password, user.password):
                if user.approved:
                    login_user(user)
                    flash('Logged in successfully.', 'success')
                    return redirect(url_for('view_own_portfolio'))
                else:
                    flash('Your account is not yet approved by the admin.', 'error')
            else:
                flash('Invalid credentials. Please try again.', 'error')
        except Exception as e:
            print(f"Error verifying password: {e}")
            flash('Something went wrong. Please try again later.', 'error')

    return render_template('signin.html')


# Route to logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))


# Admin Panel to manage user approvals and badge assignment
@app.route('/admin')
@login_required
def admin_panel():
    if 'admin' not in [role.name for role in current_user.roles]:
        flash('Access Denied: Admins Only!', 'error')
        return redirect(url_for('home'))

    unapproved_students = User.query.filter_by(approved=False).all()
    approved_students = User.query.filter_by(approved=True).all()

    return render_template('admin.html', unapproved_students=unapproved_students, approved_students=approved_students)

# Admin sign-in route
@app.route('/admin_signin', methods=['GET', 'POST'])
def admin_signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = user_datastore.find_user(email=email)

        try:
            if user and argon2.verify(password, user.password):
                if 'admin' in [role.name for role in user.roles]:
                    login_user(user)
                    flash('Admin logged in successfully.', 'success')
                    return redirect(url_for('admin_panel'))  # Redirect to admin panel
                else:
                    flash('Access denied: You are not an admin.', 'error')
            else:
                flash('Invalid admin credentials. Please try again.', 'error')
        except Exception as e:
            print(f"Error verifying password: {e}")
            flash('Something went wrong. Please try again later.', 'error')
    return render_template('admin_signin.html')

# Route to approve a user
@app.route('/approve/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.approved = True
        db.session.commit()
        flash(f'User {user.username} approved successfully.', 'success')
    return redirect(url_for('admin_panel'))


# Route to assign badge
@app.route('/assign_badge/<int:user_id>', methods=['POST'])
@login_required
def assign_badge(user_id):
    if 'admin' not in [role.name for role in current_user.roles]:
        flash('Access Denied: Admins Only!', 'error')
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    badge = request.form.get('badge')
    if user:
        user.badge = badge
        db.session.commit()
        flash(f'Badge {badge} assigned to {user.username}.', 'success')
    else:
        flash('User not found.', 'error')

    return redirect(url_for('admin_panel'))

# Route to delete a user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if 'admin' not in [role.name for role in current_user.roles]:
        flash('Access Denied: Admins Only!', 'error')
        return redirect(url_for('home'))

    user = db.session.get(User, user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted successfully.', 'success')
    else:
        flash('User not found.', 'error')

    return redirect(url_for('admin_panel'))


# Route for portfolio creation and editing
@app.route('/portfolio', methods=['GET', 'POST'])
@login_required
def portfolio():
    # Ensure the user is logged in
    if not current_user.is_authenticated:
        flash("You need to log in to edit your portfolio", "error")
        return redirect(url_for('signin'))

    # Pre-populate the form with the user's existing data
    form = PortfolioForm(
        youtube_link=current_user.youtube_link,
        description=current_user.description,
        linkedin_link=current_user.linkedin_link,
        github_link=current_user.github_link,
        facebook_link=current_user.facebook_link
    )

    # When the form is submitted
    if form.validate_on_submit():
        # Update the fields with new form data or keep the existing data if unchanged
        current_user.youtube_link = form.youtube_link.data or current_user.youtube_link
        current_user.description = form.description.data or current_user.description
        current_user.linkedin_link = form.linkedin_link.data or current_user.linkedin_link
        current_user.github_link = form.github_link.data or current_user.github_link
        current_user.facebook_link = form.facebook_link.data or current_user.facebook_link

        # Handle uploaded image
        if form.image.data:
            image_file = secure_filename(form.image.data.filename)
            form.image.data.save(os.path.join(app.config['UPLOAD_FOLDER'], image_file))
            current_user.image_filename = image_file  # Update with the new image

        # Handle image URL
        elif form.image_url.data:
            try:
                image_url = form.image_url.data
                response = requests.get(image_url)
                img = Image.open(BytesIO(response.content))
                image_file = f"{uuid4().hex}.jpg"
                img_path = os.path.join(app.config['UPLOAD_FOLDER'], image_file)
                img.save(img_path)
                current_user.image_filename = image_file  # Update with the new image from URL
            except Exception as e:
                flash('Failed to download image from the URL. Please try again.', 'error')
                return render_template('portfolio.html', form=form)

        # Ensure a default image is set if none is provided
        if not current_user.image_filename:
            current_user.image_filename = 'default.jpg'

        # Save updates to the database
        db.session.commit()
        flash('Portfolio updated successfully!', 'success')
        return redirect(url_for('view_own_portfolio'))

    return render_template('portfolio.html', form=form)

# Route to view portfolio
@app.route('/view_own_portfolio')
@login_required
def view_own_portfolio():
    user = current_user
    youtube_embed_url = user.youtube_link.replace('watch?v=', 'embed/') if user.youtube_link else None
    return render_template('view_portfolio.html', user=user, youtube_embed_url=youtube_embed_url)


@app.route('/view_portfolio/<int:user_id>')
@login_required
def view_portfolio(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('home'))

    youtube_embed_url = user.youtube_link.replace('watch?v=', 'embed/') if user.youtube_link else None
    return render_template('view_portfolio.html', user=user, youtube_embed_url=youtube_embed_url)


if __name__ == '__main__':
    create_admin()
    app.run(debug=True)
