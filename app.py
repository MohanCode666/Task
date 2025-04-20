from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from datetime import datetime, date
import json
import os
from config import Config

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
csrf = CSRFProtect(app)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='user')
    tasks_created = db.relationship('Task', backref='creator', lazy=True, foreign_keys='Task.creator_id')
    tasks_assigned = db.relationship('Task', backref='assignee', lazy=True, foreign_keys='Task.assignee_id')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class TaskHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    change_type = db.Column(db.String(50), nullable=False)  # 'comment', 'status_change', 'priority_change', 'assignee_change'
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    comment = db.Column(db.Text, nullable=True)
    
    user = db.relationship('User', backref='task_history')
    task = db.relationship('Task', backref='history')
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'user': self.user.username,
            'change_type': self.change_type,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'comment': self.comment
        }

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    due_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pending')
    priority = db.Column(db.String(20), nullable=False, default='medium')
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    @staticmethod
    def get_default_date():
        return datetime.now()

    def __repr__(self):
        return f"Task('{self.title}', '{self.status}')"
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'date_created': self.date_created.strftime('%Y-%m-%d %H:%M:%S'),
            'due_date': self.due_date.strftime('%Y-%m-%d') if self.due_date else None,
            'status': self.status,
            'priority': self.priority,
            'creator': self.creator.username,
            'assignee': self.assignee.username if self.assignee else None
        }
    
    def get_history(self):
        return TaskHistory.query.filter_by(task_id=self.id).order_by(TaskHistory.timestamp.desc()).all()

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long'),
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_password(self, password):
        """Ensure password meets complexity requirements"""
        if not any(char.isdigit() for char in password.data):
            raise ValidationError('Password must contain at least one number')
        if not any(char.isupper() for char in password.data):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in password.data):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not any(char in '!@#$%^&*()_-+=<>?/[]{}|' for char in password.data):
            raise ValidationError('Password must contain at least one special character')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already registered. Please use a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    due_date = DateField('Due Date', format='%Y-%m-%d', validators=[])
    priority = SelectField('Priority', choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], validators=[DataRequired()])
    status = SelectField('Status', choices=[('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed')], validators=[DataRequired()])
    assignee = SelectField('Assign To', coerce=int)
    submit = SubmitField('Submit')

# Login manager setup
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    tasks_created = Task.query.filter_by(creator_id=current_user.id).order_by(Task.date_created.desc()).all()
    tasks_assigned = Task.query.filter_by(assignee_id=current_user.id).order_by(Task.date_created.desc()).all()
    
    # Calculate task statistics
    total_tasks = len(tasks_created) + len(tasks_assigned)
    pending_tasks = sum(1 for task in tasks_assigned if task.status == 'pending')
    in_progress_tasks = sum(1 for task in tasks_assigned if task.status == 'in_progress')
    completed_tasks = sum(1 for task in tasks_assigned if task.status == 'completed')
    
    return render_template(
        'dashboard.html', 
        title='Dashboard',
        tasks_created=tasks_created,
        tasks_assigned=tasks_assigned,
        total_tasks=total_tasks,
        pending_tasks=pending_tasks,
        in_progress_tasks=in_progress_tasks,
        completed_tasks=completed_tasks
    )

@app.route('/tasks')
@login_required
def tasks():
    tasks_created = Task.query.filter_by(creator_id=current_user.id).order_by(Task.date_created.desc()).all()
    tasks_assigned = Task.query.filter_by(assignee_id=current_user.id).order_by(Task.date_created.desc()).all()
    return render_template('tasks.html', title='Tasks', tasks_created=tasks_created, tasks_assigned=tasks_assigned)

@app.route('/task/new', methods=['GET', 'POST'])
@login_required
def create_task():
    form = TaskForm()
    # Populate assignee choices
    form.assignee.choices = [(0, 'Unassigned')] + [(user.id, user.username) for user in User.query.order_by(User.username).all()]
    
    if form.validate_on_submit():
        assignee_id = form.assignee.data if form.assignee.data != 0 else None
        task = Task(
            title=form.title.data,
            description=form.description.data,
            due_date=form.due_date.data,
            priority=form.priority.data,
            status=form.status.data,
            creator_id=current_user.id,
            assignee_id=assignee_id
        )
        db.session.add(task)
        db.session.commit()
        
        # Send notification through WebSocket
        if assignee_id:
            notification_data = {
                'title': 'New Task Assigned',
                'message': f'You have been assigned a new task: {task.title}',
                'assignee_id': assignee_id
            }
            socketio.emit('new_task_notification', notification_data, room=f'user_{assignee_id}')
            
        flash('Task has been created!', 'success')
        return redirect(url_for('tasks'))
    return render_template('create_task.html', title='New Task', form=form)

@app.route('/task/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.creator_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to delete this task.', 'danger')
        return redirect(url_for('tasks'))
    
    db.session.delete(task)
    db.session.commit()
    flash('Task has been deleted!', 'success')
    return redirect(url_for('tasks'))

# API endpoints
@app.route('/api/tasks', methods=['GET'])
@login_required
def get_tasks():
    tasks = Task.query.filter(
        (Task.creator_id == current_user.id) | (Task.assignee_id == current_user.id)
    ).order_by(Task.date_created.desc()).all()
    
    return jsonify([task.to_dict() for task in tasks])

@app.route('/api/tasks/<int:task_id>', methods=['GET'])
@login_required
def get_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.creator_id != current_user.id and task.assignee_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify(task.to_dict())

@app.route('/api/tasks/<int:task_id>/status', methods=['PATCH'])
@login_required
def update_task_status(task_id):
    task = Task.query.get_or_404(task_id)
    data = request.get_json()
    
    if 'status' not in data:
        return jsonify({'error': 'Missing status field'}), 400
    
    if data['status'] not in ['pending', 'in_progress', 'completed']:
        return jsonify({'error': 'Invalid status value'}), 400
    
    # If trying to mark as completed, only assignee can do it
    if data.get('status') == 'completed' and task.assignee_id != current_user.id:
        return jsonify({'error': 'Only the assigned user can mark this task as completed'}), 403
    
    # For other status changes, allow creator, assignee, or admin
    elif task.assignee_id != current_user.id and task.creator_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    task.status = data['status']
    db.session.commit()
    
    # Notify creator if status changes
    if task.creator_id != current_user.id:
        notification_data = {
            'title': 'Task Status Updated',
            'message': f'Task "{task.title}" status updated to {task.status}',
            'user_id': task.creator_id
        }
        socketio.emit('task_update_notification', notification_data, room=f'user_{task.creator_id}')
    
    return jsonify(task.to_dict())

# WebSocket handling
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        user_room = f'user_{current_user.id}'
        socketio.join_room(user_room)
        print(f'User {current_user.username} connected and joined room {user_room}')

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        user_room = f'user_{current_user.id}'
        socketio.leave_room(user_room)
        print(f'User {current_user.username} disconnected and left room {user_room}')

@socketio.on('join_task_room')
def handle_join_task_room(data):
    if current_user.is_authenticated and 'task_id' in data:
        task_id = data['task_id']
        task = Task.query.get(task_id)
        
        # Only allow joining if the user is related to the task
        if task and (task.creator_id == current_user.id or task.assignee_id == current_user.id or current_user.role == 'admin'):
            task_room = f'task_{task_id}'
            socketio.join_room(task_room)
            print(f'User {current_user.username} joined task room {task_room}')

@app.route('/task/<int:task_id>', methods=['GET'])
@login_required
def view_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has permission to view this task
    if task.creator_id != current_user.id and task.assignee_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to view this task.', 'danger')
        return redirect(url_for('tasks'))
    
    # Get all users for reference
    users = User.query.order_by(User.username).all()
    
    # Check if the current user is the creator or an admin
    can_edit = (task.creator_id == current_user.id) or (current_user.role == 'admin')
    
    # Can complete only if assignee
    can_complete = (task.assignee_id == current_user.id)
    
    # Get task history
    task_history = TaskHistory.query.filter_by(task_id=task.id).order_by(TaskHistory.timestamp.desc()).all()
    
    return render_template(
        'task_detail.html', 
        title=f'Task: {task.title}',
        task=task,
        users=users,
        can_edit=can_edit,
        can_complete=can_complete,
        task_history=task_history
    )

@app.route('/task/<int:task_id>/comment', methods=['POST'])
@login_required
def add_comment(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has permission to comment on this task
    if task.creator_id != current_user.id and task.assignee_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to comment on this task.', 'danger')
        return redirect(url_for('tasks'))
    
    comment_text = request.form.get('comment')
    
    if comment_text:
        # Create a new task history entry for the comment
        history_entry = TaskHistory(
            task_id=task_id,
            user_id=current_user.id,
            change_type='comment',
            comment=comment_text
        )
        
        db.session.add(history_entry)
        db.session.commit()
        
        # Emit real-time notification
        task_room = f'task_{task_id}'
        comment_data = {
            'task_id': task_id,
            'user': current_user.username,
            'comment': comment_text,
            'timestamp': history_entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        socketio.emit('new_comment', comment_data, room=task_room)
        
        # Also notify task creator and assignee if they're not the commenter
        if task.creator_id != current_user.id:
            notification_data = {
                'title': 'New Comment on Task',
                'message': f'New comment on task "{task.title}"',
                'user_id': task.creator_id
            }
            socketio.emit('task_update_notification', notification_data, room=f'user_{task.creator_id}')
            
        if task.assignee_id and task.assignee_id != current_user.id:
            notification_data = {
                'title': 'New Comment on Task',
                'message': f'New comment on task "{task.title}"',
                'user_id': task.assignee_id
            }
            socketio.emit('task_update_notification', notification_data, room=f'user_{task.assignee_id}')
        
        flash('Comment added successfully!', 'success')
    else:
        flash('Comment cannot be empty.', 'warning')
    
    return redirect(url_for('view_task', task_id=task_id))

@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    # Allow creator, assignee, or admin to edit the task
    if task.creator_id != current_user.id and task.assignee_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to edit this task.', 'danger')
        return redirect(url_for('tasks'))
    
    form = TaskForm()
    # Populate assignee choices
    form.assignee.choices = [(0, 'Unassigned')] + [(user.id, user.username) for user in User.query.order_by(User.username).all()]
    
    if form.validate_on_submit():
        # Track changes
        changes = []
        
        # Track title change
        if task.title != form.title.data:
            changes.append(TaskHistory(
                task_id=task.id,
                user_id=current_user.id,
                change_type='title_change',
                old_value=task.title,
                new_value=form.title.data
            ))
            
        # Track description change
        if task.description != form.description.data:
            changes.append(TaskHistory(
                task_id=task.id,
                user_id=current_user.id,
                change_type='description_change',
                old_value=task.description,
                new_value=form.description.data
            ))
            
        # Track due date change
        old_due_date = task.due_date.strftime('%Y-%m-%d') if task.due_date else 'None'
        new_due_date = form.due_date.data.strftime('%Y-%m-%d') if form.due_date.data else 'None'
        if old_due_date != new_due_date:
            changes.append(TaskHistory(
                task_id=task.id,
                user_id=current_user.id,
                change_type='due_date_change',
                old_value=old_due_date,
                new_value=new_due_date
            ))
            
        # Track priority change
        if task.priority != form.priority.data:
            changes.append(TaskHistory(
                task_id=task.id,
                user_id=current_user.id,
                change_type='priority_change',
                old_value=task.priority,
                new_value=form.priority.data
            ))
            
        # Track status change
        if task.status != form.status.data:
            changes.append(TaskHistory(
                task_id=task.id,
                user_id=current_user.id,
                change_type='status_change',
                old_value=task.status,
                new_value=form.status.data
            ))
            
        # Track assignee change
        old_assignee = task.assignee.username if task.assignee else 'Unassigned'
        new_assignee_id = form.assignee.data if form.assignee.data != 0 else None
        new_assignee = User.query.get(new_assignee_id).username if new_assignee_id else 'Unassigned'
        
        if (task.assignee_id or 0) != (new_assignee_id or 0):
            changes.append(TaskHistory(
                task_id=task.id,
                user_id=current_user.id,
                change_type='assignee_change',
                old_value=old_assignee,
                new_value=new_assignee
            ))
        
        # Update task with new values
        task.title = form.title.data
        task.description = form.description.data
        task.due_date = form.due_date.data
        task.priority = form.priority.data
        task.status = form.status.data
        task.assignee_id = new_assignee_id
        
        # Save changes
        if changes:
            for change in changes:
                db.session.add(change)
        
        db.session.commit()
        
        # Send notifications for changes
        if new_assignee_id and (task.assignee_id or 0) != (new_assignee_id or 0):
            notification_data = {
                'title': 'Task Assigned',
                'message': f'You have been assigned a task: {task.title}',
                'assignee_id': new_assignee_id
            }
            socketio.emit('new_task_notification', notification_data, room=f'user_{new_assignee_id}')
            
        flash('Task has been updated!', 'success')
        return redirect(url_for('tasks'))
    elif request.method == 'GET':
        form.title.data = task.title
        form.description.data = task.description
        form.due_date.data = task.due_date
        form.priority.data = task.priority
        form.status.data = task.status
        form.assignee.data = task.assignee_id if task.assignee_id else 0
        
    # Get task history
    task_history = TaskHistory.query.filter_by(task_id=task.id).order_by(TaskHistory.timestamp.desc()).all()
        
    return render_template('edit_task.html', title='Edit Task', form=form, task=task, task_history=task_history)

# Initialize database
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
