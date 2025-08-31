import os
import sqlite3
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, g, send_file, cli)
from cryptography.fernet import Fernet
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from collections import defaultdict
from dotenv import load_dotenv
import click

# خواندن متغیرهای محیطی از فایل .env
load_dotenv()
app = Flask(__name__)

# --- Configuration and Setup ---
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key-for-dev')
FERNET_KEY = os.getenv('FERNET_KEY')
DATABASE = 'database.db'

if not FERNET_KEY:
    raise ValueError("کلید رمزنگاری (FERNET_KEY) در متغیرهای محیطی تنظیم نشده است!")

cipher = Fernet(FERNET_KEY.encode())

# --- Database Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- CLI Commands ---
@app.cli.command('init-db')
def init_db_command():
    init_db()
    click.echo('Database initialized.')

@app.cli.command('create-admin')
def create_admin_command():
    """یک کاربر ادمین جدید می سازد."""
    db = get_db()
    username = click.prompt('Enter admin username', type=str)
    password = click.prompt('Enter password', hide_input=True, confirmation_prompt=True)
    
    user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if user:
        click.echo(f"Error: User '{username}' already exists.")
        return

    hashed_password = generate_password_hash(password)
    access_levels = 'Level1,Level2' 
    
    try:
        db.execute(
            'INSERT INTO users (username, password_hash, role, access_levels) VALUES (?, ?, ?, ?)',
            (username, hashed_password, 'admin', access_levels)
        )
        db.commit()
        click.echo(f"Admin user '{username}' created successfully.")
    except Exception as e:
        click.echo(f"Failed to create admin user: {e}")

@app.cli.command('reset-password')
def reset_password_command():
    """رمز عبور یک کاربر موجود را تغییر می‌دهد."""
    db = get_db()
    username = click.prompt('Enter username to reset password for', type=str)
    
    user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        click.echo(f"Error: User '{username}' not found.")
        return

    password = click.prompt('Enter new password', hide_input=True, confirmation_prompt=True)
    hashed_password = generate_password_hash(password)
    
    try:
        db.execute(
            'UPDATE users SET password_hash = ? WHERE username = ?',
            (hashed_password, username)
        )
        db.commit()
        click.echo(f"Password for user '{username}' has been reset successfully.")
    except Exception as e:
        click.echo(f"Failed to reset password: {e}")

# --- Core Utility Functions ---
def encrypt_password(password):
    if not password:
        return None
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    if not encrypted_password:
        return ""
    try:
        return cipher.decrypt(encrypted_password.encode()).decode()
    except Exception:
        return "Decryption Error"

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Main Routes ---
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user_role = session.get('role')
    user_access_levels = session.get('access_levels', [])
    
    servers_raw = []
    if user_role == 'admin':
        servers_raw = db.execute("SELECT * FROM servers ORDER BY section, server_name").fetchall()
    elif user_access_levels:
        placeholders = ','.join('?' for _ in user_access_levels)
        query = f"SELECT * FROM servers WHERE access_level IN ({placeholders}) ORDER BY section, server_name"
        servers_raw = db.execute(query, user_access_levels).fetchall()

    sections_raw = db.execute("SELECT name FROM sections ORDER BY name ASC").fetchall()
    
    servers_by_section = defaultdict(list)
    for item in servers_raw:
        decrypted_item = dict(item)
        decrypted_item['ip_password'] = decrypt_password(item['ip_password_encrypted'])
        decrypted_item['domain_password'] = decrypt_password(item['domain_password_encrypted'])
        section_name = decrypted_item['section'] or 'Uncategorized'
        servers_by_section[section_name].append(decrypted_item)

    official_sections = [s['name'] for s in sections_raw]
    all_sections_with_servers = sorted(servers_by_section.keys())
    
    final_order = []
    for sec in official_sections:
        if sec in servers_by_section:
            final_order.append(sec)
    for sec in all_sections_with_servers:
        if sec not in final_order:
            final_order.append(sec)
            
    sorted_servers_by_section = {sec: servers_by_section[sec] for sec in final_order}

    return render_template(
        'index.html', 
        servers_by_section=sorted_servers_by_section, 
        sections=[s['name'] for s in sections_raw], 
        user_role=user_role
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            session['access_levels'] = user['access_levels'].split(',') if user['access_levels'] else []
            flash('You have successfully logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have successfully logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/users')
@admin_required
def user_management():
    db = get_db()
    users = db.execute('SELECT id, username, role, access_levels FROM users').fetchall()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    access_levels = ','.join(request.form.getlist('access_levels'))
    hashed_password = generate_password_hash(password)

    db = get_db()
    try:
        db.execute('INSERT INTO users (username, password_hash, role, access_levels) VALUES (?, ?, ?, ?)',
                   (username, hashed_password, role, access_levels))
        db.commit()
        flash(f'User {username} created successfully.', 'success')
    except db.IntegrityError:
        flash('That username is already taken.', 'danger')
    
    return redirect(url_for('user_management'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    db = get_db()
    user_to_delete = db.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user_to_delete is None:
        flash('User not found.', 'danger')
    elif user_to_delete['username'] == 'admin':
        flash('The main "admin" user cannot be deleted.', 'danger')
    elif session.get('username') == user_to_delete['username']:
        flash('You cannot delete your own account.', 'danger')
    else:
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        flash(f'User {user_to_delete["username"]} was deleted.', 'success')
    
    return redirect(url_for('user_management'))

@app.route('/add_server', methods=['POST'])
@admin_required
def add_server():
    db = get_db()
    db.execute('''
        INSERT INTO servers (server_name, server_ip, domain, port, access_level, section,
                             ip_username, ip_password_encrypted, domain_username, domain_password_encrypted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        request.form['server_name'],
        request.form.get('server_ip'),
        request.form.get('domain'),
        request.form['port'],
        request.form['access_level'],
        request.form.get('section'),
        request.form.get('ip_username'),
        encrypt_password(request.form.get('ip_password')),
        request.form.get('domain_username'),
        encrypt_password(request.form.get('domain_password'))
    ))
    db.commit()
    flash('New server added successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/server/edit/<int:server_id>', methods=['POST'])
@admin_required
def edit_server(server_id):
    db = get_db()
    server_name = request.form.get('server_name')
    ip_username = request.form.get('ip_username')
    new_ip_password = request.form.get('ip_password')
    domain_username = request.form.get('domain_username')
    new_domain_password = request.form.get('domain_password')

    updates = {
        'server_name': server_name,
        'ip_username': ip_username,
        'domain_username': domain_username
    }
    
    if new_ip_password:
        updates['ip_password_encrypted'] = encrypt_password(new_ip_password)
    
    if new_domain_password:
        updates['domain_password_encrypted'] = encrypt_password(new_domain_password)
        
    set_clause = ', '.join([f'{key} = ?' for key in updates.keys()])
    values = list(updates.values())
    values.append(server_id)

    query = f"UPDATE servers SET {set_clause} WHERE id = ?"
    
    db.execute(query, tuple(values))
    db.commit()
    
    flash(f"Server '{server_name}' updated successfully.", 'success')
    return redirect(url_for('index'))

@app.route('/delete_server/<int:server_id>', methods=['POST'])
@admin_required
def delete_server(server_id):
    db = get_db()
    db.execute('DELETE FROM servers WHERE id = ?', (server_id,))
    db.commit()
    flash('Server deleted successfully.', 'warning')
    return redirect(url_for('index'))

# --- Sections Management ---
@app.route('/sections')
@admin_required
def manage_sections():
    db = get_db()
    sections = db.execute('SELECT id, name FROM sections').fetchall()
    return render_template('sections.html', sections=sections)

@app.route('/sections/add', methods=['POST'])
@admin_required
def add_section():
    new_section = request.form.get('section_name')
    if new_section:
        db = get_db()
        try:
            db.execute('INSERT INTO sections (name) VALUES (?)', (new_section,))
            db.commit()
            flash(f'Section "{new_section}" added successfully.', 'success')
        except db.IntegrityError:
            flash('Section name must be unique.', 'danger')
    else:
        flash('Section name cannot be empty.', 'danger')
    return redirect(url_for('manage_sections'))

# ===== توابع جدید برای ویرایش و حذف بخش‌ها =====
@app.route('/sections/edit/<int:section_id>', methods=['POST'])
@admin_required
def edit_section(section_id):
    db = get_db()
    new_name = request.form.get('section_name')
    
    old_section = db.execute('SELECT name FROM sections WHERE id = ?', (section_id,)).fetchone()
    if not old_section:
        flash('Section not found.', 'danger')
        return redirect(url_for('manage_sections'))
        
    old_name = old_section['name']

    if new_name and old_name != new_name:
        try:
            db.execute('UPDATE sections SET name = ? WHERE id = ?', (new_name, section_id))
            db.execute('UPDATE servers SET section = ? WHERE section = ?', (new_name, old_name))
            db.commit()
            flash(f'Section "{old_name}" was successfully updated to "{new_name}".', 'success')
        except db.IntegrityError:
            flash(f'The section name "{new_name}" already exists.', 'danger')
    else:
        flash('No changes were made.', 'info')
        
    return redirect(url_for('manage_sections'))

@app.route('/sections/delete/<int:section_id>', methods=['POST'])
@admin_required
def delete_section(section_id):
    db = get_db()
    section = db.execute('SELECT name FROM sections WHERE id = ?', (section_id,)).fetchone()
    
    if section:
        section_name = section['name']
        db.execute("UPDATE servers SET section = NULL WHERE section = ?", (section_name,))
        db.execute("DELETE FROM sections WHERE id = ?", (section_id,))
        db.commit()
        flash(f'Section "{section_name}" and its associations have been deleted.', 'success')
    else:
        flash('Section not found.', 'danger')
        
    return redirect(url_for('manage_sections'))
  


@app.route('/export/excel/servers')
@admin_required
def export_servers_to_excel():
    db = get_db()
    all_servers = db.execute('SELECT * FROM servers').fetchall()
    
    decrypted_data = []
    for item in all_servers:
        decrypted_data.append({
            'Server Name': item['server_name'],
            'IP Address': item['server_ip'],
            'Domain': item['domain'],
            'IP Username': item['ip_username'],
            'IP Password': decrypt_password(item['ip_password_encrypted']),
            'Domain Username': item['domain_username'],
            'Domain Password': decrypt_password(item['domain_password_encrypted']),
            'Port': item['port'],
            'Section': item['section'],
            'Access Level': item['access_level'],
        })

    df = pd.DataFrame(decrypted_data)
    df.to_excel('servers.xlsx', index=False, engine='openpyxl')
    return send_file('servers.xlsx', as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
