import sqlite3
from werkzeug.security import generate_password_hash

# Create admin user in database
password = 'admin'
hashed_password = generate_password_hash(password)

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Delete existing admin if exists
cursor.execute('DELETE FROM users WHERE username = ?', ('admin',))

# Create new admin user
cursor.execute('INSERT INTO users (username, password_hash, role, access_levels) VALUES (?, ?, ?, ?)',
               ('admin', hashed_password, 'admin', 'level1,level2,level3'))

conn.commit()
conn.close()

print('Admin user created successfully!')
print('Username: admin')
print('Password: admin')