# init_db.py

import sqlite3

# به دیتابیس وصل شو (اگر وجود نداشته باشد، آن را می‌سازد)
connection = sqlite3.connect('database.db')
cursor = connection.cursor()

# ساخت جدول کاربران (اگر از قبل وجود نداشته باشد)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )
''')

# می‌توانید چند کاربر اولیه هم اضافه کنید
try:
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   ('admin', 'hashed_password_example', 'administrator'))
    print("کاربر ادمین اولیه اضافه شد.")
except sqlite3.IntegrityError:
    print("کاربر ادمین از قبل وجود داشت.")


# تغییرات را ذخیره کن و اتصال را ببند
connection.commit()
connection.close()

print("پایگاه داده و جدول کاربران با موفقیت ایجاد شد.")