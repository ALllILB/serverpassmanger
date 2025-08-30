import sqlite3
import os

DATABASE = 'database.db'

# بررسی وجود فایل دیتابیس
if not os.path.exists(DATABASE):
    print(f"خطا: فایل دیتابیس '{DATABASE}' پیدا نشد.")
    print("لطفاً ابتدا دستور 'flask init-db' را اجرا کنید.")
else:
    try:
        # اتصال به دیتابیس
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        print("--- Checking 'users' table content ---")
        
        # اجرای کوئری برای نمایش تمام کاربران
        cursor.execute("SELECT id, username, role, access_levels FROM users;")
        users = cursor.fetchall()
        
        if not users:
            print("نتیجه: جدول 'users' خالی است. هیچ کاربری پیدا نشد.")
            print("لطفاً با دستور 'flask create-admin' یک کاربر بسازید.")
        else:
            print(f"نتیجه: {len(users)} کاربر پیدا شد:")
            for user in users:
                # user[0] is id, user[1] is username, user[2] is role, user[3] is access_levels
                print(f"  ID: {user[0]}, Username: {user[1]}, Role: {user[2]}, Access Levels: '{user[3]}'")

        conn.close()

    except sqlite3.OperationalError as e:
        print(f"خطا: به نظر می‌رسد جدول 'users' در دیتابیس وجود ندارد.")
        print("لطفاً ابتدا دستور 'flask init-db' را برای ساخت جداول اجرا کنید.")
        print(f"(Error details: {e})")