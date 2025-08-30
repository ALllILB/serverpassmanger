import json
import os
from flask import Flask, request, render_template
from werkzeug.security import check_password_hash

app = Flask(__name__)

def read_json_file(filename):
    if not os.path.exists(filename):
        return {}
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}

@app.route('/login', methods=['GET', 'POST'])
def login():  # <-- نام تابع در اینجا اصلاح شد
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print("--- DEBUGGING INFO ---")
        print(f"Username Entered: '{username}'")
        print(f"Password Entered: '{password}'")
        
        users = read_json_file('users.json')
        user_data = users.get(username)
        
        if user_data:
            stored_hash = user_data['password']
            print(f"Stored Hash from file: '{stored_hash}'")
            
            # --- این مهم‌ترین بخش است ---
            is_password_correct = check_password_hash(stored_hash, password)
            print(f"Password Check Result: {is_password_correct}")
            print("----------------------")
            
            if is_password_correct:
                return "<h1>ورود موفقیت‌آمیز بود!</h1><p>مشکل از جای دیگری در کد اصلی است.</p>"
            else:
                return "<h1>رمز عبور اشتباه است.</h1><p>خروجی ترمینال را برای من بفرست.</p>"
        else:
            print(f"User '{username}' not found in users.json")
            print("----------------------")
            return "<h1>نام کاربری یافت نشد.</h1><p>خروجی ترمینال را برای من بفرست.</p>"
            
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)