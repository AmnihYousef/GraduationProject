import os
import sqlite3
import smtplib
import threading
import logging
from email.message import EmailMessage
from flask import Flask, render_template, request, send_file, redirect, session
from database import init_db
from crypto_utils import generate_aes_key, encrypt_file, decrypt_file, compute_sha256
from auth_utils import is_password_strong, email_exists, create_user, get_user_by_email, verify_password

# ==================================================
# إعداد السجلات (Logging) للتشخيص
# ==================================================
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ==================================================
# Initialize App & Database
# ==================================================
app = Flask(__name__)
app.secret_key = "49fc9997841e0bea8f0711dac58ba9b9380adf18748cc56c012e78aad3918caf"

init_db()

# ==================================================
# إعدادات البريد الإلكتروني
# ==================================================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587  # جربنا نغير البورت لـ 587 بدل 465
SENDER_EMAIL = "graduation.project.secure@gmail.com"

# مهم جداً: هنا رح نستخدم App Password
# رح نأخذ الباسوورد من متغيرات البيئة أو نستخدم واحد ثابت
import os
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "eizohobrrurzznyg")

# ==================================================
# Helper: Save file info to DB
# ==================================================
def save_file_to_db(user_email, original_filename, encrypted_path):
    conn = sqlite3.connect("secure_file_sharing.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE email = ?", (user_email,))
    user_id = cursor.fetchone()[0]

    file_size = os.path.getsize(encrypted_path)

    cursor.execute("""
        INSERT INTO files (
            uploader_id,
            stored_filename,
            original_filename,
            file_size,
            encryption_method
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        os.path.basename(encrypted_path),
        original_filename,
        file_size,
        "AES-256-GCM"
    ))

    conn.commit()
    conn.close()

# ==================================================
# دالة إرسال الإيميل في thread منفصل
# ==================================================
def send_email_background(recipient_email, filename, sender, encrypted_path):
    """ترسل الإيميل في خلفية الموقع"""
    try:
        logger.info(f"Preparing to send email to {recipient_email}")
        
        # إعداد الرسالة
        msg = EmailMessage()
        msg["Subject"] = "🔒 Encrypted File Shared With You"
        msg["From"] = SENDER_EMAIL
        msg["To"] = recipient_email

        msg.set_content(f"""
Hello,

You have received an encrypted file from: {sender}

📁 Filename: {filename}

The file is attached to this email.

🔑 IMPORTANT: The sender will provide you with the decryption key separately for security reasons.

Best regards,
Secure File Sharing System
""")

        # إرفاق الملف المشفر
        with open(encrypted_path, "rb") as f:
            msg.add_attachment(
                f.read(),
                maintype="application",
                subtype="octet-stream",
                filename=filename + ".enc"
            )

        logger.info(f"Connecting to SMTP server...")
        
        # محاولة الإتصال بـ SMTP
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()  # تشفير الإتصال
            logger.info(f"Logging in with {SENDER_EMAIL}")
            smtp.login(SENDER_EMAIL, EMAIL_PASSWORD)
            logger.info(f"Sending email to {recipient_email}")
            smtp.send_message(msg)
            logger.info(f"Email sent successfully to {recipient_email}")
            
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        print(f"❌ ERROR: {str(e)}")

# ==================================================
# Login
# ==================================================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = get_user_by_email(email)
        if not user:
            return render_template("login.html", error="Email or password is incorrect")

        user_id, user_email, password_hash = user
        if not verify_password(password_hash, password):
            return render_template("login.html", error="Email or password is incorrect")

        session["user"] = user_email
        session["user_id"] = user_id
        return redirect("/dashboard")

    return render_template("login.html")

# ==================================================
# Register
# ==================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email_exists(email):
            return render_template("register.html", error="Email already registered")

        rules, strong = is_password_strong(password)
        if not strong:
            return render_template("register.html", rules=rules, error="Password is not strong enough")

        create_user(email, password)
        return redirect("/")

    return render_template("register.html")

# ==================================================
# Logout
# ==================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ==================================================
# Dashboard
# ==================================================
@app.route("/dashboard", strict_slashes=False)
def dashboard():
    if "user" not in session:
        return redirect("/")

    # عرض رسالة نجاح إذا كانت موجودة
    message = request.args.get('message', '')
    
    conn = sqlite3.connect("secure_file_sharing.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT original_filename
        FROM files
        JOIN users ON users.id = files.uploader_id
        WHERE users.email = ?
    """, (session["user"],))

    my_files = [row[0] for row in cursor.fetchall()]
    conn.close()

    return render_template("dashboard.html", my_files=my_files, shared_files=[], message=message)

# ==================================================
# Upload + Encrypt
# ==================================================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect("/")

    if request.method == "POST":
        if "file" not in request.files:
            return render_template("upload.html", error="No file selected")

        file = request.files["file"]
        if file.filename == "":
            return render_template("upload.html", error="Empty filename")

        os.makedirs("uploads", exist_ok=True)
        os.makedirs("encrypted", exist_ok=True)

        # حفظ الملف الأصلي مؤقتاً
        upload_path = os.path.join("uploads", file.filename)
        file.save(upload_path)

        # تشفير الملف وحفظه في مجلد "encrypted"
        aes_key = generate_aes_key()
        encrypted_path = os.path.join("encrypted", file.filename + ".enc")
        encrypt_file(upload_path, aes_key, output_path=encrypted_path)

        file_hash = compute_sha256(encrypted_path)
        save_file_to_db(session["user"], file.filename, encrypted_path)

        return render_template("upload.html", 
                             hash=file_hash, 
                             key=aes_key.hex(), 
                             filename=file.filename,
                             success="File uploaded and encrypted successfully!")

    return render_template("upload.html")

# ==================================================
# Share Encrypted File via Email
# ==================================================
@app.route("/share", methods=["POST"])
def share():
    logger.info("Share route called")
    
    if "user" not in session:
        return redirect("/")

    recipient_email = request.form.get("email")
    filename = request.form.get("filename")
    sender = session["user"]

    encrypted_path = f"encrypted/{filename}.enc"
    
    # التأكد من وجود الملف
    if not os.path.exists(encrypted_path):
        logger.error(f"File not found: {encrypted_path}")
        return redirect("/dashboard?message=File+not+found")

    # إرسال الإيميل في خلفية الموقع
    thread = threading.Thread(
        target=send_email_background,
        args=(recipient_email, filename, sender, encrypted_path)
    )
    thread.daemon = True
    thread.start()

    logger.info(f"Email thread started for {recipient_email}")
    
    # إرجاع رسالة نجاح
    return redirect("/dashboard?message=File+shared+successfully!+Check+recipient+email.")

# ==================================================
# Download + Decrypt
# ==================================================
@app.route("/download/<filename>", methods=["GET", "POST"])
def download(filename):
    if "user" not in session:
        return redirect("/")

    encrypted_path = f"encrypted/{filename}.enc"
    if request.method == "POST":
        key_hex = request.form.get("key")

        if not os.path.exists(encrypted_path):
            return render_template("download.html", filename=filename, error="File not found")

        try:
            key = bytes.fromhex(key_hex)
            decrypted_path = decrypt_file(encrypted_path, key)
            return send_file(decrypted_path, as_attachment=True)
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return render_template("download.html", filename=filename, error="Invalid decryption key")

    return render_template("download.html", filename=filename)

# ==================================================
# صفحة الاختبار
# ==================================================
@app.route("/test-email")
def test_email():
    """صفحة لاختبار إرسال الإيميل"""
    try:
        # اختبار إرسال إيميل بسيط
        msg = EmailMessage()
        msg["Subject"] = "Test Email from Secure File Sharing"
        msg["From"] = "graduation.project.secure@gmail.com"
        msg["To"] = "amnih.yousef1@gmail.com"  # غيرها لإيميلك
        
        msg.set_content("This is a test email from your Secure File Sharing System.")
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login("graduation.project.secure@gmail.com", "eizohobrrurzznyg")
            smtp.send_message(msg)
            
        return "<h1>✅ Email sent successfully!</h1><p>Check your email inbox.</p>"
        
    except Exception as e:
        return f"<h1>❌ Error sending email:</h1><p>{str(e)}</p>"

# ==================================================
# Settings
# ==================================================
@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect("/")

    return render_template("settings.html")

# ==================================================
# Run App
# ==================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
