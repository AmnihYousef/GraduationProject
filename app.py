import os
import sqlite3

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    session
)

from database import init_db
from crypto_utils import (
    generate_aes_key,
    encrypt_file,
    decrypt_file,
    compute_sha256
)

from auth_utils import (
    is_password_strong,
    email_exists,
    create_user,
    get_user_by_email,
    verify_password
)


# ==================================================
# Initialize App & Database
# ==================================================
app = Flask(__name__)
app.secret_key = "49fc9997841e0bea8f0711dac58ba9b9380adf18748cc56c012e78aad3918caf"

init_db()

# ==================================================
# Helper: Save file info to DB
# ==================================================
def save_file_to_db(user_email, original_filename, encrypted_path):
    conn = sqlite3.connect("secure_file_sharing.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE email = ?",
        (user_email,)
    )
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
# Login
# ==================================================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = get_user_by_email(email)

        if not user:
            return render_template(
                "login.html",
                error="Email or password is incorrect"
            )

        user_id, user_email, password_hash = user

        if not verify_password(password_hash, password):
            return render_template(
                "login.html",
                error="Email or password is incorrect"
            )

        # تسجيل الدخول الصحيح
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
            return render_template(
                "register.html",
                error="Email already registered"
            )

        rules, strong = is_password_strong(password)
        if not strong:
            return render_template(
                "register.html",
                rules=rules,
                error="Password is not strong enough"
            )

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
# Dashboard (DB-based)
# ==================================================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

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

    return render_template(
        "dashboard.html",
        my_files=my_files,
        shared_files=[]
    )

# ==================================================
# Settings
# ==================================================
@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect("/")

    return render_template("settings.html")

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
        upload_path = os.path.join("uploads", file.filename)
        file.save(upload_path)

        aes_key = generate_aes_key()
        encrypted_path = encrypt_file(upload_path, aes_key)
        file_hash = compute_sha256(encrypted_path)

        save_file_to_db(
            session["user"],
            file.filename,
            encrypted_path
        )

        return render_template(
            "upload.html",
            hash=file_hash,
            key=aes_key.hex(),
            filename=file.filename
        )

    return render_template("upload.html")

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
            return render_template(
                "download.html",
                filename=filename,
                error="File not found"
            )

        try:
            key = bytes.fromhex(key_hex)
            decrypted_path = decrypt_file(encrypted_path, key)
            return send_file(decrypted_path, as_attachment=True)

        except Exception:
            return render_template(
                "download.html",
                filename=filename,
                error="Invalid decryption key"
            )

    return render_template("download.html", filename=filename)

# ==================================================
# Run App
# ==================================================
if __name__ == "__main__":
    app.run(debug=True)
