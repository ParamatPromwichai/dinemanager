from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    set_refresh_cookies
)
from flask_cors import CORS
from datetime import timedelta
import psycopg2
import os
from dotenv import load_dotenv

# =====================
# Load env
# =====================
load_dotenv()

# =====================
# App setup
# =====================
app = Flask(__name__)
# CORS(app, supports_credentials=True)
# เปลี่ยนจากบรรทัดเดิม เป็นอันนี้ครับ
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# =====================
# Database connection
# =====================
def get_db():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

# =====================
# REGISTER
# =====================
@app.post("/api/register")
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    email = data.get("email") # <--- รับ email เพิ่ม

    if not username or not password or not email:
        return jsonify({"msg": "Missing username, password, or email"}), 400

    # 🔐 hash password
    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    conn = get_db()
    cur = conn.cursor()

    try:
        # เพิ่ม email ลงใน Database
        cur.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, 'user')",
            (username, email, password_hash)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(e)
        return jsonify({"msg": "Username or Email already exists"}), 400
    finally:
        cur.close()
        conn.close()

    return jsonify({"msg": "Register success"}), 201

# =====================
# LOGIN
# =====================
@app.post("/api/login")
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, password_hash FROM users WHERE username=%s",
        (username,)
    )
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({"msg": "User not found"}), 401

    if not bcrypt.check_password_hash(user[2], password):
        cur.close()
        conn.close()
        return jsonify({"msg": "Wrong password"}), 401

    # ===== บันทึกประวัติการเข้าใช้ =====
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    try:
        cur.execute(
            """
            INSERT INTO login_history (user_id, ip_address, user_agent)
            VALUES (%s, %s, %s)
            """,
            (user[0], ip, user_agent)
        )
        conn.commit()
    except Exception as e:
        print("Error saving history:", e)

    cur.close()
    conn.close()

    access_token = create_access_token(identity=user[1])

    return jsonify({"access_token": access_token})


# =====================
# USER HISTORY (ดูเฉพาะของตัวเอง)
# =====================
@app.get("/api/login-history")
@jwt_required()
def login_history():
    username = get_jwt_identity()

    conn = get_db()
    cur = conn.cursor()
    
    # Query Join เพื่อความชัวร์
    cur.execute(
        """
        SELECT lh.login_time, lh.ip_address, lh.user_agent
        FROM login_history lh
        JOIN users u ON lh.user_id = u.id
        WHERE u.username = %s
        ORDER BY lh.login_time DESC
        """,
        (username,)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    history = [
        {
            "login_time": r[0],
            "ip": r[1],
            "device": r[2]
        }
        for r in rows
    ]

    return jsonify(history)

# =====================
# ADMIN HISTORY (ดูของทุกคน) - เพิ่มใหม่
# =====================
@app.get("/api/admin/login-history")
@jwt_required()
def admin_login_history():
    current_user = get_jwt_identity()
    
    conn = get_db()
    cur = conn.cursor()

    # 1. เช็คสิทธิ์ก่อนว่าเป็น admin จริงไหม
    cur.execute("SELECT role FROM users WHERE username = %s", (current_user,))
    result = cur.fetchone()
    
    # ถ้าไม่มี role หรือ role ไม่ใช่ admin ให้ดีดออก
    if not result or result[0] != 'admin':
        cur.close()
        conn.close()
        return jsonify({"msg": "Access denied. Admin only."}), 403

    # 2. ดึงข้อมูล Login ของทุกคน (JOIN users เอาชื่อมาโชว์ด้วย)
    cur.execute("""
        SELECT u.username, lh.login_time, lh.ip_address, lh.user_agent
        FROM login_history lh
        JOIN users u ON lh.user_id = u.id
        ORDER BY lh.login_time DESC
        LIMIT 100
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()

    history = [
        {
            "username": r[0],
            "login_time": r[1],
            "ip": r[2],
            "device": r[3]
        }
        for r in rows
    ]

    return jsonify(history)

# =====================
# PROFILE (ส่ง Role กลับไปด้วย)
# =====================
@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    username = get_jwt_identity()
    
    conn = get_db()
    cur = conn.cursor()
    
    # ดึง role เพื่อส่งให้ Frontend
    cur.execute("SELECT role FROM users WHERE username = %s", (username,))
    result = cur.fetchone()
    
    cur.close()
    conn.close()

    # ถ้าไม่มี role ให้ default เป็น user
    user_role = result[0] if result else "user"

    return jsonify({"username": username, "role": user_role})


# =====================
# PROTECTED TEST
# =====================
@app.get("/api/dashboard")
@jwt_required()
def dashboard():
    return jsonify({"msg": "Welcome to Restaurant Admin Dashboard"})

# =====================
# Run
# =====================
if __name__ == "__main__":
    app.run(debug=True)