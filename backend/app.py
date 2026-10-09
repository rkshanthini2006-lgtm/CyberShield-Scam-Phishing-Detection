from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
from pathlib import Path
import sys

from config import Config
import mysql.connector


# =========================
# DATABASE CONNECTION
# =========================

def get_db_connection():

    return mysql.connector.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DATABASE
    )


# =========================
# SAVE SCAN HISTORY
# =========================

def save_scan_history(user_id, scan_type, scan_input, result):

    # Do not attempt database insertion
    # until the frontend provides a valid user ID.

    if not user_id:

        print(
            "Scan history skipped: User ID not provided."
        )

        return False

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        query = """
            INSERT INTO scan_history
            (
                user_id,
                scan_type,
                scan_input,
                risk_score,
                reasons
            )
            VALUES (%s, %s, %s, %s, %s)
        """

        reasons = ", ".join(
            result.get("reasons", [])
        )

        values = (
            user_id,
            scan_type,
            scan_input,
            result.get("score", 0),
            reasons
        )

        cursor.execute(
            query,
            values
        )

        connection.commit()

        return True

    except Exception as error:

        print(
            "Scan history database error:",
            error
        )

        return False

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================
# PYTHON DETECTOR PATH
# =========================

PYTHON_DIR = (
    Path(__file__).resolve().parent.parent / "python"
)

if str(PYTHON_DIR) not in sys.path:

    sys.path.append(
        str(PYTHON_DIR)
    )


from url_detector import scan_url
from message_detector import scan_message
from email_detector import scan_email


# =========================
# FLASK APP
# =========================

app = Flask(__name__)

app.config.from_object(Config)

CORS(app)


# =========================
# PROJECT DIRECTORIES
# =========================

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

FRONTEND_DIR = os.path.join(
    BASE_DIR,
    "frontend"
)

ASSETS_DIR = os.path.join(
    BASE_DIR,
    "assets"
)


# =========================
# FRONTEND
# =========================

@app.route("/")
def home():

    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )

@app.route("/index.html")
def index_page():

    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


@app.route("/register.html")
def register_page():

    return send_from_directory(
        FRONTEND_DIR,
        "register.html"
    )


@app.route("/login.html")
def login_page():

    return send_from_directory(
        FRONTEND_DIR,
        "login.html"
    )


@app.route("/dashboard.html")
def dashboard_page():

    return send_from_directory(
        FRONTEND_DIR,
        "dashboard.html"
    )


@app.route("/history.html")
def history_page():

    return send_from_directory(
        FRONTEND_DIR,
        "history.html"
    )

@app.route("/scan.html")
def scan_page():

    return send_from_directory(
        FRONTEND_DIR,
        "scan.html"
    )

@app.route("/report-scam.html")
def report_scam_page():

    return send_from_directory(
        FRONTEND_DIR,
        "report-scam.html"
    )

# =========================
# ASSETS
# =========================

@app.route("/assets/<path:filename>")
def assets(filename):

    return send_from_directory(
        ASSETS_DIR,
        filename
    )


# =========================
# HEALTH CHECK
# =========================

@app.route("/health")
def health():

    return jsonify({

        "message":
            "Backend is working successfully!"

    })


# =========================
# URL SCANNER
# =========================

@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    if not data or "url" not in data:

        return jsonify({

            "error":
                "URL is required"

        }), 400

    url = data["url"].strip()

    if not url:

        return jsonify({

            "error":
                "URL cannot be empty"

        }), 400

    # Analyze URL
    result = scan_url(url)

    # Get logged-in user's ID
    user_id = request.headers.get(
        "X-User-ID"
    )

    # Save scan history
    save_scan_history(

        user_id=user_id,

        scan_type="URL",

        scan_input=url,

        result=result

    )

    return jsonify(result)


# =========================
# MESSAGE SCANNER
# =========================

@app.route(
    "/scan-message",
    methods=["POST"]
)
def scan_message_route():

    data = request.get_json()

    if not data or "message" not in data:

        return jsonify({

            "error":
                "Message is required"

        }), 400

    message = data["message"].strip()

    if not message:

        return jsonify({

            "error":
                "Message cannot be empty"

        }), 400

    # Analyze message
    result = scan_message(message)

    # Get logged-in user's ID
    user_id = request.headers.get(
        "X-User-ID"
    )

    # Save scan history
    save_scan_history(

        user_id=user_id,

        scan_type="Message",

        scan_input=message,

        result=result

    )

    return jsonify(result)


# =========================
# EMAIL SCANNER
# =========================

@app.route(
    "/scan-email",
    methods=["POST"]
)
def scan_email_route():

    data = request.get_json()

    if not data or "email" not in data:

        return jsonify({

            "error":
                "Email content is required"

        }), 400

    email = data["email"].strip()

    if not email:

        return jsonify({

            "error":
                "Email content cannot be empty"

        }), 400

    # Analyze email
    result = scan_email(email)

    # Get logged-in user's ID
    user_id = request.headers.get(
        "X-User-ID"
    )

    # Save scan history
    save_scan_history(

        user_id=user_id,

        scan_type="Email",

        scan_input=email,

        result=result

    )

    return jsonify(result)


# =========================
# REPORT SCAM
# =========================

@app.route(
    "/report-scam",
    methods=["POST"]
)
def report_scam():

    data = request.get_json()

    if not data:

        return jsonify({

            "error":
                "Report data is required"

        }), 400

    reporter_name = data.get(
        "name",
        ""
    ).strip()

    reporter_email = data.get(
        "email",
        ""
    ).strip()

    scam_type = data.get(
        "scam_type",
        ""
    ).strip()

    scam_url = data.get(
        "scam_url",
        ""
    ).strip()

    scam_message = data.get(
        "scam_message",
        ""
    ).strip()

    description = data.get(
        "description",
        ""
    ).strip()

    if not scam_type:

        return jsonify({

            "error":
                "Scam type is required"

        }), 400

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        query = """
            INSERT INTO scam_reports
            (
                reporter_name,
                reporter_email,
                scam_type,
                scam_url,
                scam_message,
                description
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """

        values = (

            reporter_name,

            reporter_email,

            scam_type,

            scam_url,

            scam_message,

            description

        )

        cursor.execute(
            query,
            values
        )

        connection.commit()

        return jsonify({

            "success":
                True,

            "message":
                "Scam report submitted successfully."

        })

    except Exception as error:

        print(
            "Report scam database error:",
            error
        )

        return jsonify({

            "error":
                "Unable to save scam report."

        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

# =========================
# CONTACT US
# =========================

@app.route("/contact", methods=["POST"])
def contact():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "Contact form data is required."
        }), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    message = data.get("message", "").strip()

    if not name or not email or not message:
        return jsonify({
            "success": False,
            "error": "Please fill in all fields."
        }), 400

    if len(name) > 100 or len(email) > 255:
        return jsonify({
            "success": False,
            "error": "Name or email exceeds the allowed length."
        }), 400

    if (
        "@" not in email
        or email.startswith("@")
        or email.endswith("@")
        or any(character.isspace() for character in email)
    ):
        return jsonify({
            "success": False,
            "error": "Please enter a valid email address."
        }), 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        query = """
            INSERT INTO contact_messages
                (name, email, message)
            VALUES (%s, %s, %s)
        """

        cursor.execute(
            query,
            (name, email, message)
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Your message has been submitted successfully."
        }), 201

    except Exception as error:
        if connection:
            connection.rollback()

        app.logger.exception("Contact message database error")

        return jsonify({
            "success": False,
            "error": "Unable to save your message. Please try again."
        }), 500

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()

# =========================
# USER REGISTRATION
# =========================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    data = request.get_json()

    if not data:

        return jsonify({

            "error":
                "Registration data is required"

        }), 400

    name = data.get(
        "name",
        ""
    ).strip()

    email = data.get(
        "email",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    if not name:

        return jsonify({

            "error":
                "Name is required"

        }), 400

    if not email:

        return jsonify({

            "error":
                "Email is required"

        }), 400

    if not password:

        return jsonify({

            "error":
                "Password is required"

        }), 400

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        # Check whether email already exists

        cursor.execute(

            """
            SELECT id
            FROM users
            WHERE email = %s
            """,

            (email,)

        )

        existing_user = cursor.fetchone()

        if existing_user:

            return jsonify({

                "error":
                    "An account with this email already exists."

            }), 409

        # Create user

        query = """

            INSERT INTO users
            (
                name,
                email,
                password_hash
            )
            VALUES (%s, %s, %s)

        """

        values = (

            name,

            email,

            password

        )

        cursor.execute(
            query,
            values
        )

        connection.commit()

        return jsonify({

            "success":
                True,

            "message":
                "Account created successfully."

        }), 201

    except Exception as error:

        print(
            "Registration database error:",
            error
        )

        return jsonify({

            "error":
                "Unable to create account."

        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================
# USER LOGIN
# =========================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    data = request.get_json()

    if not data:

        return jsonify({

            "error":
                "Login data is required"

        }), 400

    email = data.get(
        "email",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    if not email:

        return jsonify({

            "error":
                "Email is required"

        }), 400

    if not password:

        return jsonify({

            "error":
                "Password is required"

        }), 400

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(

            """
            SELECT
                id,
                name,
                email,
                password_hash
            FROM users
            WHERE email = %s
            """,

            (email,)

        )

        user = cursor.fetchone()

        if not user:

            return jsonify({

                "error":
                    "Invalid email or password."

            }), 401

        if password != user["password_hash"]:

            return jsonify({

                "error":
                    "Invalid email or password."

            }), 401

        return jsonify({

            "success":
                True,

            "message":
                "Login successful.",

            "user": {

                "id":
                    user["id"],

                "name":
                    user["name"],

                "email":
                    user["email"]

            }

        }), 200

    except Exception as error:

        print(
            "Login database error:",
            error
        )

        return jsonify({

            "error":
                "Unable to login."

        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================
# DASHBOARD STATISTICS
# =========================

@app.route(
    "/dashboard-stats",
    methods=["GET"]
)
def dashboard_stats():

    user_id = request.headers.get(
        "X-User-ID"
    )

    if not user_id:

        return jsonify({

            "success":
                False,

            "error":
                "User ID is required."

        }), 401

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        # -------------------------
        # TOTAL SCANS
        # -------------------------

        cursor.execute(

            """
            SELECT COUNT(*)
            FROM scan_history
            WHERE user_id = %s
            """,

            (user_id,)

        )

        total_scans = cursor.fetchone()[0]


        # -------------------------
        # SAFE SCANS
        # -------------------------

        cursor.execute(

            """
            SELECT COUNT(*)
            FROM scan_history
            WHERE user_id = %s
            AND risk_score >= 90
            """,

            (user_id,)

        )

        safe_scans = cursor.fetchone()[0]


        # -------------------------
        # SUSPICIOUS SCANS
        # -------------------------

        cursor.execute(

            """
            SELECT COUNT(*)
            FROM scan_history
            WHERE user_id = %s
            AND risk_score >= 60
            AND risk_score < 90
            """,

            (user_id,)

        )

        suspicious_scans = cursor.fetchone()[0]


        # -------------------------
        # DANGEROUS SCANS
        # -------------------------

        cursor.execute(

            """
            SELECT COUNT(*)
            FROM scan_history
            WHERE user_id = %s
            AND risk_score < 60
            """,

            (user_id,)

        )

        dangerous_scans = cursor.fetchone()[0]


        # -------------------------
        # TOTAL THREATS
        # -------------------------

        threats_detected = (

            suspicious_scans
            +
            dangerous_scans

        )


        # -------------------------
        # TOTAL SCAM REPORTS
        # -------------------------

        cursor.execute(

            "SELECT COUNT(*) FROM scam_reports"

        )

        total_reports = cursor.fetchone()[0]


        # -------------------------
        # RESPONSE
        # -------------------------

        return jsonify({

            "success":
                True,

            "total_scans":
                total_scans,

            "safe_scans":
                safe_scans,

            "suspicious_scans":
                suspicious_scans,

            "dangerous_scans":
                dangerous_scans,

            "threats_detected":
                threats_detected,

            "total_reports":
                total_reports

        })

    except Exception as error:

        print(
            "Dashboard database error:",
            error
        )

        return jsonify({

            "success":
                False,

            "error":
                "Unable to load dashboard statistics."

        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================
# SCAN HISTORY
# =========================

@app.route(
    "/scan-history",
    methods=["GET"]
)
def scan_history():

    user_id = request.headers.get(
        "X-User-ID"
    )

    if not user_id:

        return jsonify({

            "success":
                False,

            "error":
                "User ID is required."

        }), 401

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        query = """
            SELECT
                id,
                scan_type,
                scan_input,
                risk_score,
                reasons,
                created_at
            FROM scan_history
            WHERE user_id = %s
            ORDER BY created_at DESC
        """

        cursor.execute(
            query,
            (user_id,)
        )

        history = cursor.fetchall()

        return jsonify({

            "success":
                True,

            "history":
                history

        }), 200

    except Exception as error:

        print(
            "Scan history database error:",
            error
        )

        return jsonify({

            "success":
                False,

            "error":
                "Unable to load scan history."

        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================
# START SERVER
# =========================

if __name__ == "__main__":

    app.run(

        host=Config.HOST,

        port=Config.PORT,

        debug=Config.DEBUG

    )