import os
import io
import uuid
import time
import base64
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import fitz  # PyMuPDF
import pyotp
import qrcode

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_from_directory,
    flash,
    session,
    abort,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)
from werkzeug.utils import secure_filename


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


SECRET_KEY = os.environ.get(
    "FLASK_SECRET_KEY",
    "development-only-change-this"
)
if not SECRET_KEY:
    SECRET_KEY = os.urandom(32)

app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("FLASK_COOKIE_SECURE", "0") == "1"
    ),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
)


# ============================================================
# DIRECTORIES
# ============================================================

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
SIGNED_FOLDER = os.path.join(BASE_DIR, "signed_documents")
STORAGE_FOLDER = os.path.join(BASE_DIR, "storage")

DB_PATH = os.path.join(
    STORAGE_FOLDER,
    "app_data.db"
)

# ONLY STAMP IS STORED
STAMP_FILE = os.path.join(
    STORAGE_FOLDER,
    "stamp.png"
)


# ============================================================
# APPLICATION INFORMATION
# ============================================================

SIGNER_NAME = "HABIYAREMYE Emmanuel"
SIGNER_ROLE = "GS MUKONDO Head Teacher"

APPLICATION_NAME = "GS MUKONDO Digital Signer"
APPLICATION_VERSION = "2.0"


# ============================================================
# FILE CONFIGURATION
# ============================================================

ALLOWED_EXTENSIONS = {
    "pdf"
}

IMAGE_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg"
}

MAX_DOCUMENT_SIZE = 25 * 1024 * 1024
MAX_IMAGE_SIZE = 5 * 1024 * 1024


# ============================================================
# CREATE DIRECTORIES
# ============================================================

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    SIGNED_FOLDER,
    exist_ok=True
)

os.makedirs(
    STORAGE_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ============================================================
# DATABASE
# ============================================================

def get_db_connection():

    conn = sqlite3.connect(
        DB_PATH
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    return conn


def init_db():

    conn = get_db_connection()

    cursor = conn.cursor()

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            totp_secret TEXT NOT NULL,

            totp_enabled INTEGER NOT NULL DEFAULT 0,

            role TEXT NOT NULL DEFAULT 'user',

            active INTEGER NOT NULL DEFAULT 1,

            created_at TEXT NOT NULL,

            last_login TEXT
        )
    """)

    # --------------------------------------------------------
    # DOCUMENTS
    #
    # signature_id is retained for database compatibility.
    # It is now a SIGNING ID, not a signature image.
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            document_id TEXT UNIQUE NOT NULL,

            original_filename TEXT NOT NULL,

            signed_filename TEXT NOT NULL,

            signature_id TEXT NOT NULL,

            signed_by TEXT NOT NULL,

            signed_at TEXT NOT NULL,

            file_size INTEGER DEFAULT 0,

            status TEXT NOT NULL DEFAULT 'signed',

            uploaded_by INTEGER,

            created_at TEXT NOT NULL,

            FOREIGN KEY(uploaded_by)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # --------------------------------------------------------
    # AUDIT LOG
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            action TEXT NOT NULL,

            description TEXT,

            ip_address TEXT,

            created_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # --------------------------------------------------------
    # DEFAULT ADMIN
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE username = ?
        """,
        ("admin",)
    )

    admin = cursor.fetchone()

    if not admin:

        default_password = os.environ.get(
            "DEFAULT_ADMIN_PASSWORD",
            "admin123"
        )

        default_hash = generate_password_hash(
            default_password
        )

        default_totp_secret = pyotp.random_base32()

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                totp_secret,
                totp_enabled,
                role,
                active,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "admin",
                default_hash,
                default_totp_secret,
                0,
                "admin",
                1,
                datetime.now().isoformat(
                    timespec="seconds"
                ),
            )
        )

    conn.commit()

    conn.close()


init_db()


# ============================================================
# AUTHENTICATION
# ============================================================

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if not session.get("logged_in"):

            flash(
                "Please log in to continue.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return decorated_function


def admin_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if not session.get("logged_in"):

            return redirect(
                url_for("login")
            )

        if session.get("role") != "admin":

            flash(
                "Administrator access is required.",
                "danger"
            )

            return redirect(
                url_for("dashboard")
            )

        return function(*args, **kwargs)

    return decorated_function


# ============================================================
# SECURITY / AUDIT
# ============================================================

def log_action(
    user_id=None,
    action="SYSTEM",
    description="",
    ip_address=None
):

    conn = None

    try:

        conn = get_db_connection()

        conn.execute(
            """
            INSERT INTO audit_logs
            (
                user_id,
                action,
                description,
                ip_address,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                action,
                description,
                ip_address,
                datetime.now().isoformat(
                    timespec="seconds"
                )
            )
        )

        conn.commit()

    except sqlite3.Error as error:

        app.logger.exception(
            "AUDIT LOG DATABASE ERROR: %s",
            error
        )

    except Exception as error:

        app.logger.exception(
            "AUDIT LOG ERROR: %s",
            error
        )

    finally:

        if conn:
            conn.close()


def password_is_strong(password):

    if len(password) < 8:
        return False

    has_upper = any(
        c.isupper()
        for c in password
    )

    has_lower = any(
        c.islower()
        for c in password
    )

    has_digit = any(
        c.isdigit()
        for c in password
    )

    return (
        has_upper
        and has_lower
        and has_digit
    )


# ============================================================
# FILE HELPERS
# ============================================================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(
            ".",
            1
        )[1].lower()
        in ALLOWED_EXTENSIONS
    )


def allowed_image(filename):

    return (
        "." in filename
        and filename.rsplit(
            ".",
            1
        )[1].lower()
        in IMAGE_EXTENSIONS
    )


def generate_signature_id():

    # Kept for database compatibility.
    # This is now a signing/document identification ID.
    return uuid.uuid4().hex[:12].upper()


def generate_document_id():

    return (
        "DOC-"
        + uuid.uuid4().hex[:12].upper()
    )


def safe_remove(
    file_path,
    attempts=5,
    delay=0.4
):

    if not file_path:
        return True

    if not os.path.exists(file_path):
        return True

    for _ in range(attempts):

        try:

            os.remove(file_path)

            return True

        except OSError:

            time.sleep(delay)

    return False


def read_binary_file(file_path):

    with open(
        file_path,
        "rb"
    ) as file:

        return file.read()


def secure_path(
    folder,
    filename
):

    safe_name = secure_filename(
        filename
    )

    if not safe_name:
        abort(404)

    full_path = os.path.abspath(
        os.path.join(
            folder,
            safe_name
        )
    )

    folder_path = os.path.abspath(
        folder
    )

    if not full_path.startswith(
        folder_path + os.sep
    ):
        abort(404)

    return full_path


# ============================================================
# PDF DIGITAL SIGNATURE INFORMATION
# ============================================================

def add_digital_signature(
    page,
    signing_id,
    signed_time
):

    page_width = page.rect.width
    page_height = page.rect.height

    # --------------------------------------------------------
    # Block dimensions
    # --------------------------------------------------------

    block_width = min(
        270,
        page_width - 30
    )

    block_height = 82

    # Bottom-right
    block_x = max(
        10,
        page_width - block_width - 15
    )

    block_y = max(
        10,
        page_height - block_height - 15
    )

    block_rect = fitz.Rect(
        block_x,
        block_y,
        min(
            block_x + block_width,
            page_width - 5
        ),
        min(
            block_y + block_height,
            page_height - 5
        )
    )

    # --------------------------------------------------------
    # Border
    # --------------------------------------------------------

    page.draw_rect(
        block_rect,
        color=(
            0.25,
            0.25,
            0.25
        ),
        width=0.7,
        overlay=True
    )

    # --------------------------------------------------------
    # DIGITAL SIGNATURE
    # --------------------------------------------------------

    page.insert_textbox(
        fitz.Rect(
            block_rect.x0 + 5,
            block_rect.y0 + 4,
            block_rect.x1 - 5,
            block_rect.y0 + 17
        ),
        "DIGITALLY SIGNED BY HEAD MASTER",
        fontsize=8.5,
        fontname="helv",
        color=(
            0.05,
            0.25,
            0.15
        ),
        align=fitz.TEXT_ALIGN_CENTER,
        overlay=True
    )

    # --------------------------------------------------------
    # SIGNER
    # --------------------------------------------------------

    page.insert_textbox(
        fitz.Rect(
            block_rect.x0 + 5,
            block_rect.y0 + 19,
            block_rect.x1 - 5,
            block_rect.y0 + 32
        ),
        f"Signed by: {SIGNER_NAME}",
        fontsize=7.5,
        fontname="helv",
        color=(
            0.10,
            0.10,
            0.10
        ),
        overlay=True
    )

    # --------------------------------------------------------
    # ROLE
    # --------------------------------------------------------

    page.insert_textbox(
        fitz.Rect(
            block_rect.x0 + 5,
            block_rect.y0 + 32,
            block_rect.x1 - 5,
            block_rect.y0 + 45
        ),
        SIGNER_ROLE,
        fontsize=7.5,
        fontname="helv",
        color=(
            0.10,
            0.10,
            0.10
        ),
        overlay=True
    )

    # --------------------------------------------------------
    # SIGNING ID
    # --------------------------------------------------------

    page.insert_textbox(
        fitz.Rect(
            block_rect.x0 + 5,
            block_rect.y0 + 45,
            block_rect.x1 - 5,
            block_rect.y0 + 58
        ),
        f"Signing ID: {signing_id}",
        fontsize=7,
        fontname="helv",
        color=(
            0.10,
            0.10,
            0.10
        ),
        overlay=True
    )

    # --------------------------------------------------------
    # DATE
    # --------------------------------------------------------

    page.insert_textbox(
        fitz.Rect(
            block_rect.x0 + 5,
            block_rect.y0 + 58,
            block_rect.x1 - 5,
            block_rect.y0 + 72
        ),
        f"Date: {signed_time}",
        fontsize=7,
        fontname="helv",
        color=(
            0.10,
            0.10,
            0.10
        ),
        overlay=True
    )


# ============================================================
# STAMP + DIGITAL SIGNATURE BLOCK
# ============================================================

def apply_stamp_and_digital_signature(
    page,
    stamp_bytes,
    signing_id,
    signed_time
):

    page_width = page.rect.width
    page_height = page.rect.height

    # --------------------------------------------------------
    # Group location
    # --------------------------------------------------------

    group_x = 35

    group_y = max(
        20,
        page_height - 150
    )

    group_width = min(
        180,
        page_width - 45
    )

    # --------------------------------------------------------
    # DIGITAL SIGNATURE LABEL
    # --------------------------------------------------------

    label_rect = fitz.Rect(
        group_x,
        group_y,
        group_x + group_width,
        group_y + 22
    )

    page.insert_textbox(
        label_rect,
        "DIGITAL SIGNATURE",
        fontsize=10,
        fontname="helv",
        color=(
            0,
            0,
            0
        ),
        align=fitz.TEXT_ALIGN_LEFT,
        overlay=True
    )

    # --------------------------------------------------------
    # STAMP
    # --------------------------------------------------------

    stamp_size = min(
        75,
        page_width - group_x - 10,
        page_height - group_y - 35
    )

    stamp_rect = fitz.Rect(
        group_x,
        group_y + 27,
        group_x + stamp_size,
        group_y + 27 + stamp_size
    )

    page.insert_image(
        stamp_rect,
        stream=stamp_bytes,
        keep_proportion=True,
        overlay=True
    )

    # --------------------------------------------------------
    # LINE
    # --------------------------------------------------------

    line_y = (
        group_y
        + 27
        + stamp_size
        + 7
    )

    page.draw_line(
        fitz.Point(
            group_x,
            line_y
        ),
        fitz.Point(
            group_x + group_width,
            line_y
        ),
        width=0.8,
        color=(
            0.5,
            0.5,
            0.5
        ),
        overlay=True
    )

    # --------------------------------------------------------
    # SIGNING ID
    # --------------------------------------------------------

    page.insert_text(
        fitz.Point(
            group_x,
            line_y + 12
        ),
        f"Signing ID: {signing_id}",
        fontsize=6.5,
        fontname="helv",
        color=(
            0.25,
            0.25,
            0.25
        ),
        overlay=True
    )

    # --------------------------------------------------------
    # AUTHENTICATION TEXT
    # --------------------------------------------------------

    page.insert_text(
        fitz.Point(
            group_x,
            line_y + 23
        ),
        "Digitally document Signed ",
        fontsize=7,
        fontname="helv",
        color=(
            0.25,
            0.25,
            0.25
        ),
        overlay=True
    )


@app.route("/admin/cleanup", methods=["GET", "POST"])
@login_required
def cleanup():
    """
    Administrator-only database and file cleanup.

    Deletes:
        - All document records
        - All audit log records
        - Uploaded PDF files
        - Signed PDF files

    Preserves:
        - Users
        - Passwords
        - 2FA settings
        - Stored signature
        - Stored stamp
    """

    # ==========================================================
    # ADMIN ACCESS CHECK
    # ==========================================================
    if session.get("role") != "admin":
        flash(
            "Administrator access is required.",
            "error"
        )
        return redirect(url_for("dashboard"))

    # ==========================================================
    # POST: PERFORM CLEANUP
    # ==========================================================
    if request.method == "POST":

        confirmation = (
            request.form.get("confirmation", "")
            .strip()
            .upper()
        )

        # ------------------------------------------------------
        # CONFIRMATION CHECK
        # ------------------------------------------------------
        if confirmation != "DELETE ALL":
            flash(
                'Cleanup cancelled. Please type "DELETE ALL" '
                "exactly to confirm.",
                "error"
            )
            return redirect("/admin/cleanup")

        conn = None

        # Counters
        deleted_documents = 0
        deleted_audit_logs = 0
        deleted_uploads = 0
        deleted_signed = 0
        failed_uploads = 0
        failed_signed = 0

        try:
            # ==================================================
            # DATABASE CLEANUP
            # ==================================================
            conn = get_db_connection()

            # Count records before deletion
            deleted_documents = conn.execute(
                "SELECT COUNT(*) AS count FROM documents"
            ).fetchone()["count"]

            deleted_audit_logs = conn.execute(
                "SELECT COUNT(*) AS count FROM audit_logs"
            ).fetchone()["count"]

            # Delete documents
            conn.execute(
                "DELETE FROM documents"
            )

            # Delete audit logs
            conn.execute(
                "DELETE FROM audit_logs"
            )

            conn.commit()

            # ==================================================
            # UPLOAD FOLDER CLEANUP
            # ==================================================
            if os.path.exists(UPLOAD_FOLDER):

                for filename in os.listdir(UPLOAD_FOLDER):

                    file_path = secure_path(
                        UPLOAD_FOLDER,
                        filename
                    )

                    # Only delete files
                    if not os.path.isfile(file_path):
                        continue

                    if safe_remove(file_path):
                        deleted_uploads += 1
                    else:
                        failed_uploads += 1

            # ==================================================
            # SIGNED DOCUMENTS CLEANUP
            # ==================================================
            if os.path.exists(SIGNED_FOLDER):

                for filename in os.listdir(SIGNED_FOLDER):

                    file_path = secure_path(
                        SIGNED_FOLDER,
                        filename
                    )

                    # Only delete files
                    if not os.path.isfile(file_path):
                        continue

                    if safe_remove(file_path):
                        deleted_signed += 1
                    else:
                        failed_signed += 1

            # ==================================================
            # RESULT MESSAGE
            # ==================================================
            if failed_uploads == 0 and failed_signed == 0:

                flash(
                    "Database cleanup completed successfully. "
                    f"{deleted_documents} document record(s), "
                    f"{deleted_audit_logs} audit log record(s), "
                    f"{deleted_uploads} uploaded file(s), and "
                    f"{deleted_signed} signed file(s) were removed. "
                    "Users, passwords, 2FA settings, signature, "
                    "and stamp were preserved.",
                    "success"
                )

            else:

                flash(
                    "Cleanup completed with some file deletion "
                    "warnings. "
                    f"{deleted_documents} document record(s), "
                    f"{deleted_audit_logs} audit log record(s), "
                    f"{deleted_uploads} uploaded file(s), and "
                    f"{deleted_signed} signed file(s) were removed. "
                    f"{failed_uploads} uploaded file(s) and "
                    f"{failed_signed} signed file(s) could not be removed.",
                    "warning"
                )

            # IMPORTANT:
            # Do NOT call log_action() here because the cleanup
            # intentionally removes all audit logs.

            return redirect("/admin/cleanup")

        except Exception as error:

            # --------------------------------------------------
            # DATABASE ROLLBACK
            # --------------------------------------------------
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass

            app.logger.exception(
                "DATABASE CLEANUP ERROR: %s",
                error
            )

            flash(
                "Database cleanup failed. No further cleanup "
                "operation was completed.",
                "error"
            )

            return redirect("/admin/cleanup")

        finally:

            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    # ==========================================================
    # GET: DISPLAY CLEANUP PAGE
    # ==========================================================
    conn = None

    try:

        conn = get_db_connection()

        # ------------------------------------------------------
        # DATABASE STATISTICS
        # ------------------------------------------------------
        document_count = conn.execute(
            "SELECT COUNT(*) AS count FROM documents"
        ).fetchone()["count"]

        audit_count = conn.execute(
            "SELECT COUNT(*) AS count FROM audit_logs"
        ).fetchone()["count"]

        user_count = conn.execute(
            "SELECT COUNT(*) AS count FROM users"
        ).fetchone()["count"]

        # ------------------------------------------------------
        # FILE STATISTICS
        # ------------------------------------------------------
        upload_file_count = 0

        if os.path.exists(UPLOAD_FOLDER):

            upload_file_count = sum(
                1
                for filename in os.listdir(UPLOAD_FOLDER)
                if os.path.isfile(
                    secure_path(
                        UPLOAD_FOLDER,
                        filename
                    )
                )
            )

        signed_file_count = 0

        if os.path.exists(SIGNED_FOLDER):

            signed_file_count = sum(
                1
                for filename in os.listdir(SIGNED_FOLDER)
                if os.path.isfile(
                    secure_path(
                        SIGNED_FOLDER,
                        filename
                    )
                )
            )

        # ------------------------------------------------------
        # RENDER PAGE
        # ------------------------------------------------------
        return render_template(
            "admin_cleanup.html",

            document_count=document_count,
            audit_count=audit_count,
            user_count=user_count,

            upload_file_count=upload_file_count,
            signed_file_count=signed_file_count
        )

    except Exception as error:

        app.logger.exception(
            "DATABASE CLEANUP PAGE ERROR: %s",
            error
        )

        flash(
            "Unable to load the database cleanup page.",
            "error"
        )

        return redirect(url_for("dashboard"))

    finally:

        if conn:

            try:
                conn.close()
            except Exception:
                pass


@app.route("/")
def home():

    if session.get("logged_in"):

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Please enter your username and password.",
                "error"
            )

            return render_template(
                "login.html"
            )

        conn = None

        try:

            conn = get_db_connection()

            user = conn.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    totp_secret,
                    totp_enabled,
                    role,
                    active
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

            if not user:

                flash(
                    "Invalid username or password.",
                    "error"
                )

                return render_template(
                    "login.html"
                )

            if not user["active"]:

                flash(
                    "Your account has been disabled.",
                    "error"
                )

                return render_template(
                    "login.html"
                )

            if not check_password_hash(
                user["password_hash"],
                password
            ):

                flash(
                    "Invalid username or password.",
                    "error"
                )

                return render_template(
                    "login.html"
                )

            session["pre_auth_user_id"] = user["id"]
            session["pre_auth_username"] = user["username"]
            session["pre_auth_role"] = user["role"]

            if not user["totp_enabled"]:

                flash(
                    "Two-factor authentication is required. "
                    "Please configure Google Authenticator.",
                    "warning"
                )

                return redirect(
                    url_for("setup_2fa")
                )

            return redirect(
                url_for("verify_2fa")
            )

        except sqlite3.Error as error:

            app.logger.exception(
                "LOGIN DATABASE ERROR: %s",
                error
            )

            flash(
                "A database error occurred while signing in.",
                "error"
            )

            return render_template(
                "login.html"
            ), 500

        except Exception as error:

            app.logger.exception(
                "LOGIN ERROR: %s",
                error
            )

            flash(
                "An unexpected error occurred during login.",
                "error"
            )

            return render_template(
                "login.html"
            ), 500

        finally:

            if conn:
                conn.close()

    return render_template(
        "login.html"
    )


# ============================================================
# SETUP 2FA
# ============================================================

@app.route(
    "/setup-2fa",
    methods=["GET", "POST"]
)
def setup_2fa():

    user_id = session.get(
        "pre_auth_user_id"
    )

    if not user_id:

        flash(
            "Please log in with your username and password first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    conn = None

    try:

        conn = get_db_connection()

        user = conn.execute(
            """
            SELECT
                id,
                username,
                totp_secret,
                totp_enabled,
                role,
                active
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not user:

            session.clear()

            flash(
                "User account could not be found.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        if not user["active"]:

            session.clear()

            flash(
                "Your account has been disabled.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        if user["totp_enabled"]:

            return redirect(
                url_for("verify_2fa")
            )

        totp_secret = user["totp_secret"]

        if not totp_secret:

            totp_secret = pyotp.random_base32()

            conn.execute(
                """
                UPDATE users
                SET totp_secret = ?
                WHERE id = ?
                """,
                (
                    totp_secret,
                    user_id
                )
            )

            conn.commit()

        totp = pyotp.TOTP(
            totp_secret
        )

        provisioning_uri = totp.provisioning_uri(
            name=user["username"],
            issuer_name=APPLICATION_NAME
        )

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4
        )

        qr.add_data(
            provisioning_uri
        )

        qr.make(
            fit=True
        )

        qr_image = qr.make_image(
            fill_color="black",
            back_color="white"
        )

        qr_buffer = io.BytesIO()

        qr_image.save(
            qr_buffer,
            format="PNG"
        )

        qr_base64 = base64.b64encode(
            qr_buffer.getvalue()
        ).decode("utf-8")

        if request.method == "POST":

            otp_code = request.form.get(
                "otp_code",
                ""
            ).strip().replace(
                " ",
                ""
            )

            if (
                not otp_code.isdigit()
                or len(otp_code) != 6
            ):

                flash(
                    "Enter the 6-digit code displayed in Google Authenticator.",
                    "error"
                )

                return render_template(
                    "setup_2fa.html",
                    qr_code=qr_base64,
                    secret=totp_secret,
                    username=user["username"]
                )

            if not totp.verify(
                otp_code,
                valid_window=1
            ):

                flash(
                    "Invalid verification code.",
                    "error"
                )

                return render_template(
                    "setup_2fa.html",
                    qr_code=qr_base64,
                    secret=totp_secret,
                    username=user["username"]
                )

            conn.execute(
                """
                UPDATE users
                SET totp_enabled = 1
                WHERE id = ?
                """,
                (user_id,)
            )

            conn.commit()

            log_action(
                user_id,
                "2FA_ENABLED",
                "Google Authenticator two-factor authentication enabled.",
                request.remote_addr
            )

            session.pop(
                "pre_auth_user_id",
                None
            )

            session.pop(
                "pre_auth_username",
                None
            )

            session.pop(
                "pre_auth_role",
                None
            )

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["logged_in"] = True

            conn.execute(
                """
                UPDATE users
                SET last_login = ?
                WHERE id = ?
                """,
                (
                    datetime.now().isoformat(
                        timespec="seconds"
                    ),
                    user_id
                )
            )

            conn.commit()

            flash(
                "2FA setup completed successfully.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "setup_2fa.html",
            qr_code=qr_base64,
            secret=totp_secret,
            username=user["username"]
        )

    except Exception as error:

        if conn:
            conn.rollback()

        app.logger.exception(
            "2FA SETUP ERROR: %s",
            error
        )

        flash(
            "An error occurred during 2FA setup.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    finally:

        if conn:
            conn.close()


# ============================================================
# VERIFY 2FA
# ============================================================

@app.route(
    "/verify-2fa",
    methods=["GET", "POST"]
)
def verify_2fa():

    user_id = session.get(
        "pre_auth_user_id"
    )

    if not user_id:

        flash(
            "Your login session has expired.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    conn = None

    try:

        conn = get_db_connection()

        user = conn.execute(
            """
            SELECT
                id,
                username,
                totp_secret,
                totp_enabled,
                role,
                active
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not user:

            session.clear()

            return redirect(
                url_for("login")
            )

        if not user["active"]:

            session.clear()

            flash(
                "Your account has been disabled.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        if not user["totp_enabled"]:

            return redirect(
                url_for("setup_2fa")
            )

        if request.method == "POST":

            otp_code = request.form.get(
                "otp_code",
                ""
            ).strip().replace(
                " ",
                ""
            )

            if (
                not otp_code.isdigit()
                or len(otp_code) != 6
            ):

                flash(
                    "Enter the 6-digit Google Authenticator code.",
                    "error"
                )

                return render_template(
                    "verify_2fa.html"
                )

            totp = pyotp.TOTP(
                user["totp_secret"]
            )

            if not totp.verify(
                otp_code,
                valid_window=1
            ):

                log_action(
                    user["id"],
                    "2FA_FAILED",
                    "Invalid Google Authenticator verification code.",
                    request.remote_addr
                )

                flash(
                    "Invalid or expired verification code.",
                    "error"
                )

                return render_template(
                    "verify_2fa.html"
                )

            session.pop(
                "pre_auth_user_id",
                None
            )

            session.pop(
                "pre_auth_username",
                None
            )

            session.pop(
                "pre_auth_role",
                None
            )

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["logged_in"] = True

            conn.execute(
                """
                UPDATE users
                SET last_login = ?
                WHERE id = ?
                """,
                (
                    datetime.now().isoformat(
                        timespec="seconds"
                    ),
                    user["id"]
                )
            )

            conn.commit()

            log_action(
                user["id"],
                "LOGIN_2FA_SUCCESS",
                "User successfully authenticated using Google Authenticator.",
                request.remote_addr
            )

            flash(
                "Login successful. Welcome back!",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "verify_2fa.html"
        )

    except Exception as error:

        if conn:
            conn.rollback()

        app.logger.exception(
            "2FA VERIFICATION ERROR: %s",
            error
        )

        flash(
            "An error occurred during 2FA verification.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    finally:

        if conn:
            conn.close()


# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.route(
    "/change-password",
    methods=["GET", "POST"]
)
@login_required
def change_password():

    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            ""
        )

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if new_password != confirm_password:

            flash(
                "New passwords do not match.",
                "danger"
            )

            return redirect(
                url_for("change_password")
            )

        if not password_is_strong(
            new_password
        ):

            flash(
                "Password must contain at least 8 characters, "
                "including uppercase, lowercase and a number.",
                "danger"
            )

            return redirect(
                url_for("change_password")
            )

        conn = get_db_connection()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],)
        ).fetchone()

        if not user:

            conn.close()

            session.clear()

            return redirect(
                url_for("login")
            )

        if not check_password_hash(
            user["password_hash"],
            current_password
        ):

            conn.close()

            flash(
                "Incorrect current password.",
                "danger"
            )

            return redirect(
                url_for("change_password")
            )

        new_hash = generate_password_hash(
            new_password
        )

        conn.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (
                new_hash,
                session["user_id"]
            )
        )

        conn.commit()
        conn.close()

        log_action(
            session.get("user_id"),
            "CHANGE_PASSWORD",
            "User changed their password.",
            request.remote_addr
        )

        flash(
            "Password changed successfully.",
            "success"
        )

        return redirect(
            url_for("settings")
        )

    return render_template(
        "change_password.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    user_id = session.get(
        "user_id"
    )

    if user_id:

        log_action(
            user_id,
            "LOGOUT",
            "User logged out.",
            request.remote_addr
        )

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = None

    try:

        per_page = 5

        page = request.args.get(
            "page",
            default=1,
            type=int
        )

        if page < 1:
            page = 1

        conn = get_db_connection()

        total_documents = conn.execute(
            """
            SELECT COUNT(*)
            FROM documents
            """
        ).fetchone()[0]

        signed_documents = conn.execute(
            """
            SELECT COUNT(*)
            FROM documents
            WHERE LOWER(
                COALESCE(status, 'signed')
            ) = 'signed'
            """
        ).fetchone()[0]

        total_pages = max(
            1,
            (
                total_documents
                + per_page
                - 1
            ) // per_page
        )

        if page > total_pages:
            page = total_pages

        offset = (
            page - 1
        ) * per_page

        documents = conn.execute(
            """
            SELECT
                d.id,
                d.document_id,
                d.original_filename,
                d.signed_filename,
                d.signature_id,
                d.signed_by,
                d.signed_at,
                d.file_size,
                d.status,
                d.uploaded_by,
                d.created_at,
                u.username
            FROM documents d
            LEFT JOIN users u
                ON d.uploaded_by = u.id
            ORDER BY
                d.created_at DESC,
                d.id DESC
            LIMIT ? OFFSET ?
            """,
            (
                per_page,
                offset
            )
        ).fetchall()

        page_numbers = list(
            range(
                1,
                total_pages + 1
            )
        )

        conn.close()
        conn = None

        return render_template(
            "dashboard.html",

            documents=documents,

            page=page,
            total_pages=total_pages,
            page_numbers=page_numbers,

            total_documents=total_documents,
            signed_documents=signed_documents,

            application_name=APPLICATION_NAME,
            application_version=APPLICATION_VERSION,

            signer_name=SIGNER_NAME,
            signer_role=SIGNER_ROLE,

            username=session.get(
                "username",
                "Admin"
            ),

            role=session.get(
                "role",
                "user"
            )
        )

    except sqlite3.Error as error:

        app.logger.exception(
            "DATABASE ERROR IN DASHBOARD: %s",
            error
        )

        if conn:
            conn.close()

        return render_template(
            "500.html",
            error="Database error while loading the dashboard."
        ), 500

    except Exception as error:

        app.logger.exception(
            "DASHBOARD ERROR: %s",
            error
        )

        if conn:
            conn.close()

        return render_template(
            "500.html",
            error="An unexpected error occurred."
        ), 500

    finally:

        if conn:

            try:
                conn.close()
            except Exception:
                pass


# ============================================================
# SETTINGS
# ============================================================

@app.route(
    "/settings",
    methods=["GET", "POST"]
)
@login_required
def settings():

    if request.method == "POST":

        stamp = request.files.get(
            "stamp"
        )

        if stamp and stamp.filename:

            if not allowed_image(
                stamp.filename
            ):

                flash(
                    "Invalid stamp image. Use PNG, JPG or JPEG.",
                    "danger"
                )

                return redirect(
                    url_for("settings")
                )

            # Check size
            stamp.seek(
                0,
                os.SEEK_END
            )

            stamp_size = stamp.tell()

            stamp.seek(0)

            if stamp_size > MAX_IMAGE_SIZE:

                flash(
                    "Stamp image is too large. Maximum size is 5 MB.",
                    "danger"
                )

                return redirect(
                    url_for("settings")
                )

            # Save only stamp
            stamp.save(
                STAMP_FILE
            )

            log_action(
                session.get("user_id"),
                "UPDATE_STAMP",
                "Stored GS MUKONDO stamp image was updated.",
                request.remote_addr
            )

            flash(
                "Official stamp updated successfully.",
                "success"
            )

        return redirect(
            url_for("settings")
        )

    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT
            username,
            role,
            totp_enabled,
            created_at,
            last_login
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    conn.close()

    if not user:

        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "settings.html",

        # NO signature_exists
        # NO stored signature

        stamp_exists=os.path.isfile(
            STAMP_FILE
        ),

        totp_enabled=bool(
            user["totp_enabled"]
        ),

        username=user["username"],

        role=user["role"],

        created_at=user["created_at"],

        last_login=user["last_login"],

        signer_name=SIGNER_NAME,

        signer_role=SIGNER_ROLE
    )


# ============================================================
# UPLOAD AND SIGN PDF
# ============================================================

@app.route(
    "/upload",
    methods=["GET", "POST"]
)
@login_required
def upload():

    if request.method == "GET":

        return render_template(
            "upload.html"
        )

    uploaded_file = request.files.get(
        "document"
    )

    if (
        not uploaded_file
        or not uploaded_file.filename
    ):

        flash(
            "Please select a PDF document.",
            "danger"
        )

        return redirect(
            url_for("upload")
        )

    if not allowed_file(
        uploaded_file.filename
    ):

        flash(
            "Only PDF documents are allowed.",
            "danger"
        )

        return redirect(
            url_for("upload")
        )

    # --------------------------------------------------------
    # ONLY STAMP IS REQUIRED
    # --------------------------------------------------------

    if not os.path.isfile(
        STAMP_FILE
    ):

        flash(
            "Official stamp is missing. "
            "Please configure the stamp in Settings.",
            "danger"
        )

        return redirect(
            url_for("settings")
        )

    unique_id = uuid.uuid4().hex

    original_name = secure_filename(
        uploaded_file.filename
    )

    if not original_name:

        flash(
            "Invalid filename.",
            "danger"
        )

        return redirect(
            url_for("upload")
        )

    input_filename = (
        f"{unique_id}_{original_name}"
    )

    input_path = os.path.join(
        UPLOAD_FOLDER,
        input_filename
    )

    base_name = os.path.splitext(
        original_name
    )[0]

    output_filename = (
        f"{base_name}_signed_"
        f"{unique_id[:8]}.pdf"
    )

    output_path = os.path.join(
        SIGNED_FOLDER,
        output_filename
    )

    uploaded_file.save(
        input_path
    )

    doc = None
    conn = None

    try:

        # ----------------------------------------------------
        # FILE SIZE
        # ----------------------------------------------------

        file_size = os.path.getsize(
            input_path
        )

        if file_size > MAX_DOCUMENT_SIZE:

            raise ValueError(
                "The PDF is larger than the allowed 25 MB."
            )

        # ----------------------------------------------------
        # READ STAMP
        # ----------------------------------------------------

        stamp_bytes = read_binary_file(
            STAMP_FILE
        )

        # ----------------------------------------------------
        # GENERATE IDENTIFIERS
        # ----------------------------------------------------

        signing_id = generate_signature_id()

        document_id = generate_document_id()

        signed_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M"
        )

        # ----------------------------------------------------
        # OPEN PDF
        # ----------------------------------------------------

        doc = fitz.open(
            input_path
        )

        if doc.page_count == 0:

            raise ValueError(
                "The PDF contains no pages."
            )

        # ----------------------------------------------------
        # APPLY STAMP + DIGITAL SIGNATURE INFORMATION
        # ----------------------------------------------------

        for page in doc:

            apply_stamp_and_digital_signature(
                page,
                stamp_bytes,
                signing_id,
                signed_time
            )

            # Additional detailed digital signature
            # information on the bottom-right.
            add_digital_signature(
                page,
                signing_id,
                signed_time
            )

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        doc.save(
            output_path,
            garbage=4,
            deflate=True
        )

        doc.close()
        doc = None

        # ----------------------------------------------------
        # DATABASE
        # ----------------------------------------------------

        conn = get_db_connection()

        conn.execute(
            """
            INSERT INTO documents
            (
                document_id,
                original_filename,
                signed_filename,
                signature_id,
                signed_by,
                signed_at,
                file_size,
                status,
                uploaded_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document_id,
                original_name,
                output_filename,
                signing_id,
                SIGNER_NAME,
                signed_time,
                os.path.getsize(
                    output_path
                ),
                "signed",
                session["user_id"],
                datetime.now().isoformat(
                    timespec="seconds"
                ),
            )
        )

        conn.commit()
        conn.close()
        conn = None

        # ----------------------------------------------------
        # AUDIT
        # ----------------------------------------------------

        log_action(
            session.get("user_id"),
            "SIGN_DOCUMENT",
            (
                f"Document {document_id} signed with "
                f"GS MUKONDO stamp. "
                f"Signing ID: {signing_id}"
            ),
            request.remote_addr
        )

        flash(
            "Document signed successfully with the GS MUKONDO stamp.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    except Exception as error:

        if doc:

            try:
                doc.close()
            except Exception:
                pass

        if conn:

            try:
                conn.rollback()
                conn.close()
            except Exception:
                pass

        safe_remove(
            output_path
        )

        app.logger.exception(
            "DOCUMENT SIGNING ERROR: %s",
            error
        )

        flash(
            f"Error processing document: {error}",
            "danger"
        )

        return redirect(
            url_for("upload")
        )

    finally:

        safe_remove(
            input_path
        )


# ============================================================
# SIGNED DOCUMENT RESULT
# ============================================================

@app.route(
    "/result/<filename>"
)
@login_required
def result(filename):

    safe_name = secure_filename(
        filename
    )

    file_path = secure_path(
        SIGNED_FOLDER,
        safe_name
    )

    if not os.path.isfile(
        file_path
    ):

        flash(
            "Document not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    conn = get_db_connection()

    document = conn.execute(
        """
        SELECT *
        FROM documents
        WHERE signed_filename = ?
        """,
        (safe_name,)
    ).fetchone()

    conn.close()

    return render_template(
        "result.html",
        filename=safe_name,
        document=document
    )


# ============================================================
# PDF PREVIEW
# ============================================================

@app.route(
    "/preview/<filename>"
)
@login_required
def preview(filename):

    safe_name = secure_filename(
        filename
    )

    file_path = secure_path(
        SIGNED_FOLDER,
        safe_name
    )

    if not os.path.isfile(
        file_path
    ):

        abort(404)

    log_action(
        session.get("user_id"),
        "PREVIEW_DOCUMENT",
        f"Previewed document: {safe_name}",
        request.remote_addr
    )

    return send_from_directory(
        SIGNED_FOLDER,
        safe_name,
        mimetype="application/pdf"
    )


# ============================================================
# DOWNLOAD
# ============================================================

@app.route(
    "/download/<filename>"
)
@login_required
def download(filename):

    safe_name = secure_filename(
        filename
    )

    file_path = secure_path(
        SIGNED_FOLDER,
        safe_name
    )

    if not os.path.isfile(
        file_path
    ):

        abort(404)

    log_action(
        session.get("user_id"),
        "DOWNLOAD_DOCUMENT",
        f"Downloaded document: {safe_name}",
        request.remote_addr
    )

    return send_from_directory(
        SIGNED_FOLDER,
        safe_name,
        as_attachment=True
    )


# ============================================================
# STORED STAMP
# ============================================================

@app.route(
    "/storage/stamp"
)
@login_required
def stored_stamp():

    if not os.path.isfile(
        STAMP_FILE
    ):

        abort(404)

    return send_from_directory(
        STORAGE_FOLDER,
        "stamp.png"
    )


# ============================================================
# ADMIN: USERS
# ============================================================

@app.route(
    "/admin/users"
)
@admin_required
def admin_users():

    conn = get_db_connection()

    users = conn.execute(
        """
        SELECT
            id,
            username,
            role,
            active,
            totp_enabled,
            created_at,
            last_login
        FROM users
        ORDER BY id ASC
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin_users.html",
        users=users
    )


# ============================================================
# ADMIN: CREATE USER
# ============================================================

@app.route(
    "/admin/users/create",
    methods=["GET", "POST"]
)
@admin_required
def create_user():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        role = request.form.get(
            "role",
            "user"
        )

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return redirect(
                url_for("create_user")
            )

        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "danger"
            )

            return redirect(
                url_for("create_user")
            )

        if not password_is_strong(
            password
        ):

            flash(
                "Password must contain at least 8 characters, "
                "uppercase, lowercase and a number.",
                "danger"
            )

            return redirect(
                url_for("create_user")
            )

        if role not in {
            "admin",
            "user"
        }:

            role = "user"

        conn = get_db_connection()

        try:

            conn.execute(
                """
                INSERT INTO users
                (
                    username,
                    password_hash,
                    totp_secret,
                    totp_enabled,
                    role,
                    active,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(
                        password
                    ),
                    pyotp.random_base32(),
                    0,
                    role,
                    1,
                    datetime.now().isoformat(
                        timespec="seconds"
                    ),
                )
            )

            conn.commit()

            log_action(
                session.get("user_id"),
                "CREATE_USER",
                f"Created user: {username}",
                request.remote_addr
            )

            flash(
                "User created successfully.",
                "success"
            )

        except sqlite3.IntegrityError:

            flash(
                "Username already exists.",
                "danger"
            )

        finally:

            conn.close()

        return redirect(
            url_for("admin_users")
        )

    return render_template(
        "create_user.html"
    )


# ============================================================
# ADMIN: ENABLE / DISABLE USER
# ============================================================

@app.route(
    "/admin/users/<int:user_id>/toggle",
    methods=["POST"]
)
@admin_required
def toggle_user(user_id):

    conn = None

    try:

        conn = get_db_connection()

        user = conn.execute(
            """
            SELECT
                id,
                username,
                role,
                active
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not user:

            flash(
                "User not found.",
                "error"
            )

            return redirect(
                url_for("admin_users")
            )

        if user["id"] == session.get(
            "user_id"
        ):

            flash(
                "You cannot disable your own account.",
                "error"
            )

            return redirect(
                url_for("admin_users")
            )

        new_status = (
            0
            if user["active"]
            else 1
        )

        conn.execute(
            """
            UPDATE users
            SET active = ?
            WHERE id = ?
            """,
            (
                new_status,
                user_id
            )
        )

        conn.commit()

        action = (
            "USER_ENABLED"
            if new_status
            else "USER_DISABLED"
        )

        description = (
            f"User '{user['username']}' was "
            f"{'enabled' if new_status else 'disabled'} "
            f"by administrator."
        )

        log_action(
            session.get("user_id"),
            action,
            description,
            request.remote_addr
        )

        flash(
            (
                f"User '{user['username']}' "
                f"has been "
                f"{'enabled' if new_status else 'disabled'}."
            ),
            "success"
        )

        return redirect(
            url_for("admin_users")
        )

    except Exception as error:

        if conn:
            conn.rollback()

        app.logger.exception(
            "TOGGLE USER ERROR: %s",
            error
        )

        flash(
            "Unable to change the user's account status.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )

    finally:

        if conn:
            conn.close()


# ============================================================
# ADMIN: DOCUMENTS
# ============================================================

@app.route(
    "/admin/documents"
)
@admin_required
def admin_documents():

    conn = get_db_connection()

    documents = conn.execute(
        """
        SELECT
            d.*,
            u.username
        FROM documents d
        LEFT JOIN users u
            ON d.uploaded_by = u.id
        ORDER BY d.created_at DESC
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin_documents.html",
        documents=documents
    )


# ============================================================
# ADMIN: AUDIT LOG
# ============================================================

@app.route(
    "/admin/audit-logs"
)
@admin_required
def audit_logs():

    conn = None

    try:

        per_page = 5

        page = request.args.get(
            "page",
            default=1,
            type=int
        )

        if page < 1:
            page = 1

        conn = get_db_connection()

        total_logs = conn.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            """
        ).fetchone()[0]

        total_pages = max(
            1,
            (
                total_logs
                + per_page
                - 1
            ) // per_page
        )

        if page > total_pages:
            page = total_pages

        offset = (
            page - 1
        ) * per_page

        logs = conn.execute(
            """
            SELECT
                a.id,
                a.user_id,
                a.action,
                a.description,
                a.ip_address,
                a.created_at,
                u.username
            FROM audit_logs a
            LEFT JOIN users u
                ON a.user_id = u.id
            ORDER BY
                a.created_at DESC,
                a.id DESC
            LIMIT ? OFFSET ?
            """,
            (
                per_page,
                offset
            )
        ).fetchall()

        page_numbers = list(
            range(
                1,
                total_pages + 1
            )
        )

        return render_template(
            "audit_logs.html",
            logs=logs,
            page=page,
            per_page=per_page,
            total_logs=total_logs,
            total_pages=total_pages,
            page_numbers=page_numbers
        )

    except Exception as error:

        app.logger.exception(
            "AUDIT LOG ERROR: %s",
            error
        )

        return render_template(
            "500.html",
            error="Unable to load audit logs."
        ), 500

    finally:

        if conn:

            try:
                conn.close()
            except Exception:
                pass


# ============================================================
# DELETE DOCUMENT
# ============================================================

@app.route(
    "/delete-document/<int:document_id>",
    methods=["POST"]
)
@login_required
def delete_document(document_id):

    conn = None

    try:

        conn = get_db_connection()

        document = conn.execute(
            """
            SELECT *
            FROM documents
            WHERE id = ?
            """,
            (document_id,)
        ).fetchone()

        if not document:

            flash(
                "Document not found.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        # ----------------------------------------------------
        # OWNER OR ADMIN ONLY
        # ----------------------------------------------------

        if (
            session.get("role") != "admin"
            and document["uploaded_by"]
            != session.get("user_id")
        ):

            flash(
                "You do not have permission to delete this document.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        signed_filename = document[
            "signed_filename"
        ]

        # ----------------------------------------------------
        # DELETE SIGNED PDF
        # ----------------------------------------------------

        if signed_filename:

            signed_path = secure_path(
                SIGNED_FOLDER,
                signed_filename
            )

            if os.path.exists(
                signed_path
            ):

                if not safe_remove(
                    signed_path
                ):

                    app.logger.warning(
                        "Could not delete signed file: %s",
                        signed_path
                    )

        # ----------------------------------------------------
        # DELETE DATABASE RECORD
        # ----------------------------------------------------

        conn.execute(
            """
            DELETE FROM documents
            WHERE id = ?
            """,
            (document_id,)
        )

        conn.commit()

        log_action(
            session.get("user_id"),
            "DOCUMENT_DELETED",
            (
                f"Deleted document: "
                f"{document['original_filename']}"
            ),
            request.remote_addr
        )

        flash(
            (
                f"Document "
                f"'{document['original_filename']}' "
                f"deleted successfully."
            ),
            "success"
        )

    except Exception as error:

        if conn:
            conn.rollback()

        app.logger.exception(
            "DOCUMENT DELETE ERROR: %s",
            error
        )

        flash(
            "Unable to delete the document.",
            "error"
        )

    finally:

        if conn:
            conn.close()

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# APPLY STAMP + DIGITAL SIGNATURE TO EXISTING DOCUMENT
# ============================================================

@app.route(
    "/apply-grouped-signature/<int:document_id>",
    methods=["POST"]
)
@login_required
def apply_grouped_signature_endpoint(
    document_id
):

    conn = None
    output_pdf = None

    try:

        user_id = session.get(
            "user_id"
        )

        if not user_id:

            return redirect(
                url_for("login")
            )

        conn = get_db_connection()

        document = conn.execute(
            """
            SELECT *
            FROM documents
            WHERE id = ?
            """,
            (document_id,)
        ).fetchone()

        if not document:

            flash(
                "Document not found.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        if (
            session.get("role") != "admin"
            and document["uploaded_by"] != user_id
        ):

            flash(
                "You are not allowed to modify this document.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        # ----------------------------------------------------
        # ONLY STAMP REQUIRED
        # ----------------------------------------------------

        if not os.path.isfile(
            STAMP_FILE
        ):

            flash(
                "Stamp is not configured. Upload it in Settings.",
                "error"
            )

            return redirect(
                url_for("settings")
            )

        # ----------------------------------------------------
        # Find original uploaded PDF.
        #
        # The original upload filename stored in the database
        # may not be the physical upload filename, so search
        # for the UUID-prefixed file.
        # ----------------------------------------------------

        original_filename = secure_filename(
            document["original_filename"]
        )

        possible_files = []

        for filename in os.listdir(
            UPLOAD_FOLDER
        ):

            if filename.endswith(
                "_" + original_filename
            ):

                possible_files.append(
                    filename
                )

        if not possible_files:

            flash(
                "Original uploaded PDF could not be found.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        input_filename = sorted(
            possible_files
        )[-1]

        input_pdf = secure_path(
            UPLOAD_FOLDER,
            input_filename
        )

        # ----------------------------------------------------
        # OUTPUT
        # ----------------------------------------------------

        output_filename = (
            f"signed_{uuid.uuid4().hex}.pdf"
        )

        output_pdf = secure_path(
            SIGNED_FOLDER,
            output_filename
        )

        # ----------------------------------------------------
        # READ STAMP INTO MEMORY
        # ----------------------------------------------------

        stamp_bytes = read_binary_file(
            STAMP_FILE
        )

        signing_id = generate_signature_id()

        signed_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M"
        )

        # ----------------------------------------------------
        # OPEN PDF
        # ----------------------------------------------------

        pdf = fitz.open(
            input_pdf
        )

        try:

            if pdf.page_count == 0:

                raise ValueError(
                    "The PDF contains no pages."
                )

            for page in pdf:

                apply_stamp_and_digital_signature(
                    page,
                    stamp_bytes,
                    signing_id,
                    signed_time
                )

                add_digital_signature(
                    page,
                    signing_id,
                    signed_time
                )

            pdf.save(
                output_pdf,
                garbage=4,
                deflate=True
            )

        finally:

            pdf.close()

        # ----------------------------------------------------
        # UPDATE DOCUMENT
        # ----------------------------------------------------

        conn.execute(
            """
            UPDATE documents
            SET
                signed_filename = ?,
                signature_id = ?,
                signed_at = ?,
                status = 'signed'
            WHERE id = ?
            """,
            (
                output_filename,
                signing_id,
                signed_time,
                document_id
            )
        )

        conn.commit()

        log_action(
            user_id,
            "SIGN_DOCUMENT",
            (
                f"Applied GS MUKONDO stamp and "
                f"digital signature information to "
                f"document #{document_id}. "
                f"Signing ID: {signing_id}"
            ),
            request.remote_addr
        )

        flash(
            "Document signed successfully.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    except Exception as error:

        if output_pdf:

            safe_remove(
                output_pdf
            )

        if conn:

            conn.rollback()

        app.logger.exception(
            "GROUPED SIGNING ERROR: %s",
            error
        )

        flash(
            f"Unable to sign document: {error}",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    finally:

        if conn:
            conn.close()


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def request_entity_too_large(error):

    flash(
        "Uploaded file is too large. Maximum size is 25 MB.",
        "danger"
    )

    return redirect(
        url_for("upload")
    )


@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "404.html"
    ), 404


@app.errorhandler(500)
def internal_server_error(error):

    return render_template(
        "500.html"
    ), 500


# ============================================================
# CONTEXT PROCESSOR
# ============================================================

@app.context_processor
def inject_application_info():

    return {
        "application_name": APPLICATION_NAME,
        "application_version": APPLICATION_VERSION,
        "signer_name": SIGNER_NAME,
        "signer_role": SIGNER_ROLE,
        "current_year": datetime.now().year,
    }


# ============================================================
# CLEAN WERKZEUG LOGS
# ============================================================

class IgnoreNoiseFilter(
    __import__("logging").Filter
):

    def filter(
        self,
        record
    ):

        message = record.getMessage()

        ignored_paths = [
            "/hybridaction/zybTrackerStatisticsAction",
        ]

        return not any(
            path in message
            for path in ignored_paths
        )


werkzeug_logger = __import__(
    "logging"
).getLogger(
    "werkzeug"
)

werkzeug_logger.addFilter(
    IgnoreNoiseFilter()
)

if __name__ == "__main__":

    # ==========================================================
    # DISPLAY REGISTERED FLASK ROUTES
    # ==========================================================
    print("\n========== REGISTERED FLASK ROUTES ==========")

    for rule in app.url_map.iter_rules():
        print(
            f"{rule.endpoint:30} "
            f"{sorted(rule.methods)} "
            f"{rule}"
        )

    print("=============================================\n")

    # ==========================================================
    # APPLICATION INFORMATION
    # ==========================================================
    print("=" * 60)
    print("GS MUKONDO DIGITAL SIGNER")
    print("=" * 60)
    print("STAMP + SIGNATURE DIGITAL SIGNING SYSTEM")
    print("=" * 60)
    print("Server: http://127.0.0.1:8080")
    print("Login : http://127.0.0.1:8080/login")
    print("Admin : http://127.0.0.1:8080/admin/cleanup")
    print("=" * 60)

    # ==========================================================
    # START FLASK SERVER
    # ==========================================================
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=True,
        use_reloader=False
    )
