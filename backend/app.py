from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from database import get_db_connection, initialize_database, BASE_DIR
from hashing import calculate_sha256

from pathlib import Path
from datetime import datetime
import os
import uuid


app = Flask(__name__)
CORS(app)

# Maximum upload size: 50 MB
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

# Folder where baseline copies are stored
EVIDENCE_DIR = BASE_DIR / "evidence_files"
EVIDENCE_DIR.mkdir(exist_ok=True)

initialize_database()


def json_error(message, status=400):
    return jsonify({"success": False, "message": message}), status


def resolve_file_path(file_path):
    """Resolve a stored relative path or an existing absolute path."""
    if not file_path:
        return None

    path = Path(file_path)

    if path.is_absolute():
        return path

    return BASE_DIR / path


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "CyberTrace",
        "description": "File Integrity and Digital Evidence Monitoring System",
        "status": "Backend Running"
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "backend": "online",
        "database": "connected"
    })


# ============================================================
# LOGIN
# ============================================================

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return json_error("Username and password are required", 400)

    connection = get_db_connection()
    user = connection.execute(
        "SELECT id, username, password, role FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    connection.close()

    if not user or not check_password_hash(user["password"], password):
        return json_error("Invalid username or password", 401)

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    })


# ============================================================
# REGISTER A FILE FROM THE BROWSER
# ============================================================

@app.route("/api/files/upload", methods=["POST"])
def upload_monitored_file():
    uploaded_file = request.files.get("file")

    if uploaded_file is None or not uploaded_file.filename:
        return json_error("Please select a file", 400)

    original_name = Path(uploaded_file.filename).name
    safe_name = secure_filename(original_name)

    if not safe_name:
        safe_name = "evidence_file"

    connection = get_db_connection()

    # Keep the UI simple: one active baseline per filename.
    existing = connection.execute(
        """
        SELECT id, status
        FROM monitored_files
        WHERE file_name = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (original_name,)
    ).fetchone()

    if existing:
        connection.close()
        return json_error(
            "A baseline for this filename already exists. Use Verify Integrity instead.",
            409
        )

    # Temporary upload path; the final path contains a unique ID.
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    stored_path = EVIDENCE_DIR / unique_name

    try:
        uploaded_file.save(stored_path)
        file_hash = calculate_sha256(stored_path)

        if file_hash is None:
            if stored_path.exists():
                stored_path.unlink()
            connection.close()
            return json_error("The file could not be read", 400)

        relative_path = str(stored_path.relative_to(BASE_DIR))

        cursor = connection.execute(
            """
            INSERT INTO monitored_files
            (file_name, file_path, original_hash, current_hash, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                original_name,
                relative_path,
                file_hash,
                file_hash,
                "SAFE"
            )
        )

        file_id = cursor.lastrowid

        connection.execute(
            """
            INSERT INTO audit_logs (username, action, details)
            VALUES (?, ?, ?)
            """,
            (
                "system",
                "FILE_ADDED",
                f"File added for monitoring: {original_name}"
            )
        )

        connection.commit()

    except Exception as exc:
        connection.rollback()
        if stored_path.exists():
            stored_path.unlink()
        connection.close()
        return json_error(f"Could not register file: {exc}", 500)

    connection.close()

    return jsonify({
        "success": True,
        "message": "File added for monitoring successfully",
        "file": {
            "id": file_id,
            "file_name": original_name,
            "file_path": relative_path,
            "sha256": file_hash,
            "status": "SAFE"
        }
    }), 201


# ============================================================
# LEGACY PATH-BASED REGISTRATION
# Kept for backend testing and existing PowerShell workflow.
# ============================================================

@app.route("/api/files", methods=["POST"])
def add_monitored_file():
    data = request.get_json(silent=True) or {}
    file_path = str(data.get("file_path", "")).strip()

    if not file_path:
        return json_error("file_path is required", 400)

    path = Path(file_path)

    if not path.is_file():
        return json_error("File not found or permission denied", 404)

    file_hash = calculate_sha256(path)

    if file_hash is None:
        return json_error("File not found or permission denied", 404)

    file_name = path.name
    connection = get_db_connection()

    existing_file = connection.execute(
        "SELECT id FROM monitored_files WHERE file_path = ?",
        (str(path),)
    ).fetchone()

    if existing_file:
        connection.close()
        return json_error("File is already being monitored", 409)

    cursor = connection.execute(
        """
        INSERT INTO monitored_files
        (file_name, file_path, original_hash, current_hash, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (file_name, str(path), file_hash, file_hash, "SAFE")
    )

    file_id = cursor.lastrowid

    connection.execute(
        """
        INSERT INTO audit_logs (username, action, details)
        VALUES (?, ?, ?)
        """,
        ("system", "FILE_ADDED", f"File added for monitoring: {file_name}")
    )

    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "message": "File added for monitoring successfully",
        "file": {
            "id": file_id,
            "file_name": file_name,
            "file_path": str(path),
            "sha256": file_hash,
            "status": "SAFE"
        }
    }), 201


@app.route("/api/files", methods=["GET"])
def get_files():
    connection = get_db_connection()
    files = connection.execute(
        "SELECT * FROM monitored_files ORDER BY id DESC"
    ).fetchall()
    connection.close()

    return jsonify([dict(file) for file in files])


# ============================================================
# VERIFY A BROWSER-UPLOADED COPY AGAINST THE SAVED BASELINE
# ============================================================

@app.route("/api/files/<int:file_id>/verify-upload", methods=["POST"])
def verify_uploaded_copy(file_id):
    uploaded_file = request.files.get("file")

    if uploaded_file is None or not uploaded_file.filename:
        return json_error("Please select a file to verify", 400)

    connection = get_db_connection()
    monitored_file = connection.execute(
        "SELECT * FROM monitored_files WHERE id = ?",
        (file_id,)
    ).fetchone()

    if not monitored_file:
        connection.close()
        return json_error("Monitored file not found", 404)

    # Read the uploaded copy directly into a temporary file.
    temp_name = f"_verify_{uuid.uuid4().hex}.tmp"
    temp_path = EVIDENCE_DIR / temp_name

    try:
        uploaded_file.save(temp_path)
        current_hash = calculate_sha256(temp_path)

        if current_hash is None:
            connection.close()
            if temp_path.exists():
                temp_path.unlink()
            return json_error("Could not calculate the uploaded file hash", 400)

        original_hash = monitored_file["original_hash"]

        if original_hash == current_hash:
            status = "SAFE"
            message = "File integrity verified"
            event_type = "INTEGRITY_CHECK"
            evidence_status = "VERIFIED"
        else:
            status = "MODIFIED"
            message = "INTEGRITY VIOLATION DETECTED"
            event_type = "FILE_MODIFIED"
            evidence_status = "INTEGRITY_VIOLATION"

        connection.execute(
            """
            UPDATE monitored_files
            SET current_hash = ?, status = ?
            WHERE id = ?
            """,
            (current_hash, status, file_id)
        )

        # Only create a digital-evidence row when a violation occurs.
        if status == "MODIFIED":
            connection.execute(
                """
                INSERT INTO evidence
                (file_id, event_type, old_hash, new_hash, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    event_type,
                    original_hash,
                    current_hash,
                    evidence_status
                )
            )

            action = "INTEGRITY_VIOLATION"
            details = f"File modification detected: {monitored_file['file_name']}"
        else:
            action = "INTEGRITY_CHECK"
            details = f"Integrity verified: {monitored_file['file_name']}"

        connection.execute(
            """
            INSERT INTO audit_logs (username, action, details)
            VALUES (?, ?, ?)
            """,
            ("system", action, details)
        )

        connection.commit()

    except Exception as exc:
        connection.rollback()
        connection.close()
        if temp_path.exists():
            temp_path.unlink()
        return json_error(f"Verification failed: {exc}", 500)

    connection.close()

    if temp_path.exists():
        temp_path.unlink()

    return jsonify({
        "success": True,
        "file_id": file_id,
        "file_name": monitored_file["file_name"],
        "status": status,
        "message": message,
        "original_hash": original_hash,
        "current_hash": current_hash
    })


# ============================================================
# VERIFY THE SERVER-STORED BASELINE
# ============================================================

@app.route("/api/files/<int:file_id>/check", methods=["POST"])
def check_file_integrity(file_id):
    connection = get_db_connection()

    monitored_file = connection.execute(
        "SELECT * FROM monitored_files WHERE id = ?",
        (file_id,)
    ).fetchone()

    if not monitored_file:
        connection.close()
        return json_error("Monitored file not found", 404)

    path = resolve_file_path(monitored_file["file_path"])
    original_hash = monitored_file["original_hash"]
    current_hash = calculate_sha256(path)

    if current_hash is None:
        connection.execute(
            """
            UPDATE monitored_files
            SET status = ?, current_hash = NULL
            WHERE id = ?
            """,
            ("DELETED", file_id)
        )

        connection.execute(
            """
            INSERT INTO evidence
            (file_id, event_type, old_hash, new_hash, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                file_id,
                "FILE_DELETED",
                original_hash,
                None,
                "INTEGRITY_VIOLATION"
            )
        )

        connection.execute(
            """
            INSERT INTO audit_logs (username, action, details)
            VALUES (?, ?, ?)
            """,
            (
                "system",
                "FILE_DELETED",
                f"Monitored file deleted or inaccessible: {monitored_file['file_name']}"
            )
        )

        connection.commit()
        connection.close()

        return jsonify({
            "success": True,
            "file_id": file_id,
            "file_name": monitored_file["file_name"],
            "status": "DELETED",
            "message": "File deleted or inaccessible",
            "original_hash": original_hash,
            "current_hash": None
        })

    if original_hash == current_hash:
        status = "SAFE"
        message = "File integrity verified"
    else:
        status = "MODIFIED"
        message = "INTEGRITY VIOLATION DETECTED"

        connection.execute(
            """
            INSERT INTO evidence
            (file_id, event_type, old_hash, new_hash, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                file_id,
                "FILE_MODIFIED",
                original_hash,
                current_hash,
                "INTEGRITY_VIOLATION"
            )
        )

    connection.execute(
        """
        UPDATE monitored_files
        SET current_hash = ?, status = ?
        WHERE id = ?
        """,
        (current_hash, status, file_id)
    )

    connection.execute(
        """
        INSERT INTO audit_logs (username, action, details)
        VALUES (?, ?, ?)
        """,
        (
            "system",
            "INTEGRITY_CHECK" if status == "SAFE" else "INTEGRITY_VIOLATION",
            (
                f"Integrity verified: {monitored_file['file_name']}"
                if status == "SAFE"
                else f"File modification detected: {monitored_file['file_name']}"
            )
        )
    )

    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "file_id": file_id,
        "file_name": monitored_file["file_name"],
        "status": status,
        "message": message,
        "original_hash": original_hash,
        "current_hash": current_hash
    })


# ============================================================
# EVIDENCE
# ============================================================

@app.route("/api/evidence", methods=["GET"])
def get_evidence():
    connection = get_db_connection()

    evidence = connection.execute(
        """
        SELECT
            evidence.id,
            evidence.file_id,
            monitored_files.file_name,
            monitored_files.file_path,
            evidence.event_type,
            evidence.old_hash,
            evidence.new_hash,
            evidence.status,
            evidence.detected_at
        FROM evidence
        JOIN monitored_files
            ON evidence.file_id = monitored_files.id
        ORDER BY evidence.id DESC
        """
    ).fetchall()

    connection.close()
    return jsonify([dict(record) for record in evidence])


# ============================================================
# AUDIT LOGS
# ============================================================

@app.route("/api/logs", methods=["GET"])
def get_logs():
    connection = get_db_connection()

    logs = connection.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC"
    ).fetchall()

    connection.close()
    return jsonify([dict(log) for log in logs])


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    connection = get_db_connection()

    total_files = connection.execute(
        "SELECT COUNT(*) AS count FROM monitored_files"
    ).fetchone()["count"]

    modified_files = connection.execute(
        "SELECT COUNT(*) AS count FROM monitored_files WHERE status = 'MODIFIED'"
    ).fetchone()["count"]

    safe_files = connection.execute(
        "SELECT COUNT(*) AS count FROM monitored_files WHERE status = 'SAFE'"
    ).fetchone()["count"]

    deleted_files = connection.execute(
        "SELECT COUNT(*) AS count FROM monitored_files WHERE status = 'DELETED'"
    ).fetchone()["count"]

    evidence_count = connection.execute(
        "SELECT COUNT(*) AS count FROM evidence"
    ).fetchone()["count"]

    connection.close()

    return jsonify({
        "total_files": total_files,
        "safe_files": safe_files,
        "modified_files": modified_files,
        "deleted_files": deleted_files,
        "evidence_records": evidence_count
    })


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
