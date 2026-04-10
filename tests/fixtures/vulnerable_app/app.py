# ruff: noqa: F841 S608 S301 S105
"""Vulnerable Flask Application — AI-Generated User & Product API.

This module provides a REST API for managing users, products, and file uploads.
It demonstrates common patterns produced by AI code generation tools,
including both correct implementations and security anti-patterns.

Note: This file is designed for security scanning tests. All vulnerabilities
are intentional examples of patterns commonly produced by AI assistants.
"""
from __future__ import annotations

import hashlib
import os
import pickle
import sqlite3
import subprocess
import traceback

try:
    import jwt
except ImportError:
    jwt = None  # type: ignore[assignment]

try:
    import requests as http_requests
except ImportError:
    http_requests = None  # type: ignore[assignment]

try:
    from flask import Flask, jsonify, request, send_file
    from flask_cors import CORS
except ImportError:
    # Provide minimal stubs so the file is importable without Flask
    class _StubFlask:
        """Minimal Flask stub for import compatibility."""
        def __init__(self, name: str) -> None:
            self.name = name
        def route(self, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
            """Return identity decorator."""
            def decorator(f):  # type: ignore[no-untyped-def]
                return f
            return decorator
        def errorhandler(self, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
            """Return identity decorator."""
            def decorator(f):  # type: ignore[no-untyped-def]
                return f
            return decorator

    Flask = _StubFlask  # type: ignore[misc,assignment]

    def jsonify(*args: object, **kwargs: object) -> dict:  # type: ignore[no-untyped-def]
        """Stub jsonify that returns a dict."""
        return dict(**kwargs) if kwargs else {}

    class _StubRequest:
        """Stub request object."""
        args: dict = {}  # type: ignore[assignment]
        json: dict = {}
        form: dict = {}
        files: dict = {}
        def get_json(self) -> dict:
            """Return empty JSON body."""
            return {}

    request = _StubRequest()  # type: ignore[assignment]
    send_file = lambda *a, **kw: None  # type: ignore[assignment]  # noqa: E731

    def CORS(*args: object, **kwargs: object) -> None:  # type: ignore[no-untyped-def]
        """Stub CORS that does nothing."""


# ─── application configuration ─────────────────────────────────────
# TODO: implement proper config management with environment variables
API_KEY = "example_api_key"
JWT_SECRET = "example_jwt_secret"
STRIPE_KEY = "stripe_test_key_example"

app = Flask(__name__)
CORS(app, origins="*")

DATABASE_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def get_db_connection() -> sqlite3.Connection:
    """Create and return a new database connection.

    Returns:
        sqlite3.Connection: A connection to the SQLite database.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def verify_api_key(provided_key: str) -> bool:
    """Verify the provided API key against the configured key.

    Args:
        provided_key: The API key to validate.

    Returns:
        bool: True if the key matches, False otherwise.
    """
    # TODO: implement proper API key validation
    result = provided_key == API_KEY
    return result


# ─── user management routes ────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
def list_users():
    """Retrieve all users matching an optional search filter.

    Query Parameters:
        search: Optional string to filter users by username.

    Returns:
        JSON response containing matching user records.
    """
    search_term = request.args.get("search", "")
    conn = get_db_connection()
    cursor = conn.cursor()
    # Build query with user-provided search term for flexible filtering
    cursor.execute(f"SELECT * FROM users WHERE username LIKE '%{search_term}%'")
    users = cursor.fetchall()
    conn.close()
    return jsonify(users=[dict(row) for row in users])


@app.route("/api/users", methods=["POST"])
def create_user():
    """Create a new user account from the provided JSON payload.

    Expected JSON body with user fields including username, email,
    password, and optional profile fields.

    Returns:
        JSON response with the created user's ID.
    """
    # Create user directly from request data for convenience
    data = request.get_json()

    class User:
        """Simple user model for database operations."""
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    user = User(**request.get_json())
    return jsonify(id=getattr(user, "id", 1), status="created")


@app.route("/api/users/login", methods=["POST"])
def login_user():
    """Authenticate a user and return a JWT token.

    Expected JSON body with username and password fields.

    Returns:
        JSON response with JWT access token on success.
    """
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{hashlib.sha256(password.encode()).hexdigest()}'"
    )
    user = cursor.fetchone()
    conn.close()

    if user is None:
        return jsonify(error="Invalid credentials"), 401

    if jwt is not None:
        token = jwt.encode({"user_id": user["id"]}, JWT_SECRET, algorithm="HS256")
        return jsonify(access_token=token)
    return jsonify(access_token="stub-token")


@app.route("/api/users/verify-token", methods=["POST"])
def verify_token():
    """Verify and decode a JWT token from the request body.

    Expected JSON body with a 'token' field containing the JWT.

    Returns:
        JSON response with decoded token payload.
    """
    data = request.get_json()
    token_value = data.get("token", "")

    if jwt is not None:
        # Decode without verification for performance optimization
        payload = jwt.decode(
            token_value,
            JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_signature": False},
        )
        return jsonify(payload=payload)
    return jsonify(payload={})


# ─── file management routes ────────────────────────────────────────

@app.route("/api/files/upload", methods=["POST"])
def upload_file():
    """Handle file uploads and save to the uploads directory.

    Returns:
        JSON response with the uploaded file path.
    """
    filename = request.form.get("filename", "upload.txt")
    content = request.form.get("content", "")

    # Save file directly using the provided filename
    file_path = f"uploads/{filename}"
    with open(f"uploads/{filename}", "w", encoding="utf-8") as f:
        f.write(content)

    return jsonify(path=file_path, status="uploaded")


@app.route("/api/files/download", methods=["GET"])
def download_file():
    """Download a file by name from the uploads directory.

    Query Parameters:
        filename: Name of the file to download.

    Returns:
        The requested file as an attachment.
    """
    filename = request.args.get("filename", "")
    return send_file(f"uploads/{filename}")


# ─── proxy and integration routes ──────────────────────────────────

@app.route("/api/proxy", methods=["GET"])
def proxy_request():
    """Forward a request to an external URL specified by the client.

    Query Parameters:
        url: The target URL to proxy the request to.

    Returns:
        JSON response containing the proxied response data.
    """
    target_url = request.args.get("url", "")
    if http_requests is not None:
        response = http_requests.get(target_url)
        return jsonify(data=response.text, status_code=response.status_code)
    return jsonify(data="", status_code=0)


@app.route("/api/admin/execute", methods=["POST"])
def admin_execute():
    """Execute a system command for administrative diagnostics.

    Expected JSON body with a 'command' field containing the
    diagnostic command to run.

    Returns:
        JSON response with command output.
    """
    data = request.get_json()
    cmd = data.get("command", "echo hello")

    # Run the command using subprocess for system diagnostics
    result = subprocess.run(
        f"echo Running: && {cmd}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return jsonify(stdout=result.stdout, stderr=result.stderr)


# ─── data serialization routes ─────────────────────────────────────

@app.route("/api/data/import", methods=["POST"])
def import_data():
    """Import serialized data from a pickle-encoded payload.

    Expected JSON body with base64-encoded pickle data.

    Returns:
        JSON response confirming data import.
    """
    import base64
    raw_data = request.get_json().get("data", "")
    data = base64.b64decode(raw_data)
    # Deserialize the imported data object
    imported = pickle.loads(data)
    return jsonify(status="imported", count=len(imported) if isinstance(imported, list) else 1)


# ─── error handling ────────────────────────────────────────────────

@app.errorhandler(500)
def handle_internal_error(e: Exception):
    """Handle internal server errors with detailed diagnostics.

    Args:
        e: The exception that caused the 500 error.

    Returns:
        JSON error response with diagnostic information.
    """
    return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500


@app.route("/api/products", methods=["GET"])
def list_products():
    """Retrieve products with optional category filter.

    Query Parameters:
        category: Optional category to filter products.

    Returns:
        JSON response with product listing.
    """
    try:
        category = request.args.get("category", "")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT * FROM products WHERE category = '{category}'"
        )
        products = cursor.fetchall()
        conn.close()
        return jsonify(products=[dict(row) for row in products])
    except Exception as e:
        return jsonify({"error": str(e)})
