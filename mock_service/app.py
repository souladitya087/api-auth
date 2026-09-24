from flask import Flask, jsonify, request

app = Flask(__name__)

# Simulated in-memory database
USERS = {
    "user_1": {"id": "user_1", "name": "Alice Tenant", "role": "user", "token": "token-alice-123"},
    "user_2": {"id": "user_2", "name": "Bob Tenant", "role": "user", "token": "token-bob-456"},
    "admin_1": {"id": "admin_1", "name": "System Admin", "role": "admin", "token": "token-admin-789"},
}

DOCUMENTS = {
    "doc_101": {"id": "doc_101", "owner_id": "user_1", "title": "Alice Confidential Strategy", "content": "Secret Project 2026"},
    "doc_202": {"id": "doc_202", "owner_id": "user_2", "title": "Bob Public Notes", "content": "Lunch meeting at noon"},
}

ORDERS = {
    "ord_1": {"id": "ord_1", "owner_id": "user_1", "item": "Corporate Laptop", "total": 1500.0},
    "ord_2": {"id": "ord_2", "owner_id": "user_2", "item": "Wireless Mouse", "total": 25.0},
}


def get_current_user():
    """Extracts authenticated user from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    token = auth_header.replace("Bearer ", "").strip()
    for user in USERS.values():
        if user["token"] == token:
            return user
    return None


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "Mock Banking & Document API"})


# --- VULNERABLE ENDPOINTS (To demonstrate BOLA / BFLA) ---

@app.route("/api/v1/documents/<doc_id>", methods=["GET"])
def get_document(doc_id):
    """
    VULNERABLE TO BOLA (API1:2023):
    Authenticates that caller has a valid token, but FAILS to check
    whether the document actually belongs to the authenticated user!
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404

    # Vulnerability: Returns document without checking doc['owner_id'] == user['id']
    return jsonify({"status": "success", "document": doc}), 200


@app.route("/api/v1/admin/system-stats", methods=["GET"])
def get_admin_stats():
    """
    VULNERABLE TO BFLA (API5:2023):
    Allows any authenticated user to view administrative telemetry,
    failing to verify role == 'admin'.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # Vulnerability: Missing role check (e.g. if user['role'] != 'admin')
    return jsonify({
        "status": "success",
        "system_stats": {
            "database_load": "12%",
            "active_sessions": 432,
            "internal_ip": "10.0.4.15",
            "server_version": "v3.14-enterprise",
        }
    }), 200


# --- SECURED ENDPOINTS (Negative Controls) ---

@app.route("/api/v1/profile/<user_id>", methods=["GET"])
def get_user_profile(user_id):
    """
    SECURE ENDPOINT:
    Correctly validates that the requester's ID matches the requested profile ID.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if user["id"] != user_id and user["role"] != "admin":
        return jsonify({"error": "Forbidden: Access denied to other tenant profiles"}), 403

    target_user = USERS.get(user_id)
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"status": "success", "profile": target_user}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
