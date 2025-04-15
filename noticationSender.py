from flask import Flask, request, jsonify

app = Flask(__name__)

# Hardcoded users (username: {password, role})
USERS = {
    "admin@estg.pt": {"password": "admin123", "role": "admin"},
    "admin@esecs.pt": {"password": "admin123", "role": "admin"},
    "admin@esad.pt": {"password": "admin123", "role": "admin"},
    "user1@esecs.pt": {"password": "user123", "role": "user"},
    "user2@estg.pt": {"password": "user456", "role": "user"},
    "user3@sad.pt": {"password": "user456", "role": "admin"},


}


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = USERS.get(username)
    if user and user["password"] == password:
        return jsonify({"status": "success", "role": user["role"]})

    return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, threaded=True)
