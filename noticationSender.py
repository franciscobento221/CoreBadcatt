from flask import Flask, request, jsonify
import os
#push
#teste push
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

HASHCAT_DIR = r"C:\Users\Public\Documents\ServidorCORE\hashcat-6.2.6"
CRACKED_PASSWORDS_FILE = os.path.join(HASHCAT_DIR, "all_cracked_hashes.txt")


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

@app.route('/check', methods=['POST'])
def check_cracked():
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    try:
        with open(CRACKED_PASSWORDS_FILE, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                user, password = line.strip().split(":", 1)
                if user == username:
                    return jsonify({"status": "cracked", "password": password})
    except FileNotFoundError:
        return jsonify({"error": "Cracked password file not found"}), 500

    return jsonify({"status": "not_cracked"})



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, threaded=True)
