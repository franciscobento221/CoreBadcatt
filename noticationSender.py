from flask import Flask, request, jsonify
import os


app = Flask(__name__)

# HARDCODED USERS
USERS = {
    "admin@estg.pt": {"password": "admin123", "role": "admin"},
    "admin@esecs.pt": {"password": "admin123", "role": "admin"},
    "admin@esad.pt": {"password": "admin123", "role": "admin"},
    "user1@esecs.pt": {"password": "user123", "role": "user"},
    "user2@estg.pt": {"password": "user456", "role": "user"},
    "user3@sad.pt": {"password": "user456", "role": "admin"},

    "admin@domainx.com": {"password": "admin123", "role": "admin"},
    "admin@domainy.com": {"password": "admin123", "role": "admin"},
    "admin@domainz.com": {"password": "admin123", "role": "admin"},

    "user@domainx.com": {"password": "user123", "role": "user"},
    "user@domainy.com": {"password": "user123", "role": "user"},
    "user@domainz.com": {"password": "user123", "role": "user"},



}

HASHCAT_DIR = r"C:\Users\Public\Documents\ServidorCORE\hashcat-6.2.6"  #ALTERAR PARA SITIO ONDE ESTEJA A PASTA COM O HASHCAT
CRACKED_PASSWORDS_FILE = os.path.join(HASHCAT_DIR, "all_cracked_hashes.txt")

#LOGIN
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


#FAZER UPDATE À LISTA DE HASHES DECIFRADAS
@app.route('/check', methods=['POST'])
def check_cracked():
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    empresas_dir = os.path.join(HASHCAT_DIR, "Empresas")
    if not os.path.exists(empresas_dir):
        return jsonify({"error": "Empresas folder not found"}), 500

    hash_to_user = {}
    for filename in os.listdir(empresas_dir):
        if not filename.endswith(".txt"):
            continue
        file_path = os.path.join(empresas_dir, filename)
        try:
            with open(file_path, "r") as f:
                for line in f:
                    parts = line.strip().split(":", 1)
                    if len(parts) == 2:
                        user, hash_val = parts
                        if hash_val not in hash_to_user:
                            hash_to_user[hash_val] = user
        except Exception as e:
            continue

    if not os.path.exists(CRACKED_PASSWORDS_FILE):
        return jsonify({"error": "Cracked password file not found"}), 500

    try:
        updated_lines = set()  # use a set to deduplicate
        with open(CRACKED_PASSWORDS_FILE, "r") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                if ":" in raw:
                    updated_lines.add(raw)
                elif raw in hash_to_user:
                    updated_lines.add(f"{hash_to_user[raw]}:{raw}")
                else:
                    updated_lines.add(raw)

        with open(CRACKED_PASSWORDS_FILE, "w") as f:
            for line in sorted(updated_lines):
                f.write(line + "\n")

        cracked_count = sum(1 for line in updated_lines if ":" in line)

        if cracked_count > 0:
            return jsonify({"status": "cracked", "cracked_hashes": cracked_count})
        else:
            return jsonify({"status": "not_cracked", "cracked_hashes": 0})



    except Exception as e:
        return jsonify({"error": f"Failed to update cracked file: {e}"}), 500



#FAZER FILE COM OS USERS QUE TIVERAM HASH DECIFRADA
@app.route('/get_hashes_by_domain', methods=['POST'])
def get_hashes_by_domain():
    data = request.get_json()
    username = data.get("username")

    if not username or "@" not in username:
        return jsonify({"error": "Invalid username"}), 400

    domain = username.split("@")[1].lower()

    empresas_dir = os.path.join(HASHCAT_DIR, "Empresas")
    if not os.path.exists(empresas_dir):
        return jsonify({"error": "Empresas folder not found"}), 500

    hash_to_user = {}
    for filename in os.listdir(empresas_dir):
        if filename.endswith(".txt"):
            file_path = os.path.join(empresas_dir, filename)
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        parts = line.strip().split(":", 1)
                        if len(parts) == 2:
                            user, hash_val = parts
                            if hash_val not in hash_to_user:
                                hash_to_user[hash_val] = user
            except Exception:
                continue

    if not os.path.exists(CRACKED_PASSWORDS_FILE):
        return jsonify({"error": "Cracked password file not found"}), 500

    try:
        updated_lines = set()
        with open(CRACKED_PASSWORDS_FILE, "r") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                if ":" in raw:
                    updated_lines.add(raw)
                elif raw in hash_to_user:
                    updated_lines.add(f"{hash_to_user[raw]}:{raw}")
                else:
                    updated_lines.add(raw)

        with open(CRACKED_PASSWORDS_FILE, "w") as f:
            for line in sorted(updated_lines):
                f.write(line + "\n")
    except Exception as e:
        return jsonify({"error": f"Failed to update cracked file: {e}"}), 500

    matches = []
    try:
        with open(CRACKED_PASSWORDS_FILE, "r") as f:
            for line in f:
                if line.strip() and "@" in line:
                    email, hashval = line.strip().split(":", 1)
                    if email.lower().endswith("@" + domain):
                        matches.append({"email": email, "hash": hashval})

        return jsonify({"results": matches})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



#PARA ADICIONAR PALAVRAS AO DICIONARIO
@app.route('/upload_weak_passwords', methods=['POST'])
def upload_weak_passwords():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    try:
        DICTIONARIO_PATH = os.path.join(HASHCAT_DIR, "wordlist", "rockyou.list")
        os.makedirs(os.path.dirname(DICTIONARIO_PATH), exist_ok=True)

        lines = file.read().decode('utf-8').splitlines()

        with open(DICTIONARIO_PATH, "a", encoding='utf-8') as dict_file:
            for line in lines:
                cleaned = line.strip()
                if cleaned:
                    dict_file.write(cleaned + "\n")

        return jsonify({"status": "success", "added": len(lines)}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, threaded=True)