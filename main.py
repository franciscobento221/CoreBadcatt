from flask import Flask, request, jsonify
import os
import tempfile
import subprocess

app = Flask(__name__)

# Endpoint para receber hashes
@app.route('/crack', methods=['POST'])


def crack_hash():
    hashcat_dir = r"C:\Users\Public\Documents\ServidorCORE\hashcat-6.2.6"  # Ajuste este caminho!
    hash_to_crack = "5f4dcc3b5aa765d61d8327deb882cf99"  # Exemplo

    if not os.path.exists(os.path.join(hashcat_dir, "OpenCL")):
        return jsonify({"error": "Pasta OpenCL não encontrada!"}), 500

    try:
        hashcat_cmd = [
            os.path.join(hashcat_dir, "hashcat.exe"),
            "-m", "0",
            "-a", "0",
            "--potfile-disable",
            "--force",  # Ignora erros de GPU/OpenCL
            "-D", "1",  # Usa CPU (opcional)
            hash_to_crack,
            os.path.join(hashcat_dir, "wordlist", "rockyou.list")
        ]

        result = subprocess.run(
            hashcat_cmd,
            cwd=hashcat_dir,  # ⚠️ Diretório crítico!
            capture_output=True,
            text=True,
            timeout=300
        )

        if "cracked" in result.stdout:
            return jsonify({"status": "success", "password": result.stdout.split(":")[-1]})
        else:
            return jsonify({"status": "failed", "error": result.stderr})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Inicia o servidor
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


