from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

@app.route('/crack', methods=['POST'])
def crack_hash():
    # 1. Receber a hash da requisição
    data = request.get_json()
    if not data or 'hash' not in data:
        return jsonify({"error": "Hash não fornecida"}), 400

    hash_to_crack = data['hash']

    # 2. Configurar paths
    hashcat_dir = r"C:\Users\Public\Documents\ServidorCORE\hashcat-6.2.6"
    wordlist_path = os.path.join(hashcat_dir, "wordlist", "rockyou.list")
    hash_file_path = os.path.join(hashcat_dir, "hashToCrack.txt")
    output_file = os.path.join(hashcat_dir, "cracked.txt")

    try:
        # 3. Escrever a hash no arquivo hashToCrack.txt
        with open(hash_file_path, 'w') as f:
            f.write(hash_to_crack)

        # 4. Comando Hashcat
        hashcat_cmd = [
            os.path.join(hashcat_dir, "hashcat.exe"),
            "-m", "0",              # MD5
            "-a", "0",              # Ataque de dicionário
            hash_file_path,
            wordlist_path,
            "-o", output_file,
            "--potfile-disable",
            "--force",
            "-O",
            "-w", "3"
           # "--outfile-format=2"     # Garante que só a senha será output
        ]

        # 5. Executar Hashcat
        result = subprocess.run(
            hashcat_cmd,
            cwd=hashcat_dir,
            capture_output=True,
            text=True,
            timeout=600
        )

        # 6. Processar resultados
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                cracked_password = f.read().strip()
                if cracked_password:
                    return jsonify({
                        "status": "success",
                        "password": cracked_password
                    })

        return jsonify({
            "status": "failed",
            "error": "Hash não encontrada na wordlist",
            "hashcat_output": result.stdout,
            "hashcat_error": result.stderr
        })

    except subprocess.TimeoutExpired:
        return jsonify({"status": "failed", "error": "Timeout excedido"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # Limpar arquivos
        for file_path in [hash_file_path, output_file]:
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except:
                    pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)