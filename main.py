from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

# Endpoint para receber hashes
@app.route('/crack', methods=['POST'])
def crack_hash():
    # Recebe o hash do corpo da requisição
    data = request.json
    hash_to_crack = data.get('hash')

    if not hash_to_crack:
        return jsonify({"error": "Hash not provided"}), 400

    # Salva o hash em um arquivo temporário
    with open('hash.txt', 'w') as f:
        f.write(hash_to_crack)

    # Executa o Hashcat (exemplo com MD5 e rockyou.txt)
    try:
        result = subprocess.run(
            ['C:\\Users\\Utilizador\\Downloads\\hashcat-6.2.6\\hashcat.exe', '-m', '0', '-a', '0', 'hash.txt', 'rockyou.txt', '--show'],
            capture_output=True, text=True
        )

        # Verifica se o hash foi decifrado
        if result.returncode == 0 and result.stdout:
            password = result.stdout.split(':')[-1].strip()
            return jsonify({"hash": hash_to_crack, "password": password, "status": "cracked"})
        else:
            return jsonify({"hash": hash_to_crack, "password": None, "status": "not cracked"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Inicia o servidor
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


