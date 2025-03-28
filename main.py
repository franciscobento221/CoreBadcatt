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
    print(f"\n[+] Nova requisição recebida - Hash: {hash_to_crack}")

    # 2. Configurar paths
    hashcat_dir = r"C:\Users\Public\Documents\ServidorCORE\hashcat-6.2.6"
    wordlist_path = os.path.join(hashcat_dir, "wordlist", "rockyou.list")
    hash_file_path = os.path.join(hashcat_dir, "hashToCrack.txt")
    output_file = os.path.join(hashcat_dir, "cracked.txt")
    rule_file = os.path.join(hashcat_dir, "rules", "OneRuleToRuleThemAll.rule")

    try:
        # 3. Escrever a hash no arquivo hashToCrack.txt
        print(f"[+] Gravando hash no arquivo {hash_file_path}")
        with open(hash_file_path, 'w') as f:
            f.write(hash_to_crack)

        # 4. Comando Hashcat
        hashcat_cmd = [
            os.path.join(hashcat_dir, "hashcat.exe"),
            "-m", "0",  # MD5
            "-a", "0",  # Ataque de dicionário
            hash_file_path,
            wordlist_path,
            "-r", rule_file,
            "-o", output_file,
            "--potfile-disable",
            "--force",
            "-O",
            "-w", "3",
            "--status",  # Ativa updates de status
            "--status-timer=10",  # Atualiza status a cada 10 segundos
            "--machine-readable"  # Formato legível para parsing
        ]

        print("[+] Comando Hashcat preparado:")
        print(" ".join(hashcat_cmd))

        # 5. Executar Hashcat
        print("[+] Iniciando processo Hashcat...")
        result = subprocess.run(
            hashcat_cmd,
            cwd=hashcat_dir,
            capture_output=True,
            text=True,
            timeout=600
        )

        # Debug: Exibir saídas do Hashcat
        print("\n[DEBUG] Saída do Hashcat (stdout):")
        print(result.stdout)
        print("\n[DEBUG] Erros do Hashcat (stderr):")
        print(result.stderr)

        # 6. Processar resultados
        print(f"\n[+] Verificando arquivo de resultados: {output_file}")
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                content = f.read().strip()
                print(f"[+] Conteúdo do arquivo cracked.txt: '{content}'")

                # Processar diferentes formatos de saída
                if ':' in content:  # Formato hash:senha
                    cracked_password = content.split(':')[-1].strip()
                else:  # Formato apenas senha
                    cracked_password = content

                if cracked_password:
                    print(f"[+] Senha encontrada: {cracked_password}")
                    return jsonify({
                        "status": "success",
                        "password": cracked_password
                    })

        print("[!] Hash não foi decifrada")
        return jsonify({
            "status": "failed",
            "error": "Hash não encontrada na wordlist",
            "hashcat_output": result.stdout,
            "hashcat_error": result.stderr
        })

    except subprocess.TimeoutExpired:
        print("[!] Timeout excedido (10 minutos)")
        return jsonify({"status": "failed", "error": "Timeout excedido"}), 500
    except Exception as e:
        print(f"[!] Erro inesperado: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        # Limpar arquivos
        print("\n[+] Limpando arquivos temporários...")
        for file_path in [hash_file_path, output_file]:
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                    print(f"    - Removido: {file_path}")
                except Exception as e:
                    print(f"    - Erro ao remover {file_path}: {str(e)}")
        print("[+] Processo finalizado\n")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)