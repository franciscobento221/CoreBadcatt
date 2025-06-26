from flask import Flask, request, jsonify
import os
import subprocess
import threading
import queue
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
import configparser


app = Flask(__name__)

# Configuration
HASHCAT_DIR = r"C:\Users\Public\Documents\ServidorCORE\hashcat-6.2.6" #ALTERAR PARA SITIO ONDE ESTEJA A PASTA COM O HASHCAT
config_path = os.path.join(HASHCAT_DIR, 'config.ini')
config = configparser.ConfigParser()
read_files = config.read(config_path)

if not read_files:
    print("[ERROR] Config file not found or unreadable:", config_path)
else:
    print(f"[INFO] Loaded config from {read_files[0]}")

WORDLIST_PATH = config.get('hashcat', 'wordlist_path', fallback=os.path.join(HASHCAT_DIR, "wordlist", "rockyou.list"))
RULE_FILE = config.get('hashcat', 'rule_file', fallback=os.path.join(HASHCAT_DIR, "rules", "best64.rule"))
BATCH_INTERVAL_SECONDS = config.getint('hashcat', 'batch_interval_seconds', fallback=10)
CRACKED_PASSWORDS_FILE = os.path.join(HASHCAT_DIR, "all_cracked_hashes.txt")



task_queue = queue.Queue()
processing_lock = threading.Lock()
active_tasks = {}

pending_files = []
batch_lock = threading.Lock()
#BATCH_INTERVAL_SECONDS = 180  # 5 minutes


class HashcatTask:
    def __init__(self, file_path, original_filename):
        self.task_id = str(uuid.uuid4())
        self.file_path = file_path
        self.original_filename = original_filename
        self.status = "queued"
        self.start_time = None
        self.end_time = None
        self.result = None
        self.output_file = os.path.join(HASHCAT_DIR, f"cracked_{self.task_id}.txt")
        self.current_hash = None
        self.hashes = []


        with open(file_path, 'r') as f:
            self.hashes = [line.strip() for line in f if line.strip()]
        print(f"\n[+++] {len(self.hashes)} hashes from {original_filename}")
        for i, hash in enumerate(self.hashes, 1):
            print(f"  Hash {i}: {hash}")


#UPLOAD DO EDGE
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if not uploaded_file.filename.endswith('.txt'):
        return jsonify({"error": "Only .txt files are accepted"}), 400


    original_filename = secure_filename(uploaded_file.filename)
    empresas_dir = os.path.join(HASHCAT_DIR, "Empresas")
    os.makedirs(empresas_dir, exist_ok=True)  # Ensure the folder exists

    file_path = os.path.join(empresas_dir, original_filename)
    uploaded_file.save(file_path)


    with open(file_path, 'a') as f:
        f.flush()
        os.fsync(f.fileno())


    task = HashcatTask(file_path, original_filename)

    with batch_lock:
        pending_files.append(task)
        active_tasks[task.task_id] = task

    print(f"\n[+++] File saved to Empresas and queued: {original_filename}")
    return jsonify({
        "status": "queued_for_batch",
        "task_id": task.task_id,
        "filename": original_filename
    })




@app.route('/status/<task_id>', methods=['GET'])
def get_status(task_id):
    with processing_lock:
        task = active_tasks.get(task_id)

    if not task:
        return jsonify({"error": "Task not found"}), 404

    response = {
        "task_id": task_id,
        "filename": task.original_filename,
        "status": task.status,
        "start_time": task.start_time.isoformat() if task.start_time else None,
        "end_time": task.end_time.isoformat() if task.end_time else None
    }

    if task.status == "completed":
        response.update(task.result)

    return jsonify(response)

#METODO BATCHING
@app.route('/queue', methods=['GET'])
def get_queue():
    with processing_lock:
        queue_status = {
            "pending": task_queue.qsize(),
            "active": len([t for t in active_tasks.values() if t.status == "processing"]),
            "completed": len([t for t in active_tasks.values() if t.status == "completed"])
        }
        tasks = [
            {
                "task_id": t.task_id,
                "filename": t.original_filename,
                "status": t.status
            } for t in active_tasks.values()
        ]

    return jsonify({
        "queue_status": queue_status,
        "tasks": tasks
    })

def batch_processor():
    while True:
        print("\n[***] Waiting for next batch window...")
        threading.Event().wait(BATCH_INTERVAL_SECONDS)

        with batch_lock:
            if not pending_files:
                print("[---] No files in this batch window.")
                continue

            batch_id = str(uuid.uuid4())
            batch_input_file = os.path.join(HASHCAT_DIR, f"batch_input_{batch_id}.txt")
            batch_output_file = os.path.join(HASHCAT_DIR, f"batch_output_{batch_id}.txt")
            print(f"\n[===] Starting new batch with {len(pending_files)} files")

            combined_lines = []
            for task in pending_files:
                print(f"\n[+] File: {task.original_filename}")
                try:
                    with open(task.file_path, 'r') as f:
                        lines = [line.strip() for line in f if line.strip()]
                        for i, h in enumerate(lines, 1):
                            print(f"  Hash {i}: {h}")
                        task.hashes = lines
                        combined_lines.extend(lines)
                except Exception as e:
                    print(f"  [!] Could not read {task.file_path}: {e}")

            with open(batch_input_file, 'w') as f:
                for line in combined_lines:
                    f.write(line + "\n")


            hashcat_cmd = [
                os.path.join(HASHCAT_DIR, "hashcat.exe"),
                "-m", "0",
                "-a", "0",
                "--username",
               #"--show",
                batch_input_file,
                WORDLIST_PATH,
                "-r", RULE_FILE,
                "-o", CRACKED_PASSWORDS_FILE,
                "--potfile-disable",
                "--outfile-format=1",
                "--force",
                "-O",
                "-w", "3",
            ]

            print(f"[***] Running hashcat on batch...")

            try:
                process = subprocess.Popen(
                    hashcat_cmd,
                    cwd=HASHCAT_DIR,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )

                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(f"[hashcat] {output.strip()}")

                if process.returncode != 0:
                    print(f"[!!!] Hashcat exited with code {process.returncode}")
                    for task in pending_files:
                        task.status = "failed"
                        task.result = {"status": "failed", "error": f"Hashcat exited with code {process.returncode}"}
                    pending_files.clear()
                    continue

            except Exception as e:
                print(f"[!!!] Exception running hashcat: {e}")
                for task in pending_files:
                    task.status = "failed"
                    task.result = {"status": "failed", "error": str(e)}
                pending_files.clear()
                continue


            cracked_results = {}



            for task in pending_files:
                cracked = []
                for hash in task.hashes:
                    email = hash.split(':')[0]
                    if email in cracked_results:
                        cracked.append({"hash": hash, "password": cracked_results[email]})

                task.status = "completed"
                task.end_time = datetime.now()
                task.result = {
                    "status": "completed",
                    "cracked_count": len(cracked),
                    "total_hashes": len(task.hashes),
                    "results": cracked
                }

                # try:
                #     os.remove(task.file_path)
                # except Exception as e:
                #     print(f"[Cleanup Error] {e}")
                print(f"[INFO] File kept: {task.file_path}")

            pending_files.clear()



if __name__ == '__main__':
    threading.Thread(target=batch_processor, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, threaded=True)