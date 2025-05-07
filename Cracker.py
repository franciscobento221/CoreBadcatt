from flask import Flask, request, jsonify
import os
import subprocess
import threading
import queue
import uuid
from datetime import datetime
#push

app = Flask(__name__)

# Configuration
HASHCAT_DIR = r"C:\Users\Public\Documents\ServidorCORE\hashcat-6.2.6"
WORDLIST_PATH = os.path.join(HASHCAT_DIR, "wordlist", "rockyou.list")
RULE_FILE = os.path.join(HASHCAT_DIR, "rules", "best64.rule")
CRACKED_PASSWORDS_FILE = os.path.join(HASHCAT_DIR, "all_cracked_hashes.txt")


# Task queue and processing system
task_queue = queue.Queue()
processing_lock = threading.Lock()
active_tasks = {}

pending_files = []
batch_lock = threading.Lock()
BATCH_INTERVAL_SECONDS = 120  # 5 minutes


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

        # Read and log all hashes when task is created
        with open(file_path, 'r') as f:
            self.hashes = [line.strip() for line in f if line.strip()]
        print(f"\n[+++] {len(self.hashes)} hashes from {original_filename}")
        for i, hash in enumerate(self.hashes, 1):
            print(f"  Hash {i}: {hash}")


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if not uploaded_file.filename.endswith('.txt'):
        return jsonify({"error": "Only .txt files are accepted"}), 400

    # Save the uploaded file
    file_path = os.path.join(HASHCAT_DIR, f"hashes_{str(uuid.uuid4())}.txt")
    uploaded_file.save(file_path)

    # Create task metadata (not yet processed)
    task = HashcatTask(file_path, uploaded_file.filename)

    with batch_lock:
        pending_files.append(task)
        active_tasks[task.task_id] = task

    print(f"\n[+++] File queued for batch: {uploaded_file.filename}")
    return jsonify({
        "status": "queued_for_batch",
        "task_id": task.task_id,
        "filename": uploaded_file.filename
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

            # Run hashcat
            hashcat_cmd = [
                os.path.join(HASHCAT_DIR, "hashcat.exe"),
                "-m", "0",
                "-a", "0",
                "--username",
                batch_input_file,
                WORDLIST_PATH,
                "-r", RULE_FILE,
                "-o", CRACKED_PASSWORDS_FILE,
                "--potfile-disable",
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

            # Parse cracked results
            cracked_results = {}


            # Update task results
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

                try:
                    os.remove(task.file_path)
                except Exception as e:
                    print(f"[Cleanup Error] {e}")

            pending_files.clear()
            print(f"[===] Batch complete: {len(cracked_results)} cracked")


if __name__ == '__main__':
    threading.Thread(target=batch_processor, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, threaded=True)
