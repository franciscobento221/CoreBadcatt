from flask import Flask, request, jsonify
import os
import subprocess
import threading
import queue
import uuid
from datetime import datetime

app = Flask(__name__)

# Configuration
HASHCAT_DIR = r"C:\Users\Public\Documents\ServidorCORE\hashcat-6.2.6"
WORDLIST_PATH = os.path.join(HASHCAT_DIR, "wordlist", "weakpass_4.txt")
RULE_FILE = os.path.join(HASHCAT_DIR, "rules", "OneRuleToRuleThemAll.rule")
CRACKED_PASSWORDS_FILE = os.path.join(HASHCAT_DIR, "all_cracked_hashes.txt")


# Task queue and processing system
task_queue = queue.Queue()
processing_lock = threading.Lock()
active_tasks = {}


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


def process_tasks():
    while True:
        task = task_queue.get()
        with processing_lock:
            active_tasks[task.task_id] = task

        try:
            task.status = "processing"
            task.start_time = datetime.now()
            print(f"\n[===] Starting processing - {task.original_filename}")

            # Create a temporary file for each hash to track current progress
            temp_hash_file = os.path.join(HASHCAT_DIR, f"current_hash_{task.task_id}.txt")

            # Process each hash one by one
            for i, current_hash in enumerate(task.hashes, 1):
                task.current_hash = current_hash
                print(f"\n[>>>] Processing hash {i}/{len(task.hashes)}: {current_hash}")

                # Write current hash to temp file
                with open(temp_hash_file, 'w') as f:
                    f.write(current_hash)

                # Run hashcat for this single hash
                hashcat_cmd = [
                    os.path.join(HASHCAT_DIR, "hashcat.exe"),
                    "-m", "0",
                    "-a", "0",
                    "--username",  # Important for username handling
                    temp_hash_file,  # Contains username:hash
                    WORDLIST_PATH,
                    "-r", RULE_FILE,
                    "-o", task.output_file,  # Will contain username:hash:password
                    "--outfile-format=3",  # username:hash:password format
                    "--potfile-disable",
                    "--force",
                    "-O",
                    "-w", "3",
                    "--status",
                    "--status-timer=5"
                ]

                # Run hashcat with stdout/stderr capture
                process = subprocess.Popen(
                    hashcat_cmd,
                    cwd=HASHCAT_DIR,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # Monitor hashcat output in real-time
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(f"  Hashcat: {output.strip()}")
                        if "Status...........: Cracked" in output:
                            print(f"  [!!!] CRACKED: {current_hash}")

                # Check if hash was cracked
                if os.path.exists(task.output_file) and os.path.getsize(task.output_file) > 0:
                    with open(task.output_file, 'r') as f:
                        # Read all lines and get the last non-empty line
                        lines = [line.strip() for line in f if line.strip()]
                        if lines:  # Only proceed if there are any lines
                            result = lines[-1]  # Get the last line
                            print(f"  Cracked password: {result}")
                            with open(CRACKED_PASSWORDS_FILE, 'a') as crackedFile:
                                crackedFile.write(result + '\n')

            # Final results processing
            final_results = []
            if os.path.exists(task.output_file) and os.path.getsize(task.output_file) > 0:
                with open(task.output_file, 'r') as f:
                    cracked_passwords = [line.strip() for line in f if line.strip()]

                for hash, password in zip(task.hashes, cracked_passwords):
                    if password:  # Only include successfully cracked hashes
                        final_results.append({
                            "hash": hash,
                            "password": password
                        })

            task.result = {
                "status": "completed",
                "cracked_count": len(final_results),
                "total_hashes": len(task.hashes),
                "results": final_results
            }

        except Exception as e:
            print(f"[!!!] Error processing task {task.task_id}: {str(e)}")
            task.result = {
                "status": "failed",
                "error": str(e)
            }
        finally:
            task.status = "completed"
            task.end_time = datetime.now()
            # Cleanup
            for file_path in [task.file_path, task.output_file, temp_hash_file]:
                if file_path and os.path.exists(file_path):
                    try:
                        os.unlink(file_path)
                    except Exception as e:
                        print(f"  Cleanup error for {file_path}: {str(e)}")
            task_queue.task_done()
            print(
                f"\n[===] Completed Task {task.task_id} - Cracked {len(final_results) if 'final_results' in locals() else 0}/{len(task.hashes)} hashes")


# Start worker thread
worker_thread = threading.Thread(target=process_tasks, daemon=True)
worker_thread.start()


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if not uploaded_file.filename.endswith('.txt'):
        return jsonify({"error": "Only .txt files are accepted"}), 400

    # Save uploaded file
    file_path = os.path.join(HASHCAT_DIR, f"hashes_{str(uuid.uuid4())}.txt")
    uploaded_file.save(file_path)
    print(f"\n[+++] Received file {uploaded_file.filename} saved as {file_path}")

    # Create and queue task
    task = HashcatTask(file_path, uploaded_file.filename)
    task_queue.put(task)
    active_tasks[task.task_id] = task

    return jsonify({
        "status": "queued",
        "task_id": task.task_id,
        "filename": uploaded_file.filename,
        "total_hashes": len(task.hashes)
    })

#@app.route('/cracked', methods=['GET'])
#def get_cracked_hashes():
#   """Endpoint to view all cracked hashes"""
#    try:
#        with open(CRACKED_FILE, 'r') as f:
#            lines = [line.strip() for line in f if line.strip()]
#            results = []
#            for line in lines:
#                if ':' in line:
#                    hash, password = line.split(':', 1)
#                    results.append({"hash": hash, "password": password})

#        return jsonify({
 #           "status": "success",
  #          "count": len(results),
   #         "results": results
    #    })
    #except Exception as e:
     #   return jsonify({"error": str(e)}), 500

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


if __name__ == '__main__':
    #print(f"[***] Starting Hashcat Server - All cracked hashes will be saved to {CRACKED_FILE}")
    app.run(host='0.0.0.0', port=5000, threaded=True)