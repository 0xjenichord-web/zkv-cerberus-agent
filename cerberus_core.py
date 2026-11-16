from flask import Flask, request, jsonify
import subprocess
import json
import os
import tempfile
import time

app = Flask(__name__)

# =========================================================
# KONFIGURASI ZK-CERBERUS
# =========================================================
SIMULATION_MODE = False  # Mode pertarungan sesungguhnya
PORT = 3000

# =========================================================
# LOGIKA 7 PENGECEKAN (Fail-Closed)
# =========================================================
def perform_seven_checks(task):
    """
    Mengembalikan (is_valid, reason).
    Logika ini harus selaras dengan batasan sirkuit.
    """
    try:
        # 1. Cek Penerima (Recipient)
        if task.get("recipient") != task.get("condition_recipient"):
            return False, "Recipient mismatch"
        
        # 2. Cek Saldo (Balance) vs Minimum
        if int(task.get("public_balance", 0)) < int(task.get("minimum", 0)):
            return False, "Insufficient balance"
        
        # 3. Cek Double-Spend (Nullifier / History)
        if task.get("hasBeenUsed", False):
            return False, "Proof already used"
        
        # 4. Cek Waktu Kedaluwarsa (Expiry Block)
        if int(task.get("current_block", 0)) > int(task.get("expiry_block", 0)):
            return False, "Task expired"
        
        # 5. Cek Batas Maksimal Transfer
        if int(task.get("amount", 0)) > int(task.get("max_transfer", 0)):
            return False, "Amount exceeds limit"
        
        # 6. Cek Kecocokan Hash VK
        if task.get("proof_vk") != task.get("registered_vk"):
            return False, "VK mismatch"
        
        # 7. Cek Tanda Tangan (Placeholder HMAC)
        if "signature" not in task:
            return False, "Missing signature"

        return True, "All checks passed"
        
    except Exception as e:
        return False, f"Error during checks: {str(e)}"

# =========================================================
# GENERATE PROOF ASLI (13 SINYAL)
# =========================================================
def generate_proof(is_valid, task):
    if SIMULATION_MODE:
        print("[CERBERUS-SIMULASI] Membuat proof palsu...")
        time.sleep(1) 
        return {"pi_a": ["0x123", "0x456"], "pi_b": [], "pi_c": []}, ["0x1"]

    print("[CERBERUS-ASLI] Menjalankan snarkjs...")
    
    # Konversi alamat hex ke integer (BigInt) untuk sirkuit
    # Sirkuit menggunakan tipe field element (BN254)
    def to_field(val):
        if isinstance(val, str) and val.startswith("0x"):
            return int(val, 16)
        return int(val) if val is not None else 0

    # Menyusun 13 input sinyal sesuai spesifikasi sirkuit resmi
    circuit_input = {
        "decision": 1 if is_valid else 0,
        "minimum": to_field(task.get("minimum", 0)),
        "publicBalance": to_field(task.get("public_balance", 0)),
        "amount": to_field(task.get("amount", 0)),
        "maxTransfer": to_field(task.get("max_transfer", 0)),
        "expiryBlock": to_field(task.get("expiry_block", 0)),
        "currentBlock": to_field(task.get("current_block", 0)),
        "recipient": to_field(task.get("recipient", "0x0")),
        "conditionRecipient": to_field(task.get("condition_recipient", "0x0")),
        "registeredVkHash": to_field(task.get("registered_vk", "0x0")),
        "proofVkHash": to_field(task.get("proof_vk", "0x0")),
        "taskId": to_field(task.get("task_id", 0)),
        "salt": to_field(task.get("salt", 0)) # Input privat
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, 'input.json')
        proof_path = os.path.join(tmpdir, 'proof.json')
        public_path = os.path.join(tmpdir, 'public.json')

        with open(input_path, 'w') as f:
            json.dump(circuit_input, f, indent=2)

        command = [
            "snarkjs", "groth16", "fullProve",
            input_path,
            "./circuits/gatekeeper.wasm",
            "./circuits/gatekeeper_final.zkey",
            proof_path,
            public_path
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0:
            # Jika witness gagal, kemungkinan decision bertentangan dengan constraint sirkuit
            raise Exception(f"Snarkjs Gagal: {result.stderr or 'Witness calculation failed (decision mismatch?)'}")

        with open(proof_path, 'r') as f:
            proof_data = json.load(f)
        with open(public_path, 'r') as f:
            public_signals = json.load(f)
            
        return proof_data, public_signals

# =========================================================
# ENDPOINT UTAMA AGEN
# =========================================================
@app.route('/agent', methods=['POST'])
def handle_task():
    start_time = time.time()
    print("\n=== [ZK-CERBERUS] MENERIMA TUGAS BARU ===")
    
    task = request.json
    if not task:
        return jsonify({"error": "Invalid JSON", "decision": "REJECT"}), 400

    is_valid, reason = perform_seven_checks(task)
    decision = "APPROVE" if is_valid else "REJECT"
    print(f"-> Keputusan: {decision}")
    print(f"-> Alasan: {reason}")

    try:
        proof_data, public_signals = generate_proof(is_valid, task)
        
        elapsed = round(time.time() - start_time, 2)
        print(f"-> Waktu proses: {elapsed} detik")

        return jsonify({
            "decision": decision,
            "proof": proof_data,
            "publicSignals": public_signals
        })

    except Exception as e:
        print(f"-> ERROR FATAL: {str(e)}")
        # Fail-closed: kirim REJECT tanpa proof jika gagal
        return jsonify({
            "error": str(e),
            "decision": "REJECT",
            "proof": None,
            "publicSignals": None
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    return "ZK-CERBERUS is ALIVE", 200

if __name__ == '__main__':
    print(f"=== ZK-CERBERUS DIAKTIFKAN DI PORT {PORT} ===")
    print(f"Mode Simulasi: {'AKTIF' if SIMULATION_MODE else 'NONAKTIF'}")
    app.run(host='0.0.0.0', port=PORT)
