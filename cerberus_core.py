from flask import Flask, request, jsonify, make_response
import subprocess, json, os, tempfile, time, hmac, hashlib

app = Flask(__name__)
SIMULATION_MODE = False
PORT = int(os.environ.get("PORT", 3000))
HMAC_SECRET = os.environ.get("AGENT_GAMES_HMAC_SECRET", "")

def verify_hmac(raw_body, signature):
    if not HMAC_SECRET: return True
    expected_raw = hmac.new(HMAC_SECRET.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected_raw, signature or ""):
        return True
    try:
        decoded_secret = bytes.fromhex(HMAC_SECRET)
        expected_hex = hmac.new(decoded_secret, raw_body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_hex, signature or "")
    except ValueError:
        return False

def sign_body(raw_body: bytes) -> str:
    if not HMAC_SECRET: return ""
    return hmac.new(HMAC_SECRET.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()

def perform_seven_checks(task):
    try:
        if task.get("proof_vk") != task.get("registered_vk"):
            return False, "VK_SUBSTITUTION"
        if task.get("hasBeenUsed", False) or task.get("proof_reused", False):
            return False, "PROOF_REUSED"
        if int(task.get("public_balance", 0)) < int(task.get("minimum", 0)):
            return False, "THRESHOLD_MISMATCH"
        if int(task.get("current_block", 0)) >= int(task.get("expiry_block", 0)):
            return False, "EXPIRED_CONDITION"
        if task.get("recipient") != task.get("condition_recipient"):
            return False, "RECIPIENT_MISMATCH"
        
        amount = int(task.get("amount", 0))
        max_transfer = int(task.get("max_transfer", 0))
        if amount <= 0 or amount > max_transfer:
            return False, "AMOUNT_OVERFLOW"
        
        return True, "VALID_CONDITION"
    except Exception:
        return False, "INTERNAL_ERROR"

def generate_proof(is_valid, task):
    if SIMULATION_MODE:
        time.sleep(0.5) 
        return {"pi_a": ["0x123"], "pi_b": [], "pi_c": []}, ["0x1"]

    # PERBAIKAN: Fungsi to_field sekarang bisa mengubah teks UUID menjadi angka
    def to_field(val):
        if isinstance(val, int): return val
        if isinstance(val, str):
            if val.startswith("0x"): return int(val, 16)
            if val.isdigit(): return int(val)
            # Jika berupa teks (seperti task_id), ubah menjadi hash angka
            return int(hashlib.sha256(val.encode()).hexdigest(), 16) % (2**254)
        return 0

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
        "salt": to_field(task.get("salt", 0))
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, 'input.json')
        proof_path = os.path.join(tmpdir, 'proof.json')
        public_path = os.path.join(tmpdir, 'public.json')

        with open(input_path, 'w') as f:
            json.dump(circuit_input, f)

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
            raise Exception("Snarkjs Gagal")

        with open(proof_path, 'r') as f:
            proof_data = json.load(f)
        with open(public_path, 'r') as f:
            public_signals = json.load(f)
            
        return proof_data, public_signals

@app.route('/agent', methods=['POST'])
def handle_agent():
    raw_body = request.get_data()
    sig = request.headers.get("x-agent-games-signature")
    
    if not verify_hmac(raw_body, sig):
        return jsonify({"error": "Unauthorized"}), 401

    task = request.get_json(silent=True) or {}
    
    if task.get("type") == "agent-games.preflight.v1":
        resp_body = json.dumps({"ok": True, "protocolVersion": "v1"}).encode('utf-8')
        resp_sig = sign_body(resp_body)
        resp = make_response(resp_body, 200)
        resp.headers['Content-Type'] = 'application/json'
        if resp_sig: resp.headers['x-agent-games-signature'] = resp_sig
        return resp

    is_valid, reason = perform_seven_checks(task)
    decision = "APPROVE" if is_valid else "REJECT"
    
    try:
        proof_data, public_signals = generate_proof(is_valid, task)
        payload = {
            "decision": decision,
            "reason_code": reason,
            "proof": proof_data,
            "public_signals": public_signals
        }
    except Exception as e:
        payload = {
            "decision": decision,
            "reason_code": reason,
            "proof": None,
            "public_signals": None
        }

    resp_body = json.dumps(payload).encode('utf-8')
    resp_sig = sign_body(resp_body)
    resp = make_response(resp_body, 200)
    resp.headers['Content-Type'] = 'application/json'
    if resp_sig: resp.headers['x-agent-games-signature'] = resp_sig
    return resp

@app.route('/health', methods=['GET'])
def health(): 
    return "ZK-CERBERUS is ALIVE", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
