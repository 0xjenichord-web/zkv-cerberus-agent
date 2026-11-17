from flask import Flask, request, jsonify, make_response
import subprocess, json, os, sys, tempfile, hmac, hashlib, threading

app = Flask(__name__)

PORT = int(os.environ.get("PORT", 3000))
HMAC_SECRET = os.environ.get("AGENT_GAMES_HMAC_SECRET", "")
# Daftar proof_tx yang sudah diterima + cache jawaban per task_id.
# Disimpan di disk supaya restart tidak membuat agent lupa.
STATE_PATH = os.environ.get("STATE_PATH", "/app/data/state.json")
_lock = threading.Lock()


def log(*args):
    print(*args, flush=True)


# ---------------------------------------------------------------- HMAC
def verify_hmac(raw_body, signature):
    if not HMAC_SECRET:
        return False  # fail closed: tanpa secret, tolak semua
    sig = (signature or "").strip().lower()
    if sig.startswith("sha256="):
        sig = sig[7:]
    candidates = [hmac.new(HMAC_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()]
    try:
        candidates.append(hmac.new(bytes.fromhex(HMAC_SECRET), raw_body, hashlib.sha256).hexdigest())
    except ValueError:
        pass
    return any(hmac.compare_digest(c.encode(), sig.encode()) for c in candidates)


def sign_body(raw_body: bytes) -> str:
    if not HMAC_SECRET:
        return ""
    return hmac.new(HMAC_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()


def reply(payload):
    body = json.dumps(payload).encode("utf-8")
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "application/json"
    sig = sign_body(body)
    if sig:
        resp.headers["x-agent-games-signature"] = sig
    return resp


# ---------------------------------------------------------------- state
def load_state():
    try:
        with open(STATE_PATH) as f:
            s = json.load(f)
        s.setdefault("accepted", {})
        s.setdefault("tasks", {})
        return s
    except Exception:
        return {"accepted": {}, "tasks": {}}


def save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_PATH)
    except Exception as e:
        log(f"!!! Gagal menyimpan state: {e}")


# ---------------------------------------------------------------- checks
def to_field(val):
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        v = val.strip()
        if v.lower().startswith("0x"):
            try:
                return int(v, 16)
            except ValueError:
                pass
        if v.isdigit():
            return int(v)
        return int(hashlib.sha256(v.encode()).hexdigest(), 16) % (2 ** 254)
    return 0


def perform_seven_checks(data, reused=False):
    """Urutan: semua cek yang ada di dalam circuit dulu, PROOF_REUSED terakhir.
    Dengan begitu penolakan karena alasan lain tetap bisa membawa proof."""
    try:
        if to_field(data.get("proof_vk")) != to_field(data.get("registered_vk")):
            return False, "VK_SUBSTITUTION"
        if to_field(data.get("public_balance", 0)) < to_field(data.get("minimum", 0)):
            return False, "THRESHOLD_MISMATCH"
        if to_field(data.get("current_block", 0)) >= to_field(data.get("expiry_block", 0)):
            return False, "EXPIRED_CONDITION"
        if to_field(data.get("recipient")) != to_field(data.get("condition_recipient")):
            return False, "RECIPIENT_MISMATCH"
        amount = to_field(data.get("amount", 0))
        if amount <= 0 or amount > to_field(data.get("max_transfer", 0)):
            return False, "AMOUNT_OVERFLOW"
        if reused or data.get("hasBeenUsed", False) or data.get("proof_reused", False):
            return False, "PROOF_REUSED"
        return True, "VALID_CONDITION"
    except Exception as e:
        log(f"Check Error: {e}")
        return False, "INTERNAL_ERROR"


# ---------------------------------------------------------------- proof
def generate_proof(is_valid, data, task_id):
    circuit_input = {
        "decision": 1 if is_valid else 0,
        "minimum": to_field(data.get("minimum", 0)),
        "publicBalance": to_field(data.get("public_balance", 0)),
        "amount": to_field(data.get("amount", 0)),
        "maxTransfer": to_field(data.get("max_transfer", 0)),
        "expiryBlock": to_field(data.get("expiry_block", 0)),
        "currentBlock": to_field(data.get("current_block", 0)),
        "recipient": to_field(data.get("recipient", "0x0")),
        "conditionRecipient": to_field(data.get("condition_recipient", "0x0")),
        "registeredVkHash": to_field(data.get("registered_vk", "0x0")),
        "proofVkHash": to_field(data.get("proof_vk", "0x0")),
        "taskId": to_field(task_id),
        "salt": to_field(data.get("proof_tx", 0)),
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, "input.json")
        proof_path = os.path.join(tmpdir, "proof.json")
        public_path = os.path.join(tmpdir, "public.json")
        with open(input_path, "w") as f:
            json.dump(circuit_input, f)

        command = [
            "snarkjs", "groth16", "fullProve",
            input_path,
            "./circuits/gatekeeper.wasm",
            "./circuits/gatekeeper_final.zkey",
            proof_path,
            public_path,
        ]
        log("--> Menjalankan snarkjs (maksimal 10 detik)...")
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            raise Exception("snarkjs timeout > 10 detik")
        if result.returncode != 0:
            raise Exception(f"snarkjs gagal: {result.stderr.strip()[-400:]}")

        with open(proof_path) as f:
            proof_data = json.load(f)
        with open(public_path) as f:
            public_signals = json.load(f)
    log("--> Proof berhasil dibuat!")
    return proof_data, public_signals


# ---------------------------------------------------------------- routes
@app.route("/agent", methods=["POST"])
def handle_agent():
    log("\n=== [ZK-CERBERUS] MENERIMA HTTP REQUEST ===")
    raw_body = request.get_data()
    if not verify_hmac(raw_body, request.headers.get("x-agent-games-signature")):
        log("!!! ERROR: HMAC Signature tidak cocok (401)")
        return jsonify({"error": "Unauthorized"}), 401

    task = request.get_json(silent=True) or {}

    if task.get("type") == "agent-games.preflight.v1":
        log("--> Merespons Preflight Check (200 OK)")
        return reply({"ok": True, "protocolVersion": "v1"})

    task_data = task.get("input", {}) or {}
    task_id = str(task.get("task_id", "unknown"))
    mode = str(task.get("mode", "competition"))
    proof_tx = task_data.get("proof_tx")
    reuse_key = f"{mode}:{str(proof_tx).lower()}" if proof_tx else None
    log(f"--> Menerima Tugas: {task_id} (mode={mode})")

    with _lock:
        state = load_state()

        # Tugas yang sama dikirim ulang oleh platform -> jawaban identik.
        if task_id != "unknown" and task_id in state["tasks"]:
            log("--> Tugas ulang, mengirim jawaban yang sama")
            return reply(state["tasks"][task_id])

        reused = bool(reuse_key and reuse_key in state["accepted"])
        is_valid, reason = perform_seven_checks(task_data, reused)
        decision = "APPROVE" if is_valid else "REJECT"
        log(f"--> Keputusan: {decision} | Alasan: {reason}")

        proof_data, public_signals = None, None
        if reason not in ("PROOF_REUSED", "INTERNAL_ERROR"):  # di luar circuit
            try:
                proof_data, public_signals = generate_proof(is_valid, task_data, task_id)
            except Exception as e:
                log(f"!!! SNARKJS ERROR: {e}")
                log("--> Mengirim keputusan tanpa proof")

        payload = {
            "decision": decision,
            "reason_code": reason,
            "proof_tx": proof_tx,
            "proof": proof_data,
            "public_signals": public_signals,
        }

        if is_valid and reuse_key:
            state["accepted"][reuse_key] = task_id
        if task_id != "unknown":
            state["tasks"][task_id] = payload
        save_state(state)

    log("=== RESPONS DIKIRIM KE ZKVERIFY ===\n")
    return reply(payload)


@app.route("/health", methods=["GET"])
def health():
    return "ZK-CERBERUS is ALIVE", 200


# ---------------------------------------------------------------- selftest
def selftest():
    """python cerberus_core.py selftest  -> uji proof untuk tiap jenis keputusan."""
    base = {
        "registered_vk": "0x7d3a", "proof_vk": "0x7d3a",
        "minimum": "1000", "public_balance": "1460",
        "expiry_block": 19842201, "current_block": 19832000,
        "recipient": "0xde42", "condition_recipient": "0xde42",
        "amount": "500", "max_transfer": "1000", "proof_tx": "0xa4c1",
    }
    cases = [
        ("VALID_CONDITION", {}),
        ("VK_SUBSTITUTION", {"proof_vk": "0x9999"}),
        ("THRESHOLD_MISMATCH", {"public_balance": "900"}),
        ("EXPIRED_CONDITION", {"current_block": 19842201}),
        ("RECIPIENT_MISMATCH", {"condition_recipient": "0xbeef"}),
        ("AMOUNT_OVERFLOW", {"amount": "1500"}),
    ]
    for expected, change in cases:
        d = dict(base, **change)
        ok, reason = perform_seven_checks(d)
        try:
            _, signals = generate_proof(ok, d, "selftest")
            res = f"proof OK (decision signal={signals[-2] if len(signals) > 1 else '?'})"
        except Exception as e:
            res = f"proof GAGAL: {str(e)[:200]}"
        status = "cocok" if reason == expected else f"BEDA (dapat {reason})"
        print(f"{expected:20} alasan {status:8} | {res}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        selftest()
    else:
        app.run(host="0.0.0.0", port=PORT)
