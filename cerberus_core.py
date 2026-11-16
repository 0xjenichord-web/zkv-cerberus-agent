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
        
