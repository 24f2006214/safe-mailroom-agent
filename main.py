import base64
import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse


PROFILE = "ga5-mailroom-action-gate/v2"
DB_PATH = os.getenv("DATABASE_PATH", "mailroom.db")
LOCK = threading.RLock()
app = FastAPI(title="Safe AI Mailroom", version="2.0.0")

ALLOWED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}


def compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(value: Any) -> str:
    return hashlib.sha256(compact(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            request_hash TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            verifier_json TEXT NOT NULL,
            proposals_json TEXT NOT NULL,
            dossier_ids_json TEXT NOT NULL,
            final_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS dossier_cache (
            fingerprint TEXT PRIMARY KEY,
            proposal_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    connection.commit()
    return connection


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, media_type="application/json")


def as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(as_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key}: {as_text(item)}" for key, item in value.items())
    return str(value)


def dossier_lines(dossier: dict[str, Any]) -> list[dict[str, str]]:
    result = []
    for source in dossier.get("sources", []):
        if not isinstance(source, dict):
            continue
        for line in source.get("lines", []):
            if isinstance(line, dict) and line.get("lineId") is not None and line.get("text") is not None:
                result.append({"lineId": str(line["lineId"]), "text": str(line["text"])})
    return result


def first_match(text: str, patterns: list[str], default: str = "") -> str:
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1).strip()
    return default


def proposal_digest(proposal: dict[str, Any]) -> str:
    digestable = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal["target"],
        "payload": proposal["payload"],
        "evidence": sorted(proposal["evidence"]),
    }
    return sha256(digestable)


def choose_proposal(dossier: dict[str, Any], stable_call_id: str | None = None) -> dict[str, Any]:
    dossier_id = str(dossier.get("dossierId", ""))
    mailbox = str(dossier.get("mailbox", ""))
    objective = str(dossier.get("objective", ""))
    lines = dossier_lines(dossier)
    text = " ".join(line["text"] for line in lines)
    lower = (objective + " " + text).lower()

    # Choose the smallest useful evidence set: the lines containing the
    # strongest authority/safety signal plus one line containing the argument.
    scored = []
    for line in lines:
        line_lower = line["text"].lower()
        score = 0
        if any(word in line_lower for word in ("approved", "authorized", "authority", "permission", "consent")):
            score += 4
        if any(word in line_lower for word in ("recipient", "to:", "email", "template", "status", "case", "reference")):
            score += 2
        if any(word in line_lower for word in ("ignore previous", "system prompt", "secret", "password", "tool call", "send immediately")):
            score += 5
        scored.append((score, line["lineId"]))
    scored.sort(key=lambda pair: (-pair[0], pair[1]))
    evidence = []
    for _, line_id in scored:
        if line_id not in evidence:
            evidence.append(line_id)
        if len(evidence) == 3:
            break
    if not evidence and lines:
        evidence = [lines[0]["lineId"]]

    recipient = first_match(text, [r"recipient\s*[:=]\s*([^,;\n]+)", r"to\s*[:=]\s*([^,;\n]+)", r"([\w.+-]+@[\w.-]+)"])
    reference = first_match(text, [r"reference(?:Id| ID|)\s*[:=]\s*([A-Za-z0-9_.:-]+)", r"order\s*(?:#|number)\s*[:=]?\s*([A-Za-z0-9_.:-]+)", r"case\s*(?:#|ID|id)\s*[:=]?\s*([A-Za-z0-9_.:-]+)"]) or dossier_id
    case_id = first_match(text, [r"case\s*(?:#|ID|id)\s*[:=]\s*([A-Za-z0-9_.:-]+)"]) or dossier_id
    team = first_match(text, [r"(?:team|queue)\s*[:=]\s*([^,;\n]+)"]) or "mailroom"

    injection = re.search(r"ignore (?:all )?(?:previous|prior)|system prompt|reveal|secret|password|tool call|send immediately|override", lower)
    duplicate = re.search(r"duplicate|already completed|already sent|previously handled", lower)
    explicit_send_approval = re.search(r"approved|authorized|consent", lower) and recipient and re.search(r"send|notice|email", lower)
    internal_update = re.search(r"delivery window|update (?:the )?internal|internal record", lower)
    draft_request = re.search(r"draft|prepare but do not send", lower)
    ambiguous = re.search(r"unclear|unknown|cannot verify|mismatch|different recipient|not sure|unconfirmed", lower)

    if injection:
        action = "quarantine_item"
        target = {"kind": "security_queue", "id": "mailroom"}
        payload = {"artifactId": dossier_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"}
    elif duplicate:
        action = "no_action"
        target = None
        payload = {"reasonCode": "DUPLICATE" if "duplicate" in lower else "ALREADY_COMPLETED", "referenceId": reference}
    elif explicit_send_approval and not ambiguous:
        action = "send_approved_notice"
        target = {"kind": "email", "id": recipient}
        payload = {"referenceId": reference, "status": "approved", "template": "approved_delivery_notice"}
    elif internal_update and not ambiguous:
        value = first_match(text, [r"delivery window\s*[:=]\s*([^,;\n]+)"]) or "confirmed"
        event_id = first_match(text, [r"(?:event|sourceEventId)\s*[:=]\s*([A-Za-z0-9_.:-]+)"]) or reference
        action = "update_internal_record"
        target = {"kind": "case_record", "id": case_id}
        payload = {"field": "delivery_window", "sourceEventId": event_id, "value": value}
    elif draft_request and recipient:
        action = "create_draft"
        target = {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}
        payload = {"recipient": recipient, "referenceId": reference, "status": "draft", "template": "order_status"}
    elif ambiguous or not text:
        action = "request_confirmation"
        target = {"kind": "approval_queue", "id": team}
        payload = {"claimedSender": first_match(text, [r"sender\s*[:=]\s*([^,;\n]+)"]) or "unknown", "questionCode": "VERIFY_REQUEST", "referenceId": reference}
    else:
        action = "no_action"
        target = None
        payload = {"reasonCode": "INFORMATIONAL", "referenceId": reference}

    if stable_call_id is None:
        stable_call_id = "call_" + hashlib.sha256((dossier_id + "|" + sha256(dossier)).encode()).hexdigest()[:24]
    proposal = {"dossierId": dossier_id, "callId": stable_call_id, "action": action, "target": target, "payload": payload, "evidence": evidence}
    return proposal


def validate_request(body: Any) -> tuple[str, str]:
    if not isinstance(body, dict) or body.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail="invalid profile")
    operation = body.get("operation")
    evaluation_id = body.get("evaluationId")
    if operation not in {"propose", "commit"} or not isinstance(evaluation_id, str) or not evaluation_id:
        raise HTTPException(status_code=400, detail="invalid operation")
    return operation, evaluation_id


def validate_dossiers(dossiers: Any) -> None:
    if not isinstance(dossiers, list) or not dossiers:
        raise HTTPException(status_code=400, detail="dossiers required")
    ids = []
    for dossier in dossiers:
        if not isinstance(dossier, dict) or not isinstance(dossier.get("dossierId"), str):
            raise HTTPException(status_code=400, detail="invalid dossier")
        if dossier["dossierId"] in ids:
            raise HTTPException(status_code=400, detail="duplicate dossier")
        ids.append(dossier["dossierId"])
        if not isinstance(dossier.get("sources"), list):
            raise HTTPException(status_code=400, detail="invalid sources")


def public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
        raise ValueError("invalid JWK")
    raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    return Ed25519PublicKey.from_public_bytes(raw)


def signed_bytes(body: dict[str, Any], receipt: dict[str, Any]) -> bytes:
    inner = {key: receipt[key] for key in ("dossierId", "callId", "action", "accepted", "proposalDigest", "receiptId")}
    return compact({"profile": PROFILE, "evaluationId": body["evaluationId"], "inputDigest": body["inputDigest"], "receipt": inner}).encode("utf-8")


@app.post("/mailroom")
@app.post("/")
async def mailroom(request: Request):
    try:
        body = await request.json()
        operation, evaluation_id = validate_request(body)
        request_hash = sha256(body)
        with LOCK:
            connection = db()
            existing = connection.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (evaluation_id,)).fetchone()
            if operation == "propose":
                if existing:
                    if existing["request_hash"] != request_hash:
                        return error(409, "evaluation content conflict")
                    return JSONResponse(json.loads(existing["proposals_json"]), media_type="application/json")
                validate_dossiers(body.get("dossiers"))
                allowed = body.get("allowedActions")
                if not isinstance(allowed, list) or set(allowed) != ALLOWED_ACTIONS:
                    raise HTTPException(status_code=400, detail="invalid allowedActions")
                verifier = body.get("receiptVerifier")
                if not isinstance(verifier, dict) or verifier.get("algorithm") != "Ed25519":
                    raise HTTPException(status_code=400, detail="invalid receipt verifier")
                dossiers = body["dossiers"]
                input_digest = sha256(dossiers)
                proposals = []
                for dossier in dossiers:
                    fingerprint = sha256(dossier)
                    cached = connection.execute("SELECT proposal_json FROM dossier_cache WHERE fingerprint=?", (fingerprint,)).fetchone()
                    if cached:
                        proposal = json.loads(cached["proposal_json"])
                    else:
                        proposal = choose_proposal(dossier)
                        connection.execute("INSERT OR REPLACE INTO dossier_cache VALUES (?, ?, ?)", (fingerprint, json.dumps(proposal), utc_now()))
                    proposals.append(proposal)
                response = {"profile": PROFILE, "evaluationId": evaluation_id, "status": "awaiting_receipts", "inputDigest": input_digest, "proposals": proposals}
                timestamp = utc_now()
                connection.execute("INSERT INTO evaluations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (evaluation_id, request_hash, input_digest, json.dumps(verifier), json.dumps(response), json.dumps([p["dossierId"] for p in proposals]), None, timestamp, timestamp))
                connection.commit()
                return JSONResponse(response, media_type="application/json")

            if not existing:
                return error(409, "unknown evaluation")
            if existing["final_json"]:
                if existing["request_hash"] == request_hash:
                    return JSONResponse(json.loads(existing["final_json"]), media_type="application/json")
                return error(409, "evaluation content conflict")
            if body.get("inputDigest") != existing["input_digest"]:
                return error(409, "input digest mismatch")
            receipts = body.get("receipts")
            if not isinstance(receipts, list):
                raise HTTPException(status_code=400, detail="receipts required")
            proposals_response = json.loads(existing["proposals_json"])
            proposal_by_call = {p["callId"]: p for p in proposals_response["proposals"]}
            if len(receipts) != len(proposal_by_call) or len({r.get("callId") for r in receipts}) != len(receipts):
                raise HTTPException(status_code=400, detail="receipt count mismatch")
            try:
                verifier = json.loads(existing["verifier_json"])
                public_key = public_key_from_jwk(verifier["publicKeyJwk"])
            except Exception as exc:
                raise HTTPException(status_code=400, detail="invalid receipt verifier") from exc
            outcomes = []
            for receipt in receipts:
                if not isinstance(receipt, dict):
                    raise HTTPException(status_code=400, detail="invalid receipt")
                call_id = receipt.get("callId")
                proposal = proposal_by_call.get(call_id)
                if not proposal or receipt.get("dossierId") != proposal["dossierId"] or receipt.get("action") != proposal["action"] or receipt.get("proposalDigest") != proposal_digest(proposal):
                    raise HTTPException(status_code=409, detail="receipt does not match proposal")
                try:
                    signature = base64.b64decode(receipt.get("receiptSignature", ""), validate=True)
                    public_key.verify(signature, signed_bytes(body, receipt))
                except (ValueError, InvalidSignature, KeyError):
                    raise HTTPException(status_code=409, detail="invalid receipt signature")
                outcomes.append({"dossierId": proposal["dossierId"], "callId": call_id, "action": proposal["action"], "proposalDigest": proposal_digest(proposal), "receiptId": receipt["receiptId"], "status": "executed" if receipt.get("accepted") is True else "rejected"})
            final = {"profile": PROFILE, "evaluationId": evaluation_id, "status": "completed", "inputDigest": existing["input_digest"], "outcomes": outcomes}
            timestamp = utc_now()
            connection.execute("UPDATE evaluations SET final_json=?, updated_at=? WHERE evaluation_id=? AND final_json IS NULL", (json.dumps(final), timestamp, evaluation_id))
            connection.commit()
            return JSONResponse(final, media_type="application/json")
    except HTTPException as exc:
        return error(exc.status_code, str(exc.detail))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return error(400, "invalid JSON")
    except Exception:
        return error(400, "invalid request")

