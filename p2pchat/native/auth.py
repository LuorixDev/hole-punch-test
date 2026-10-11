"""Attempt-bound shared-room-key authentication; never log frames or secrets."""
import hashlib
import hmac
import json
import re
import secrets


def packed(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


class Auth:
    def __init__(self, room, secret, connection, attempt, local, remote):
        self.room, self.key = room, secret.encode()
        self.connection, self.attempt = connection, attempt
        self.local, self.remote = local, remote
        self.nonce = secrets.token_hex(32)
        self.remote_nonce = None
        self.acked = False
        self.received_hello = False

    def proof(self, sender, receiver, nonce, echo=None):
        values = ["p2pobs-v1" if echo is None else "p2pobs-v1-ack", self.room,
                  self.connection, self.attempt, sender, receiver, nonce]
        if echo is not None:
            values.append(echo)
        return hmac.new(self.key, packed(values), hashlib.sha256).hexdigest()

    def frame(self, ack=False):
        result = dict(v=1, kind="hello-ack" if ack else "hello", peer=self.local,
                      connectionId=self.connection, attemptId=self.attempt, nonce=self.nonce)
        if ack:
            result["echoNonce"] = self.remote_nonce
        result["proof"] = self.proof(self.local, self.remote, self.nonce, self.remote_nonce if ack else None)
        return result

    def receive(self, frame):
        if (frame.get("v") != 1 or frame.get("peer") != self.remote or
                frame.get("connectionId") != self.connection or frame.get("attemptId") != self.attempt):
            raise ValueError("AUTH_FAILED")
        nonce = frame.get("nonce", "")
        if not isinstance(nonce, str) or not re.fullmatch("[0-9a-f]{64}", nonce):
            raise ValueError("AUTH_FAILED")
        kind = frame.get("kind")
        if kind not in ("hello", "hello-ack"):
            raise ValueError("AUTH_FAILED")
        echo = frame.get("echoNonce") if kind == "hello-ack" else None
        if kind == "hello-ack" and echo != self.nonce:
            raise ValueError("AUTH_FAILED")
        expected = self.proof(self.remote, self.local, nonce, echo)
        if not isinstance(frame.get("proof"), str) or not hmac.compare_digest(expected, frame["proof"]):
            raise ValueError("AUTH_FAILED")
        if self.remote_nonce is not None and nonce != self.remote_nonce:
            raise ValueError("NONCE_REPLAY")
        self.remote_nonce = nonce
        if kind == "hello":
            self.received_hello = True
            return self.frame(ack=True)
        self.acked = True
        return None

    def control(self, kind, nonce):
        body = ["p2pobs-v1-control", self.connection, self.attempt, self.local, self.remote, kind, nonce]
        return {"kind": kind, "nonce": nonce, "proof": hmac.new(self.key, packed(body), hashlib.sha256).hexdigest()}

    def verify_control(self, frame):
        nonce, kind = frame.get("nonce", ""), frame.get("kind")
        if kind not in {"ping", "pong"} or not isinstance(nonce, str) or not re.fullmatch("[0-9a-f]{32}", nonce):
            raise ValueError("AUTH_FAILED")
        body = ["p2pobs-v1-control", self.connection, self.attempt, self.remote, self.local, kind, nonce]
        expected = hmac.new(self.key, packed(body), hashlib.sha256).hexdigest()
        if not isinstance(frame.get("proof"), str) or not hmac.compare_digest(expected, frame["proof"]):
            raise ValueError("AUTH_FAILED")
        return nonce

    @property
    def direct(self):
        return self.acked and self.received_hello

    def clear(self):
        self.key = b""
        self.nonce = self.remote_nonce = None
