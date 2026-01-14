import hashlib
import time

class SessionEngine:
    def __init__(self):
        self._salt = b"\x13\x37\x42"
        self._epoch = int(time.time()) // 60

    def _mix(self, data: bytes) -> bytes:
        h = hashlib.sha256()
        h.update(self._salt)
        h.update(data)
        h.update(str(self._epoch).encode())
        return h.digest()

    def verify_token(self, user_input: str) -> bool:
        expected = self._mix(b"authorized_user")
        attempt = self._mix(user_input.encode())
        return expected[:6] == attempt[:6]


def main():
    engine = SessionEngine()
    token = input("Enter session token: ")

    if engine.verify_token(token):
        print("Session accepted")
    else:
        print("Session rejected")


if __name__ == "__main__":
    main()
