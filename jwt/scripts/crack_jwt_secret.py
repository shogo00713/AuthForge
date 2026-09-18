import base64
import hashlib
import hmac


token = input("JWT: ")
wordlist_path = input("Wordlist: ")


header, payload, signature = token.split(".")

signing_input = f"{header}.{payload}"


with open(wordlist_path, "r", encoding="utf-8") as f:
    for line in f:
        secret = line.rstrip("\n")

        calculated_signature = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hashlib.sha256,
        ).digest()

        calculated_signature = base64.urlsafe_b64encode(
            calculated_signature
        ).rstrip(b"=").decode()

        if hmac.compare_digest(calculated_signature, signature):
            print(f"✓ Secretを発見しました: {secret}")
            break
    else:
        print("✗ Secretは見つかりませんでした")