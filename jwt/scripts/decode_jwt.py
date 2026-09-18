import base64

token = input("JWT: ")

# 分割する
header, payload, signature = token.split(".")

# Base64URLデコードする関数
def decode_base64url(value):
    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)
    return decoded.decode("utf-8")

print("=== Header ===")
print(decode_base64url(header))

print("\n=== Payload ===")
print(decode_base64url(payload))

print("\n=== Signature ===")
print(signature)