import base64
import hashlib
import hmac

token = input("JWT: ")
secret = input("Secret: ")

# JWTを3つに分解
header, payload, signature = token.split(".")

# 署名対象
signing_input = f"{header}.{payload}"

# HMAC-SHA256で署名を計算
expected_signature = hmac.new(
    secret.encode(),
    signing_input.encode(),
    hashlib.sha256,
).digest()

# 計算した署名をBase64URLエンコード
expected_signature = base64.urlsafe_b64encode(
    expected_signature
).rstrip(b"=").decode()

# JWTのSignatureと比較
if hmac.compare_digest(expected_signature, signature):
    print("✓ 署名検証に成功しました")
else:
    print("✗ 署名検証に失敗しました")