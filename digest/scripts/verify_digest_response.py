import hashlib


def digest(value: str) -> str:
    """MD5 digestを16進数文字列で返す関数"""
    return hashlib.md5(value.encode("utf-8")).hexdigest()


# キャプチャした値を入力
username = ""
password = ""

realm = "Digest Authentication"
method = "GET"
uri = "/"

nonce = ""
nc = ""
cnonce = ""
qop = "auth"

captured_response = ""


# Digest計算

# HA1 = MD5(username:realm:password)
HA1 = digest(
    f"{username}:{realm}:{password}"
)

# HA2 = MD5(method:uri)
HA2 = digest(
    f"{method}:{uri}"
)

# response
response = digest(
    f"{HA1}:{nonce}:{nc}:{cnonce}:{qop}:{HA2}"
)


# 結果表示

print("=== Digest Authentication ===")
print(f"HA1      : {HA1}")
print(f"HA2      : {HA2}")
print(f"response : {response}")
print(f"captured : {captured_response}")
print()

if response == captured_response:
    print("✓ Response matches!")
else:
    print("✗ Response does NOT match.")