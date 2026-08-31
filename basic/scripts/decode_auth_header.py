import base64

header_authorization = input("Authorization: ")

# <type>指定の "Basic " の部分を取り除く
encoded = header_authorization.removeprefix("Basic ").strip()

# Base64でデコードする
decoded = base64.b64decode(encoded).decode("utf-8")

# ユーザー名とパスワードに分解
username, password = decoded.split(":", 1)

print(f"Your username is {username}")
print(f"Your password is {password}")