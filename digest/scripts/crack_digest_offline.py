import hashlib
import itertools
import string


def digest(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


# キャプチャした値
username = ""

realm = "Digest Authentication"
method = "GET"
uri = "/"

nonce = ""
nc = ""
cnonce = ""
qop = "auth"

captured_response = ""


# パスワード候補を総当たり
characters = string.ascii_lowercase

attempts = 0

for password_tuple in itertools.product(characters, repeat=4):
    password = "".join(password_tuple)
    attempts += 1

    # HA1
    HA1 = digest(
        f"{username}:{realm}:{password}"
    )

    # HA2
    HA2 = digest(
        f"{method}:{uri}"
    )

    # response
    response = digest(
        f"{HA1}:{nonce}:{nc}:{cnonce}:{qop}:{HA2}"
    )

    if response == captured_response:
        print("=== Password Found! ===")
        print(f"password : {password}")
        print(f"attempts : {attempts}")
        break

else:
    print("Password not found.")
    print(f"attempts : {attempts}")