"""
アクセストークンを1つ発行して、ヘッダーとペイロードを表示する (観察用)

認可サーバー (localhost:4000) を起動した状態で実行する。
CLIENT_SECRET / TEST_USERNAME / TEST_PASSWORD は環境変数で渡す。
"""

import base64
import json

from common import login_and_get_tokens


def decode_part(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


tokens = login_and_get_tokens(scope="openid profile:basic")
if not tokens:
    raise SystemExit("トークンを取得できませんでした")

for name in ("access_token", "id_token"):
    token = tokens.get(name)
    if not token:
        continue
    header, payload, _ = token.split(".")
    print(f"=== {name} ===")
    print("token  :", token)
    print("header :", json.dumps(decode_part(header), ensure_ascii=False))
    print("payload:", json.dumps(decode_part(payload), ensure_ascii=False))
