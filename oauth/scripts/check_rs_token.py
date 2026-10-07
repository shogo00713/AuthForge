"""
リソースサーバー (/resources) のアクセストークン検証テスト (OIDC 編 5-D)

「不正なトークンは弾き、正規のトークンだけ通す」ことを確かめる。
  - 前提: 認可サーバーと同じ形・同じ鍵で作ったトークンは通る (これが通らないと、以降の SAFE は意味がない)
  - 各ケースは、前提のトークンから「1 か所だけ」変えたもの。弾かれた理由を切り分けられる
  - 200 が返ったら VULNERABLE (受け入れてはいけないものを通した)

使い方:
    cd oauth/scripts
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_rs_token.py
"""

import sys
import time

import requests

from common import (
    AS_KID,
    AS_PUBLIC_KEY_PATH,
    AS_URL,
    RS_URL,
    forge_jwt,
    generate_other_private_key,
    login_and_get_tokens,
    precondition,
    report,
    summary,
    valid_access_claims,
)

ENDPOINT = f"{RS_URL}/resources"


def call(token: str = None, authorization: str = None) -> requests.Response:
    headers = {}
    if authorization is not None:
        headers["Authorization"] = authorization
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return requests.get(ENDPOINT, headers=headers)


def expect_rejected(name: str, resp: requests.Response):
    """200 以外 (401 / 400 など) なら SAFE。WWW-Authenticate のエラー種別も詳細に残す"""
    www = resp.headers.get("WWW-Authenticate", "")
    report(name, resp.status_code == 200, f"status={resp.status_code} {www[:70]}")


def main():
    # --- 前提: 正規の形のトークンは通ること ---
    control = call(forge_jwt(valid_access_claims()))
    precondition("認可サーバーと同じ形・同じ鍵のトークンが通る", control.status_code == 200, f"status={control.status_code}")
    real = login_and_get_tokens(scope="openid profile:basic")
    precondition("実際に発行されたアクセストークンが通る", real is not None and call(real["access_token"]).status_code == 200)

    print()
    # --- 署名・アルゴリズム ---
    expect_rejected("A[別の鍵で署名]: kid は正規のものを偽装",
                    call(forge_jwt(valid_access_claims(), key=generate_other_private_key())))
    expect_rejected("B[未知の kid]: JWKS にない kid",
                    call(forge_jwt(valid_access_claims(), kid="evil-key", key=generate_other_private_key())))
    expect_rejected("C[kid なし]",
                    call(forge_jwt(valid_access_claims(), kid=None, key=generate_other_private_key())))
    expect_rejected("D[alg=none]: 署名なし",
                    call(forge_jwt(valid_access_claims(), alg="none")))
    try:
        with open(AS_PUBLIC_KEY_PATH, "rb") as f:
            public_pem = f.read()
        expect_rejected("E[HS256 アルゴリズム混同]: 公開鍵を共通鍵にして署名",
                        call(forge_jwt(valid_access_claims(), alg="HS256", secret=public_pem)))
    except FileNotFoundError:
        print(f"[SKIP] E: 公開鍵ファイルが見つかりません ({AS_PUBLIC_KEY_PATH})")

    print()
    # --- クレーム (署名は正規の鍵。1 か所だけ変える) ---
    expect_rejected("F[iss 偽装]: 正規の鍵で署名、iss だけ別の認可サーバー",
                    call(forge_jwt(valid_access_claims(iss="https://evil.example"))))
    expect_rejected("G[期限切れ]: exp が過去",
                    call(forge_jwt(valid_access_claims(iat=int(time.time()) - 120, exp=int(time.time()) - 60))))
    expect_rejected("H[aud が別]: aud = クライアント (IDトークンの形)",
                    call(forge_jwt(valid_access_claims(aud="fortune-app"))))
    expect_rejected("I[aud なし]",
                    call(forge_jwt(valid_access_claims(aud=None))))
    expect_rejected("J[exp なし]: 期限のないトークン",
                    call(forge_jwt(valid_access_claims(exp=None))))

    print()
    # --- 実物の IDトークンを送る (トークン取り違え) ---
    expect_rejected("K[IDトークンを送る]: 実際に発行された id_token をアクセストークンとして使う",
                    call(real["id_token"]))

    print()
    # --- リクエストの形 ---
    expect_rejected("L[トークンなし]", call())
    expect_rejected("M[Bearer ではない]: Basic 認証", call(authorization="Basic dXNlcjpwYXNz"))
    expect_rejected("N[空のトークン]", call(authorization="Bearer "))
    expect_rejected("O[でたらめな文字列]", call("abc.def.ghi"))

    sys.exit(summary())


if __name__ == "__main__":
    print(f"=== リソースサーバーのトークン検証テスト against {ENDPOINT} (iss={AS_URL}, kid={AS_KID}) ===\n")
    main()
