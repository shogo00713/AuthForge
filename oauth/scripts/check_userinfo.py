"""
UserInfo (/userinfo) のテスト (OIDC 編 5-D)

「正規のアクセストークンだけが通り、返す内容がスコープの範囲に収まる」ことを確かめる。
  - 前提: 認可サーバーと同じ形・同じ鍵のトークンは通る (これが通らないと、以降の SAFE は意味がない)
  - 弾くべきもの (期待するステータス) :
      IDトークン / aud に UserInfo が無いトークン / 別の鍵 / alg=none / 期限切れ / トークンなし -> 401
      openid スコープが無いトークン                                                         -> 403
  - 返す内容: openid だけなら sub のみ。preferred_username は profile:* があるときだけ

使い方:
    cd oauth/scripts
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_userinfo.py
"""

import sys
import time

import requests

from common import (
    RS_URL,
    USERINFO_URL,
    forge_jwt,
    generate_other_private_key,
    login_and_get_tokens,
    precondition,
    report,
    summary,
    valid_access_claims,
)


def call(token: str = None) -> requests.Response:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return requests.get(USERINFO_URL, headers=headers)


def expect_status(name: str, resp: requests.Response, expected: int):
    """期待したステータス (401 か 403) で弾かれていれば SAFE。200 が返ったら VULNERABLE。
    別のステータスで弾かれた場合も、期待とずれているので VULNERABLE 扱いにして気づけるようにする"""
    www = resp.headers.get("WWW-Authenticate", "")
    report(name, resp.status_code != expected, f"status={resp.status_code} (期待 {expected}) {www[:60]}")


def main():
    # --- 前提: 正規の形のトークンは通ること ---
    control = call(forge_jwt(valid_access_claims()))
    precondition("認可サーバーと同じ形・同じ鍵のトークンが通る", control.status_code == 200, f"status={control.status_code} body={control.text[:80]}")
    real = login_and_get_tokens(scope="openid profile:basic")
    precondition("実際に発行されたアクセストークンが通る", real is not None and call(real["access_token"]).status_code == 200)

    print()
    # --- 弾くべきもの ---
    expect_status("A[IDトークンを送る]: 実際に発行された id_token (aud=クライアント)", call(real["id_token"]), 401)
    expect_status("B[aud に UserInfo が無い]: リソースサーバー宛てだけのトークン",
                  call(forge_jwt(valid_access_claims(aud=RS_URL))), 401)
    expect_status("C[aud なし]", call(forge_jwt(valid_access_claims(aud=None))), 401)
    expect_status("D[別の鍵で署名]: kid は正規のものを偽装",
                  call(forge_jwt(valid_access_claims(), key=generate_other_private_key())), 401)
    expect_status("E[alg=none]", call(forge_jwt(valid_access_claims(), alg="none")), 401)
    expect_status("F[期限切れ]",
                  call(forge_jwt(valid_access_claims(iat=int(time.time()) - 120, exp=int(time.time()) - 60))), 401)
    expect_status("F2[exp なし]: 期限のないトークン",
                  call(forge_jwt(valid_access_claims(exp=None))), 401)
    expect_status("G[iss 偽装]", call(forge_jwt(valid_access_claims(iss="https://evil.example"))), 401)
    expect_status("H[存在しないユーザー]: sub が台帳にない", call(forge_jwt(valid_access_claims(sub="u999"))), 401)
    expect_status("I[トークンなし]", call(), 401)

    print()
    # --- スコープ ---
    only_profile = login_and_get_tokens(scope="profile:basic")
    expect_status("J[openid スコープなし]: 実際に発行された profile:basic のみのトークン",
                  call(only_profile["access_token"]), 403)

    print()
    # --- 返す内容がスコープの範囲に収まるか ---
    openid_only = login_and_get_tokens(scope="openid")
    body = call(openid_only["access_token"]).json()
    report("K[openid のみ]: sub 以外 (preferred_username など) を返していないか",
           set(body.keys()) != {"sub"}, f"返ったクレーム={sorted(body.keys())}")
    body = call(real["access_token"]).json()
    report("L[openid profile:basic]: sub と preferred_username だけか (余計な個人情報を返していないか)",
           set(body.keys()) != {"sub", "preferred_username"}, f"返ったクレーム={sorted(body.keys())}")

    sys.exit(summary())


if __name__ == "__main__":
    print(f"=== UserInfo のテスト against {USERINFO_URL} ===\n")
    main()
