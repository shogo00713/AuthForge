"""
トークンの取り違え = IDトークン (など、別の宛先向けのトークン) を、アクセストークンとして使う (OIDC 編 6)

シナリオ: クライアントが受け取った IDトークン等を、リソースサーバー (/resources) に送る。
  - 通常のリソースサーバー      : audience (自分宛てか) を検証するので、弾く                 (SAFE)
  - audience を検証しないサーバー : 署名と iss が正しければ、受け入れてしまう場合がある      (REPRODUCED)

3 つのケース (どれも、署名は認可サーバーの正規の鍵、iss も正しい。aud だけが自分宛てではない):
  1. 本物の IDトークン (認可サーバーが実際に発行したもの)
  2. scope を載せてしまった IDトークン (IDトークンに scope を入れる実装もある)
  3. 別の API 宛てのアクセストークン (同じ認可サーバーが、別のリソースサーバー向けに発行したもの)

本物のIDトークン (ケース1) は scope を持たないので、audience を外しても、別の理由
(必須クレーム scope がない) で弾かれることがある。これは「たまたま別の層が止めた」状態で、aud の代わりにはならない。

テスト用リソースサーバーは、このスクリプトが 2 つ起動・停止する (起動中のサーバーには触れない)。
audience を外すのは、リソースサーバーの危険スイッチ INSECURE_SKIP_AUD_CHECK=1 (既定はオフ)。
本物の認可サーバー (AS_URL, 既定 http://localhost:4000) が起動していること。

使い方:
    cd oauth/scripts
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_token_confusion.py
"""

import sys
import time

import requests

from common import (
    AS_URL,
    forge_jwt,
    info,
    login_and_get_tokens,
    precondition,
    report,
    reproduce,
    summary,
    valid_access_claims,
)
from mock_as import TestResourceServer

SECURE_PORT, INSECURE_PORT = 4200, 4201


def call(server: TestResourceServer, token: str) -> requests.Response:
    return requests.get(f"{server.url}/resources", headers={"Authorization": f"Bearer {token}"})


def show(resp: requests.Response) -> str:
    return f"status={resp.status_code} {resp.text[:70]}"


def main():
    try:
        discovery = requests.get(f"{AS_URL}/.well-known/openid-configuration", timeout=3)
        precondition("本物の認可サーバーが起動している", discovery.status_code == 200, f"{AS_URL} -> {discovery.status_code}")
    except requests.RequestException as e:
        precondition("本物の認可サーバーが起動している", False, f"{AS_URL} に繋がりません ({e.__class__.__name__})")

    secure = TestResourceServer(SECURE_PORT, AS_URL)
    insecure = TestResourceServer(INSECURE_PORT, AS_URL, insecure={"INSECURE_SKIP_AUD_CHECK": "1"})
    try:
        secure.start(); insecure.start()
        precondition("危険スイッチの警告が、起動ログに出ている (スイッチがオンになっている)",
                     "危険" in insecure.log_text() and "危険" not in secure.log_text())

        # 前提: 自分宛て (aud = そのサーバーの URL) の正規のアクセストークンは、どちらも通す
        for label, server in (("通常のリソースサーバー", secure), ("audience 検証なしのサーバー", insecure)):
            resp = call(server, forge_jwt(valid_access_claims(aud=server.url, scope="openid profile:basic")))
            precondition(f"{label}: 自分宛てのアクセストークンが通る", resp.status_code == 200, f"status={resp.status_code}")

        now = int(time.time())
        real = login_and_get_tokens(scope="openid profile:basic")
        precondition("本物の認可サーバーから、IDトークンを取得できた", real is not None and "id_token" in real)

        cases = [
            ("1", "本物の IDトークン (aud=fortune-app, scope なし)", real["id_token"], False),
            ("2", "scope を載せてしまった IDトークン (aud=fortune-app, scope あり)",
             forge_jwt({"iss": AS_URL, "sub": "u01", "aud": "fortune-app", "iat": now, "exp": now + 300,
                        "auth_time": now, "nonce": "n", "scope": "openid profile:full"}), True),
            ("3", "別の API 宛てのアクセストークン (aud=https://other-api.example, scope あり)",
             forge_jwt(valid_access_claims(aud="https://other-api.example", scope="openid profile:full")), True),
        ]
        for key, label, token, expect_reproduced in cases:
            print()
            resp = call(secure, token)
            report(f"{key}-1[通常のサーバー]: {label}", resp.status_code == 200, show(resp))
            resp = call(insecure, token)
            if expect_reproduced:
                reproduce(f"{key}-2[audience 検証なし]: {label}", resp.status_code == 200,
                          f"{show(resp)} ← {'他の宛先向けのトークンで、データを取れてしまった' if resp.status_code == 200 else ''}")
            else:
                # 本物の IDトークンは scope を持たない。aud を外しても、別の層 (必須クレーム) が止めるかを観察する
                info(f"{key}-2[audience 検証なし]: {label}", f"{show(resp)}")
                print("        弾いた理由 (サーバーのログ):", (insecure.new_log_errors() or ["(なし)"])[-1][:90])
    finally:
        for stoppable in (insecure, secure):
            try:
                stoppable.stop()
            except Exception as e:
                print(f"(停止時の警告: {e})")

    sys.exit(summary())


if __name__ == "__main__":
    print("=== トークンの取り違え (IDトークン等を、アクセストークンとして使う) の再現 ===\n")
    main()
