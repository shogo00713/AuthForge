"""
aud の未検証 = 別のクライアント向けのIDトークンを受け入れてしまう (OIDC 編 6)

シナリオ: 認可サーバーが「別のアプリ (other-app)」向けに発行した、署名も iss も nonce も正しいIDトークンを、
          このクライアント (fortune-app) に渡す。aud だけが違う。
  - 通常のクライアント     : aud が自分 (fortune-app) ではないので、弾く       (SAFE)
  - aud を検証しないクライアント: 他のアプリ宛てのIDトークンで、ログインできてしまう (REPRODUCED)

aud は「このトークンは誰宛てか」。署名が正しいだけでは、自分宛てかどうかは分からない。
(認可サーバーが同じなら、署名鍵も iss も同じなので、aud だけが宛先を区別する)

テスト用クライアントは、このスクリプトが起動・停止する (起動中のサーバーには触れない)。
aud を外すのは、クライアントの危険スイッチ INSECURE_SKIP_AUD_CHECK=1 (既定はオフ)。

使い方:
    cd oauth/scripts
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_id_token_aud.py
"""

import sys

from common import precondition, report, reproduce, summary
from mock_as import MockAS, TestClient, attempt_login, id_claims

MOCK_PORT, SECURE_PORT, INSECURE_PORT = 4100, 3100, 3103

CASES = [
    ("A", "別のクライアント (other-app) 宛てのIDトークン", {"aud": "other-app"}),
    ("B", "リソースサーバー宛て (アクセストークンの宛先) のトークンをIDトークンとして渡す", {"aud": "http://localhost:4001"}),
    ("C", "aud が配列で、自分 (fortune-app) を含まない", {"aud": ["other-app", "another-app"]}),
]


def main():
    mock = MockAS(MOCK_PORT)
    secure = TestClient(SECURE_PORT, mock.base_url)
    insecure = TestClient(INSECURE_PORT, mock.base_url, insecure={"INSECURE_SKIP_AUD_CHECK": "1"})
    try:
        mock.start(); secure.start(); insecure.start()
        precondition("危険スイッチの警告が、起動ログに出ている (スイッチがオンになっている)",
                     "危険" in insecure.log_text() and "危険" not in secure.log_text())

        # 前提: 細工なし (aud が自分) なら、どちらのクライアントでもログインが成立する
        for label, client in (("通常のクライアント", secure), ("aud 検証なしのクライアント", insecure)):
            ok, detail = attempt_login(mock, client, lambda n: mock.sign(id_claims(mock, n)))
            precondition(f"{label}: aud が自分のIDトークンなら、ログインが成立する", ok, detail)

        for key, label, overrides in CASES:
            print()
            token = lambda n, o=overrides: mock.sign(id_claims(mock, n, **o))  # nonce・署名・iss は正しいまま、aud だけ違う
            ok, detail = attempt_login(mock, secure, token)
            report(f"{key}-1[通常のクライアント]: {label}", ok, f"ログイン{'成立' if ok else '不成立'}: {detail}")
            ok, detail = attempt_login(mock, insecure, token)
            reproduce(f"{key}-2[aud 検証なし]: {label}", ok,
                      f"ログイン{'成立 (自分宛てではないIDトークンで、ログインできてしまった)' if ok else '不成立'}: {detail}")
    finally:
        for stoppable in (insecure, secure, mock):
            try:
                stoppable.stop()
            except Exception as e:
                print(f"(停止時の警告: {e})")

    sys.exit(summary())


if __name__ == "__main__":
    print("=== aud の未検証 (別クライアント向けIDトークンの受け入れ) の再現 ===\n")
    main()
