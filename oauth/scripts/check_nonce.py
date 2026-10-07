"""
nonce の未検証 = IDトークンのリプレイ (OIDC 編 6)

シナリオ: 過去のログインで発行された、有効なIDトークン (別のログインの nonce が入っている) を、
          別のログイン試行の途中に差し込む。
  - 通常のクライアント           : nonce が一致しないので、弾く                         (SAFE)
  - nonce を照合しないクライアント: 古いIDトークンを受け入れ、そのユーザーとしてログインしてしまう (REPRODUCED)

あわせて state との役割の違いを確かめる:
  - state は「コールバックの URL」の CSRF 対策。リプレイでは state は正しい値のままなので、state では防げない
  - state が違うコールバックは、nonce を照合しないクライアントでも弾く (state と nonce は別の仕組み)

テスト用クライアントは、このスクリプトが起動・停止する (起動中のサーバーには触れない)。
nonce を外すのは、クライアントの危険スイッチ INSECURE_SKIP_NONCE_CHECK=1 (既定はオフ)。

使い方:
    cd oauth/scripts
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_nonce.py
"""

import sys
import time

from common import precondition, report, reproduce, summary
from mock_as import MockAS, TestClient, attempt_login, id_claims

MOCK_PORT, SECURE_PORT, INSECURE_PORT = 4100, 3100, 3102


def main():
    mock = MockAS(MOCK_PORT)
    secure = TestClient(SECURE_PORT, mock.base_url)
    insecure = TestClient(INSECURE_PORT, mock.base_url, insecure={"INSECURE_SKIP_NONCE_CHECK": "1"})
    try:
        mock.start(); secure.start(); insecure.start()
        precondition("危険スイッチの警告が、起動ログに出ている (スイッチがオンになっている)",
                     "危険" in insecure.log_text() and "危険" not in secure.log_text())

        # 前提: 細工なしなら、どちらのクライアントでもログインが成立する
        for label, client in (("通常のクライアント", secure), ("nonce 照合なしのクライアント", insecure)):
            ok, detail = attempt_login(mock, client, lambda n: mock.sign(id_claims(mock, n)))
            precondition(f"{label}: 細工なしのIDトークンなら、ログインが成立する", ok, detail)

        print()
        print("# リプレイ: 1 分前に発行された、有効なIDトークン (別のログインの nonce) を差し込む")
        now = int(time.time())
        old_token = mock.sign(id_claims(mock, "nonce-of-an-earlier-login", iat=now - 60, auth_time=now - 60))
        replay = lambda n: old_token  # 今のログインの nonce (n) ではなく、古いトークンをそのまま返す

        ok, detail = attempt_login(mock, secure, replay)
        report("A[通常のクライアント]: 古いIDトークンを差し込まれる", ok, f"ログイン{'成立' if ok else '不成立'}: {detail}")
        ok, detail = attempt_login(mock, insecure, replay)
        reproduce("B[nonce 照合なし]: 古いIDトークンを差し込まれる", ok,
                  f"ログイン{'成立 (他人のIDトークンで、ログインできてしまった)' if ok else '不成立'}: {detail}")

        print()
        print("# state との違い: コールバックの state が違う場合")
        ok, detail = attempt_login(mock, secure, lambda n: mock.sign(id_claims(mock, n)), callback_state="forged-state")
        report("C[通常のクライアント]: state が違う", ok, f"ログイン{'成立' if ok else '不成立'}: {detail}")
        ok, detail = attempt_login(mock, insecure, lambda n: mock.sign(id_claims(mock, n)), callback_state="forged-state")
        report("D[nonce 照合なし]: state が違う (nonce を外しても、state は別に守っている)", ok,
               f"ログイン{'成立' if ok else '不成立'}: {detail}")
    finally:
        for stoppable in (insecure, secure, mock):
            try:
                stoppable.stop()
            except Exception as e:
                print(f"(停止時の警告: {e})")

    sys.exit(summary())


if __name__ == "__main__":
    print("=== nonce の未検証 (IDトークンのリプレイ) の再現 ===\n")
    main()
