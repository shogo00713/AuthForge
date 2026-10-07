"""
クライアントの IDトークン検証と、UserInfo の sub 照合のテスト (OIDC 編 5-D)

クライアントは IDトークンを、サーバー間通信で受け取る。外から差し込めないので、
mock_as.py の「偽の認可サーバー」に向けたテスト用クライアントを別ポートで起動し、
シナリオごとに細工したトークンを返させて、ログインが成立するかを見る。

  - 前提: 細工なしのトークンなら、ログインが成立する (これが崩れたら以降の SAFE は意味がない)
  - 各ケースは、前提のトークンから「1 か所だけ」変えたもの
  - ログインが成立してしまったら VULNERABLE。弾いた理由 (クライアントのログの Error 行) も表示する

使い方 (サーバーの起動は不要。テスト用クライアントを、このスクリプトが起動・停止する):
    cd oauth/scripts
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_client_id_token.py
"""

import sys
import time
from urllib.parse import unquote

import requests

from common import precondition, report, summary
from mock_as import MockAS, TestClient, attempt_login, id_claims

MAIN_PORTS = {"mock": 4100, "client": 3100}       # 通常のシナリオ用
MISMATCH_PORTS = {"mock": 4101, "client": 3101}   # issuer 不一致の確認用

def case(mock, client, name, build_id_token, **kwargs):
    logged_in, detail = attempt_login(mock, client, build_id_token, **kwargs)
    report(name, logged_in, f"ログイン{'成立' if logged_in else '不成立'}: {detail}")


def main():
    mock = MockAS(MAIN_PORTS["mock"])
    client = TestClient(MAIN_PORTS["client"], mock.base_url)
    mismatch_mock = MockAS(MISMATCH_PORTS["mock"], advertised_issuer=f"http://127.0.0.1:{MISMATCH_PORTS['mock']}")
    mismatch_client = TestClient(MISMATCH_PORTS["client"], mismatch_mock.base_url)
    try:
        mock.start(); mismatch_mock.start()
        client.start(); mismatch_client.start()

        # --- 前提: 細工なしならログインが成立すること ---
        ok, detail = attempt_login(mock, client, lambda n: mock.sign(id_claims(mock, n)))
        precondition("細工なしのIDトークンなら、ログインが成立する", ok, f"{detail} (ログ: {client.log.name})")

        print()
        print("# IDトークンの検証 (クライアント自身の検証コード)")
        case(mock, client, "A[nonce 不一致]: セッションの nonce と違う (別のログインのIDトークン)",
             lambda n: mock.sign(id_claims(mock, "nonce-of-another-login")))
        case(mock, client, "B[nonce なし]", lambda n: mock.sign(id_claims(mock, n, nonce=None)))
        case(mock, client, "C[aud 不一致]: 別クライアント宛てのIDトークン",
             lambda n: mock.sign(id_claims(mock, n, aud="other-app")))
        case(mock, client, "D[aud がリソースサーバー]: アクセストークンの形",
             lambda n: mock.sign(id_claims(mock, n, aud="http://localhost:4001")))
        case(mock, client, "E[iss 不一致]: 署名は正しいが、iss が別の認可サーバー",
             lambda n: mock.sign(id_claims(mock, n, iss="https://evil.example")))
        case(mock, client, "F[期限切れ]",
             lambda n: mock.sign(id_claims(mock, n, iat=int(time.time()) - 600, exp=int(time.time()) - 300)))
        case(mock, client, "G[exp なし]", lambda n: mock.sign(id_claims(mock, n, exp=None)))
        case(mock, client, "H[iat なし]", lambda n: mock.sign(id_claims(mock, n, iat=None)))
        case(mock, client, "I[auth_time なし]", lambda n: mock.sign(id_claims(mock, n, auth_time=None)))
        case(mock, client, "J[sub なし]", lambda n: mock.sign(id_claims(mock, n, sub=None)))

        print()
        print("# 署名・アルゴリズム")
        case(mock, client, "K[別の鍵で署名]: kid はモックのものを偽装",
             lambda n: mock.sign(id_claims(mock, n), key=mock.other_key))
        case(mock, client, "L[未知の kid]",
             lambda n: mock.sign(id_claims(mock, n), kid="evil-key", key=mock.other_key))
        case(mock, client, "M[alg=none]", lambda n: mock.sign(id_claims(mock, n), alg="none"))
        case(mock, client, "N[HS256 アルゴリズム混同]: 公開鍵を共通鍵にして署名",
             lambda n: mock.sign(id_claims(mock, n), alg="HS256", secret=mock.public_pem))

        print()
        print("# トークンレスポンスの形")
        case(mock, client, "O[id_token が返らない]: openid を要求したのに、IDトークンがない", lambda n: None)

        print()
        print("# UserInfo の sub 照合 (OIDC Core 5.3.2)")
        case(mock, client, "P[sub 食い違い]: IDトークンは u01、UserInfo は u02",
             lambda n: mock.sign(id_claims(mock, n)), userinfo_sub="u02")
        case(mock, client, "Q[UserInfo が失敗]: 401 を返す",
             lambda n: mock.sign(id_claims(mock, n)), userinfo_status=401)

        print()
        print("# Discovery の issuer 一致 (OIDC Discovery 4.3)")
        r = requests.get(f"{mismatch_client.url}/login", params={"scope": "profile:basic"}, allow_redirects=False)
        loc = r.headers.get("Location", "")
        reasons = mismatch_client.new_log_errors()
        report("R[issuer 不一致]: Discovery が名乗る issuer が、期待値とわずかに違う (localhost と 127.0.0.1)",
               "/authorize" in loc,
               f"認可エンドポイントへ{'進んだ' if '/authorize' in loc else '進まなかった'}: {(reasons[0] if reasons else unquote(loc))[:110]}")
    finally:
        for stoppable in (client, mismatch_client, mock, mismatch_mock):
            try:
                stoppable.stop()
            except Exception as e:
                print(f"(停止時の警告: {e})")

    sys.exit(summary())


if __name__ == "__main__":
    print("=== クライアントの IDトークン検証テスト (モック認可サーバー + テスト用クライアント) ===\n")
    main()
