"""
redirect_uri 検証テスト

GET /authorize と POST /authorize の両方で redirect_uri が
正しく検証されているかを確認する。

使い方:
    AS_URL=http://localhost:4000 \
    CLIENT_ID=fortune-app \
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    REDIRECT_URI=http://localhost:3000/callback \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<users.ts の Bob のパスワード> \
    python check_redirect_uri.py
"""

import sys
import requests

from common import (
    AS_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI,
    TEST_USERNAME,
    TEST_PASSWORD,
    EVIL_URL,
    authorize_get,
    authorize_post,
    exchange_code,
    location_host,
    location_query,
    login_and_get_code,
    report,
    summary,
)

from urllib.parse import urlparse

EVIL_HOST = urlparse(EVIL_URL).netloc


def test_a_get_malformed_redirect_uri():
    """A: GET /authorize に対する崩した redirect_uri がすべて 400 になるか"""
    base = urlparse(REDIRECT_URI)
    candidates = {
        "別ドメイン": EVIL_URL,
        "末尾スラッシュ追加": REDIRECT_URI + "/",
        "パス追加(前方一致)": REDIRECT_URI + "/evil",
        "サブドメイン偽装": f"{base.scheme}://{base.hostname}.evil.example{base.path}",
        "クエリ追加": REDIRECT_URI + "?x=1",
        "スキーム違い(https)": REDIRECT_URI.replace("http://", "https://"),
    }
    for name, uri in candidates.items():
        resp = authorize_get(
            client_id=CLIENT_ID,
            redirect_uri=uri,
            response_type="code",
            scope="profile:basic",
        )
        vulnerable = resp.status_code != 400
        report(
            f"A[GET]: {name}",
            vulnerable,
            f"status={resp.status_code} uri={uri}",
        )


def test_b_deny_open_redirect():
    """B: 認証不要で decision=deny のまま redirect_uri だけ差し替えられないか"""
    resp = authorize_post(
        decision="deny",
        client_id=CLIENT_ID,
        redirect_uri=EVIL_URL,
        response_type="code",
        scope="profile:basic",
    )
    host = location_host(resp)
    vulnerable = resp.status_code in (301, 302, 303, 307, 308) and host == EVIL_HOST
    report(
        "B[POST deny]: redirect_uri 差し替えでオープンリダイレクト",
        vulnerable,
        f"status={resp.status_code} location_host={host}",
    )


def test_c_code_to_evil_redirect():
    """C: 正規ログインのまま POST の redirect_uri だけ差し替えて、
    認可コードが外部ドメインに流れないか"""
    resp = authorize_post(
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        client_id=CLIENT_ID,
        redirect_uri=EVIL_URL,
        response_type="code",
        scope="profile:basic",
    )
    host = location_host(resp)
    q = location_query(resp)
    vulnerable = (
        resp.status_code in (301, 302, 303, 307, 308)
        and host == EVIL_HOST
        and "code" in q
    )
    report(
        "C[POST]: 認可コードが外部 redirect_uri に渡る",
        vulnerable,
        f"status={resp.status_code} location_host={host} code_leaked={'code' in q}",
    )


def test_d_token_endpoint_redirect_uri_mismatch():
    """D: 正規に取得したコードを、違う redirect_uri で交換できないか(トークンエンドポイント側)"""
    code = login_and_get_code()
    if not code:
        report("D[token]: redirect_uri 不一致", False, "前提の認可コード取得に失敗(SAFE側で停止)")
        return

    resp = exchange_code(code, redirect_uri=EVIL_URL)
    vulnerable = resp.status_code == 200
    report(
        "D[token]: 別の redirect_uri でコード交換",
        vulnerable,
        f"status={resp.status_code} body={resp.text[:200]}",
    )


def test_e_token_endpoint_missing_redirect_uri():
    """E: redirect_uri を省略してコード交換できないか"""
    code = login_and_get_code()
    if not code:
        report("E[token]: redirect_uri 省略", False, "前提の認可コード取得に失敗(SAFE側で停止)")
        return

    resp = requests.post(
        f"{AS_URL}/token",
        data={"grant_type": "authorization_code", "code": code},
        auth=(CLIENT_ID, CLIENT_SECRET),
    )
    vulnerable = resp.status_code == 200
    report(
        "E[token]: redirect_uri 省略でコード交換",
        vulnerable,
        f"status={resp.status_code} body={resp.text[:200]}",
    )


if __name__ == "__main__":
    print(f"=== redirect_uri 検証テスト against {AS_URL} ===\n")
    test_a_get_malformed_redirect_uri()
    test_b_deny_open_redirect()
    test_c_code_to_evil_redirect()
    test_d_token_endpoint_redirect_uri_mismatch()
    test_e_token_endpoint_missing_redirect_uri()

    sys.exit(summary())
