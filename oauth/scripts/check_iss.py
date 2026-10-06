"""
認可レスポンスの iss パラメータ (RFC 9207) のテスト

Mix-up 攻撃 (認可サーバーの取り違え) への対策として、
  - AS は redirect_uri へ返す認可レスポンス (成功・エラーとも) に iss を付けているか
  - クライアントは /callback で、iss が「フローを開始した AS」と一致するかを確認しているか
を確かめる。

C・D では iss 以外 (code / state) は正規の値をそろえ、iss の検証だけで弾かれるかを見る。

使い方:
    cd oauth/scripts
    AS_URL=http://localhost:4000 \
    CLIENT_URL=http://localhost:3000 \
    CLIENT_ID=fortune-app \
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    REDIRECT_URI=http://localhost:3000/callback \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_iss.py
"""

import sys
from typing import Optional

import requests

from common import (
    AS_URL,
    CLIENT_ID,
    CLIENT_URL,
    REDIRECT_URI,
    TEST_PASSWORD,
    TEST_USERNAME,
    authorize_post,
    client_session_is_logged_in,
    location_query,
    report,
    summary,
)

EVIL_ISSUER = "https://evil.example"


def start_flow_as_client() -> tuple[requests.Session, dict]:
    """クライアントの /login を踏んでフローを開始し、
    (クライアントとのセッション, AS へ渡される認可リクエストのパラメータ) を返す"""
    session = requests.Session()
    resp = session.get(f"{CLIENT_URL}/login", params={"scope": "profile:basic"}, allow_redirects=False)
    return session, location_query(resp)


def post_authorize(auth_params: dict, **form) -> requests.Response:
    """クライアントが組み立てた認可リクエストのパラメータのまま POST /authorize を送る"""
    return authorize_post(
        client_id=auth_params.get("client_id", CLIENT_ID),
        redirect_uri=auth_params.get("redirect_uri", REDIRECT_URI),
        response_type=auth_params.get("response_type", "code"),
        scope=auth_params.get("scope", "profile:basic"),
        state=auth_params.get("state", ""),
        code_challenge=auth_params.get("code_challenge", ""),
        **form,
    )


def test_a_iss_in_success_response():
    """A: 認可コード発行時のレスポンスに、AS 自身の iss が付いているか"""
    _, auth_params = start_flow_as_client()
    resp = post_authorize(auth_params, username=TEST_USERNAME, password=TEST_PASSWORD)
    q = location_query(resp)
    vulnerable = q.get("iss") != AS_URL
    report(
        "A[成功レスポンス]: 認可コードと一緒に iss が返るか",
        vulnerable,
        f"status={resp.status_code} code={'あり' if q.get('code') else 'なし'} iss={q.get('iss')}",
    )


def test_b_iss_in_error_response():
    """B: 拒否 (access_denied) のレスポンスにも iss が付いているか"""
    _, auth_params = start_flow_as_client()
    resp = post_authorize(auth_params, decision="deny")
    q = location_query(resp)
    vulnerable = q.get("iss") != AS_URL
    report(
        "B[エラーレスポンス]: access_denied にも iss が返るか",
        vulnerable,
        f"status={resp.status_code} error={q.get('error')} iss={q.get('iss')}",
    )


def callback_with_iss(iss: Optional[str]) -> tuple[requests.Response, bool]:
    """正規にフローを進めて code と state を手に入れ、iss だけを差し替えて /callback に渡す"""
    session, auth_params = start_flow_as_client()
    resp = post_authorize(auth_params, username=TEST_USERNAME, password=TEST_PASSWORD)
    q = location_query(resp)

    params = {"code": q.get("code", ""), "state": q.get("state", auth_params.get("state", ""))}
    if iss is not None:
        params["iss"] = iss

    cb = session.get(f"{CLIENT_URL}/callback", params=params, allow_redirects=True)
    return cb, client_session_is_logged_in(session)


def test_c_wrong_iss_on_callback():
    """C: 別の認可サーバーの iss が付いた応答を、クライアントが受け入れてしまわないか"""
    cb, logged_in = callback_with_iss(EVIL_ISSUER)
    report(
        "C[iss不一致]: 別の AS を名乗る応答で /callback が通るか",
        logged_in,
        f"callback status={cb.status_code} logged_in={logged_in}",
    )


def test_d_missing_iss_on_callback():
    """D: iss の付いていない応答を、クライアントが受け入れてしまわないか"""
    cb, logged_in = callback_with_iss(None)
    report(
        "D[iss省略]: iss の無い応答で /callback が通るか",
        logged_in,
        f"callback status={cb.status_code} logged_in={logged_in}",
    )


if __name__ == "__main__":
    print(f"=== iss (RFC 9207) テスト against AS={AS_URL} / Client={CLIENT_URL} ===\n")
    test_a_iss_in_success_response()
    test_b_iss_in_error_response()
    test_c_wrong_iss_on_callback()
    test_d_missing_iss_on_callback()

    sys.exit(summary())
