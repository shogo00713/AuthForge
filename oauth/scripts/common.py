"""
redirect_uri 検証テストの共通部品

環境変数で接続先・クライアント情報・テストユーザーを渡す。
AS_URL=http://localhost:4000 CLIENT_ID=fortune-app CLIENT_SECRET=... \
REDIRECT_URI=http://localhost:3000/callback TEST_USERNAME=Bob TEST_PASSWORD=... \
python check_redirect_uri.py
"""

import base64
import hashlib
import os
import secrets
from typing import Optional
from urllib.parse import urlparse, parse_qs

import requests

AS_URL = os.environ.get("AS_URL", "http://localhost:4000")
CLIENT_URL = os.environ.get("CLIENT_URL", "http://localhost:3000")
CLIENT_ID = os.environ.get("CLIENT_ID", "fortune-app")
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:3000/callback")
TEST_USERNAME = os.environ["TEST_USERNAME"]
TEST_PASSWORD = os.environ["TEST_PASSWORD"]
EVIL_URL = os.environ.get("EVIL_URL", "https://evil.example/cb")

# 結果の集計
_results = []


def report(name: str, vulnerable: bool, detail: str = ""):
    status = "VULNERABLE" if vulnerable else "SAFE"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))
    _results.append(vulnerable)


def summary():
    print("\n--- summary ---")
    total = len(_results)
    bad = sum(_results)
    print(f"{bad}/{total} VULNERABLE")
    return 1 if bad else 0


def authorize_get(**params) -> requests.Response:
    """GET /authorize を叩く(リダイレクトは追わない)"""
    return requests.get(f"{AS_URL}/authorize", params=params, allow_redirects=False)


def authorize_post(**form) -> requests.Response:
    """POST /authorize を叩く(リダイレクトは追わない)"""
    return requests.post(f"{AS_URL}/authorize", data=form, allow_redirects=False)


def location_host(resp: requests.Response) -> Optional[str]:
    """Location ヘッダーのホスト名だけ取り出す(無ければ None)"""
    loc = resp.headers.get("Location")
    if not loc:
        return None
    return urlparse(loc).netloc


def location_query(resp: requests.Response) -> dict:
    """Location ヘッダーのクエリパラメータを dict で取り出す"""
    loc = resp.headers.get("Location")
    if not loc:
        return {}
    return {k: v[0] for k, v in parse_qs(urlparse(loc).query).items()}


def login_and_get_code(redirect_uri: str = REDIRECT_URI, scope: str = "profile:basic",
                        **extra_params) -> Optional[str]:
    """正規のユーザー認証を通して認可コードを取得する
    extra_params で code_challenge / code_challenge_method などを追加できる"""
    resp = authorize_post(
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        client_id=CLIENT_ID,
        redirect_uri=redirect_uri,
        response_type="code",
        scope=scope,
        **extra_params,
    )
    q = location_query(resp)
    return q.get("code")


def exchange_code(code: str, redirect_uri: str = REDIRECT_URI,
                    client_id: str = CLIENT_ID, client_secret: str = CLIENT_SECRET,
                    **extra_params) -> requests.Response:
    """認可コードをアクセストークンに交換する
    extra_params で code_verifier などを追加できる"""
    return requests.post(
        f"{AS_URL}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            **extra_params,
        },
        auth=(client_id, client_secret),
    )


# --- PKCE (RFC 7636) のテスト用ヘルパー ---

def generate_code_verifier() -> str:
    """RFC 7636: 43〜128文字、[A-Za-z0-9-._~] のランダム値"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def code_challenge_s256(verifier: str) -> str:
    """code_challenge_method=S256: SHA256 したものを base64url エンコード(パディング無し)"""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def login_and_get_tokens(redirect_uri: str = REDIRECT_URI, scope: str = "profile:basic") -> Optional[dict]:
    """正規のログイン〜PKCE付き認可コード交換までを一通り行い、
    access_token / refresh_token を含むレスポンスJSONを返す(失敗時は None)"""
    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)

    code = login_and_get_code(redirect_uri=redirect_uri, scope=scope, code_challenge=challenge)
    if not code:
        return None

    resp = exchange_code(code, redirect_uri=redirect_uri, code_verifier=verifier)
    if resp.status_code != 200:
        return None
    return resp.json()


def refresh_token_exchange(refresh_token: str, client_id: str = CLIENT_ID,
                            client_secret: str = CLIENT_SECRET) -> requests.Response:
    """refresh_token を使ってアクセストークンを更新する"""
    return requests.post(
        f"{AS_URL}/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        auth=(client_id, client_secret),
    )


def client_session_is_logged_in(session: requests.Session) -> bool:
    """クライアントアプリの '/' を見て、そのセッションがログイン済み(アクセストークンを保持)かを判定する"""
    resp = session.get(f"{CLIENT_URL}/", allow_redirects=True)
    return "/logout" in resp.text


def decode_jwt_payload(token: str) -> dict:
    import base64
    import json

    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    decoded = base64.urlsafe_b64decode(payload_b64 + padding)
    return json.loads(decoded)
