"""
redirect_uri 検証テストの共通部品

環境変数で接続先・クライアント情報・テストユーザーを渡す。
AS_URL=http://localhost:4000 CLIENT_ID=fortune-app CLIENT_SECRET=... \
REDIRECT_URI=http://localhost:3000/callback TEST_USERNAME=Bob TEST_PASSWORD=... \
python check_redirect_uri.py
"""

import os
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


def login_and_get_code(redirect_uri: str = REDIRECT_URI, scope: str = "profile:basic") -> Optional[str]:
    """正規のユーザー認証を通して認可コードを取得する"""
    resp = authorize_post(
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        client_id=CLIENT_ID,
        redirect_uri=redirect_uri,
        response_type="code",
        scope=scope,
    )
    q = location_query(resp)
    return q.get("code")


def exchange_code(code: str, redirect_uri: str = REDIRECT_URI,
                    client_id: str = CLIENT_ID, client_secret: str = CLIENT_SECRET) -> requests.Response:
    """認可コードをアクセストークンに交換する"""
    return requests.post(
        f"{AS_URL}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
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
