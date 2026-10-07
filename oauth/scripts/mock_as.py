"""
モック認可サーバー (OIDC 編 5-D / 6 の検証用)

クライアントの検証ロジックを、本物のクライアントのコードのまま確かめるための部品。
クライアントは IDトークンを、サーバー間通信 (トークンエンドポイント) で受け取るので、
外から細工したトークンを渡せない。そこで、クライアントを「偽の認可サーバー」に向けて起動し、
シナリオごとに細工したトークンを返させる。

  MockAS        : 偽の認可サーバー (Discovery / JWKS / token / userinfo だけ持つ)
                  自前の RSA 鍵で署名する。本物の認可サーバーとは無関係
  start_client  : 偽の認可サーバーを向いたテスト用クライアントを、別ポートで起動する
                  (起動中の 3000 番のクライアントとはぶつからない)

  pip install requests cryptography
"""

import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs

import requests

from common import b64url, forge_jwt

MOCK_KID = "mock-key-1"
CLIENT_DIR = os.environ.get("CLIENT_DIR", "../client")


def _int_to_b64url(n: int) -> str:
    return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class _DualStackServer(HTTPServer):
    """localhost が ::1 に解決されても繋がるよう、IPv4 / IPv6 の両方で待ち受ける"""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class MockAS:
    """偽の認可サーバー

    advertised_issuer: Discovery の issuer として名乗る値 (省略時は自分のURL)。
                       クライアントの期待値とわざとずらすと、issuer 不一致の確認ができる
    """

    def __init__(self, port: int, advertised_issuer: Optional[str] = None):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.port = port
        self.base_url = f"http://localhost:{port}"
        self.issuer = advertised_issuer or self.base_url
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # 攻撃者の鍵
        self.public_pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.scenarios: dict = {}
        self.userinfo_calls = 0
        self._server: Optional[HTTPServer] = None

    # --- 署名 ---
    def sign(self, claims: dict, **kwargs) -> str:
        """モックの鍵で署名した JWT を作る (alg / kid / key / secret は forge_jwt に渡せる)"""
        kwargs.setdefault("kid", MOCK_KID)
        kwargs.setdefault("key", self.key)
        return forge_jwt(claims, **kwargs)

    def jwks(self) -> dict:
        nums = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "n": _int_to_b64url(nums.n), "e": _int_to_b64url(nums.e),
                          "alg": "RS256", "use": "sig", "kid": MOCK_KID}]}

    def discovery(self) -> dict:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.base_url}/authorize",
            "token_endpoint": f"{self.base_url}/token",
            "userinfo_endpoint": f"{self.base_url}/userinfo",
            "jwks_uri": f"{self.base_url}/jwks.json",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    # --- シナリオ: 認可コードごとに、トークンエンドポイントが返す内容を決める ---
    def register(self, code: str, id_token: Optional[str], userinfo_sub: Optional[str] = "u01",
                 userinfo_status: int = 200):
        self.scenarios[code] = {"id_token": id_token, "userinfo_sub": userinfo_sub,
                                "userinfo_status": userinfo_status}

    # --- サーバーの起動・停止 ---
    def start(self):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # 標準出力を汚さない
                pass

            def _send(self, status: int, body: dict):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/.well-known/openid-configuration":
                    return self._send(200, mock.discovery())
                if path == "/jwks.json":
                    return self._send(200, mock.jwks())
                if path == "/userinfo":
                    mock.userinfo_calls += 1
                    auth = self.headers.get("Authorization", "")
                    code = auth.removeprefix("Bearer mock-at-") if auth.startswith("Bearer mock-at-") else None
                    scenario = mock.scenarios.get(code or "")
                    if not scenario:
                        return self._send(401, {"error": "invalid_token"})
                    if scenario["userinfo_status"] != 200:
                        return self._send(scenario["userinfo_status"], {"error": "invalid_token"})
                    return self._send(200, {"sub": scenario["userinfo_sub"], "preferred_username": "mock-user"})
                self._send(404, {"error": "not_found"})

            def do_POST(self):
                if self.path.split("?")[0] != "/token":
                    return self._send(404, {"error": "not_found"})
                length = int(self.headers.get("Content-Length", 0))
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
                scenario = mock.scenarios.get(form.get("code", ""))
                if form.get("grant_type") != "authorization_code" or not scenario:
                    return self._send(400, {"error": "invalid_grant"})
                body = {"access_token": f"mock-at-{form['code']}", "token_type": "Bearer",
                        "expires_in": 10, "refresh_token": f"mock-rt-{form['code']}"}
                if scenario["id_token"] is not None:
                    body["id_token"] = scenario["id_token"]
                self._send(200, body)

        self._server = _DualStackServer(("::", self.port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()


class TestClient:
    """偽の認可サーバーを向いて起動した、テスト用のクライアントのプロセス"""

    def __init__(self, port: int, auth_server_url: str):
        self.port = port
        self.url = f"http://localhost:{port}"
        self.auth_server_url = auth_server_url
        self.log = tempfile.NamedTemporaryFile(prefix=f"client-{port}-", suffix=".log", delete=False)
        self._log_offset = 0
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        # .env の値は dotenv が上書きしないので、ここで渡した環境変数が優先される
        env = {**os.environ, "PORT": str(self.port), "AUTH_SERVER_URL": self.auth_server_url,
               "REDIRECT_URI": f"{self.url}/callback"}
        self._proc = subprocess.Popen(
            [os.path.join(CLIENT_DIR, "node_modules/.bin/tsx"), "src/index.ts"],
            cwd=CLIENT_DIR, env=env, stdout=self.log, stderr=subprocess.STDOUT,
            start_new_session=True,  # 後で、このプロセスだけをまとめて止められるように
        )
        for _ in range(60):
            if self._proc.poll() is not None:
                raise RuntimeError(f"テスト用クライアントが起動直後に終了しました。ログ: {self.log.name}")
            try:
                requests.get(self.url + "/", timeout=1)
                return
            except requests.RequestException:
                time.sleep(0.25)
        raise RuntimeError(f"テスト用クライアントが起動しませんでした。ログ: {self.log.name}")

    def stop(self):
        if self._proc and self._proc.poll() is None:
            os.killpg(self._proc.pid, signal.SIGTERM)  # このスクリプトが起動したプロセスだけを止める
            self._proc.wait(timeout=5)

    def new_log_errors(self) -> list:
        """前回から増えたログのうち、Error: で終わる名前で始まる行 (弾いた理由) を返す
        (Error: / JsonWebTokenError: / TokenExpiredError: など)"""
        with open(self.log.name, "r", errors="replace") as f:
            f.seek(self._log_offset)
            text = f.read()
            self._log_offset = f.tell()
        return [line.strip() for line in text.splitlines() if re.match(r"^\w*Error:", line)]
