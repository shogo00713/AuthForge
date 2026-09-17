from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from pathlib import Path
import secrets
import ssl
import redis
import os

BASE_DIR = Path(__file__).parent
TEMPLATE_DIR = BASE_DIR / "templates"

# テンプレートを読み込む関数
def load_template(filename):
    path = TEMPLATE_DIR / filename

    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# 登録されているユーザー名とパスワードの辞書(デモ)
user_data = {
    "Bob": {
        "name": "Bob",
        "password": "Happy0123"
    }
}

# セッション情報を保持するRedisクライアントを作成 (辞書から移行)
redis_client = redis.Redis(
    host="redis",
    port=6379,
    decode_responses=True
)

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/login":

            html = load_template("login.html")

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            self.wfile.write(html.encode("utf-8"))


        elif self.path.startswith("/dashboard"):

            cookie = self.headers.get("Cookie")

            session_id = None

            if cookie:
                cookies = {}

                # Cookieヘッダーを解析して辞書に変換する
                for item in cookie.split(";"):
                    key, value = item.strip().split("=", 1)
                    cookies[key] = value

                session_id = cookies.get("session_id")

            user = redis_client.get(
                f"session:{session_id}"
            )

            if user:

                name = user_data[user]["name"]

                html = load_template("dashboard.html")
                html = html.replace("{user}", name)


                print(
                    "Authenticated user:", user, flush=True)

                self.send_response(200)
                self.end_headers()

                self.wfile.write(
                    html.encode("utf-8")
                )

            else:

                # 権限がないエラー
                self.send_response(401)
                self.end_headers()

                self.wfile.write(
                    b"Unauthorized"
                )

        # ログアウト処理
        elif self.path == "/logout":

            cookie = self.headers.get("Cookie")

            session_id = None

            if cookie:
                cookies = {}

                for item in cookie.split(";"):
                    key, value = item.strip().split("=", 1)
                    cookies[key] = value

                session_id = cookies.get("session_id")

            # セッションを削除
            if session_id:
                redis_client.delete(f"session:{session_id}")

            print("Session ID:", session_id, flush=True)
            print("Sessions:", redis_client.keys("session:*"), flush=True)

            html = load_template("logout.html")

            self.send_response(200)
            self.send_header("Content-Type", "text/html")

            # Cookieを失効させる
            self.send_header(
                "Set-Cookie",
                "session_id=; Max-Age=0"
            )

            self.end_headers()

            self.wfile.write(
                html.encode("utf-8")
            )


        else:
            # それ以外のエラー
            self.send_response(404)
            self.end_headers()


    def do_POST(self):

        if self.path == "/login":

            content_length = int(
                self.headers["Content-Length"]
            )

            body = self.rfile.read(
                content_length
            ).decode("utf-8")

            data = parse_qs(body)

            username = data["username"][0]
            password = data["password"][0]

            # 正しいか判定する
            if user_data.get(username) and user_data[username].get("password") == password:

                # セッションIDを生成する
                session_id = secrets.token_hex(32)
                redis_client.set(f"session:{session_id}", username)


                print("Session ID:", session_id, flush=True)
                print("Sessions:", redis_client.keys("session:*"), flush=True)

                html = load_template("success.html")

                self.send_response(200)
                self.send_header(
                    "Set-Cookie",
                    f"session_id={session_id}; Secure; HttpOnly; SameSite=Lax"
                )
                self.end_headers()

                self.wfile.write(
                    html.encode("utf-8")
                )

        elif self.path == "/change-name":

            cookie = self.headers.get("Cookie")
            session_id = None

            if cookie:
                cookies = {}

                for item in cookie.split(";"):
                    key, value = item.strip().split("=", 1)
                    cookies[key] = value

                session_id = cookies.get("session_id")

            user = redis_client.get(f"session:{session_id}")

            if user:
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length).decode("utf-8")
                data = parse_qs(body)

                name = data["name"][0]

                user_data[user]["name"] = name

                print(
                    f"Name changed: {user} -> {name}",
                    flush=True
                )

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Name changed")

        else:

            html = load_template("failed.html")

            self.send_response(401)
            self.end_headers()

            self.wfile.write(
                html.encode("utf-8")
            )


port = int(os.environ.get("PORT", "8443"))

server = ThreadingHTTPServer(("0.0.0.0", port), Handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="certs/localhost.pem",
    keyfile="certs/localhost-key.pem"
)

server.socket = context.wrap_socket(server.socket, server_side=True)

server.serve_forever()