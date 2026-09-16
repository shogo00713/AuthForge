from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from pathlib import Path
import secrets
import ssl

BASE_DIR = Path(__file__).parent
TEMPLATE_DIR = BASE_DIR / "templates"

# テンプレートを読み込む関数
def load_template(filename):
    path = TEMPLATE_DIR / filename

    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# 登録されているユーザー名とパスワードの辞書(デモ)
USERS = {
    "Bob": "Happy0123"
}

# セッション情報を保持する辞書
sessions = {}

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

            user = sessions.get(session_id)

            if user:

                # URLパラメータからユーザー名をいじれるようにする
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                name = params.get("name", [user])[0]

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
            if session_id in sessions:
                del sessions[session_id]

            print("Session ID:", session_id, flush=True)
            print("Sessions:", sessions, flush=True)

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
            if USERS.get(username) == password:

                # セッションIDを生成する
                session_id = secrets.token_hex(32)
                sessions[session_id] = username


                print("Session ID:", session_id, flush=True)
                print("Sessions:", sessions, flush=True)

                html = load_template("success.html")

                self.send_response(200)
                self.send_header(
                    "Set-Cookie",
                    f"session_id={session_id}; Secure; HttpOnly"
                )
                self.end_headers()

                self.wfile.write(
                    html.encode("utf-8")
                )

            else:

                html = load_template("failed.html")

                self.send_response(401)
                self.end_headers()

                self.wfile.write(
                    html.encode("utf-8")
                )


server = HTTPServer(("0.0.0.0", 8443), Handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="certs/localhost.pem",
    keyfile="certs/localhost-key.pem"
)

server.socket = context.wrap_socket(server.socket, server_side=True)

server.serve_forever()