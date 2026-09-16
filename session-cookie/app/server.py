from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import secrets

# 登録されているユーザー名とパスワードの辞書(デモ)
USERS = {
    "Bob": "Happy0123"
}

# セッション情報を保持する辞書
sessions = {}

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/login":

            html = """
            <!DOCTYPE html>
            <html>
            <body>
                <h1>Login</h1>

                <form method="POST" action="/login">
                    <label>
                        Username:
                        <input type="text" name="username">
                    </label>

                    <br>

                    <label>
                        Password:
                        <input type="password" name="password">
                    </label>

                    <br>

                    <button type="submit">Login</button>
                </form>

            </body>
            </html>
            """

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            self.wfile.write(html.encode("utf-8"))

        else:
            # エラー時
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

                self.send_response(200)
                self.end_headers()

                self.wfile.write(
                    b"Login successful!"
                )

            else:

                self.send_response(401)
                self.end_headers()

                self.wfile.write(
                    b"Login failed!"
                )


server = HTTPServer(
    ("0.0.0.0", 8080),
    Handler
)

server.serve_forever()