import express from "express";
import jwt from "jsonwebtoken";
import path from "path";

const app = express();
app.use(express.json());
app.use(express.static(path.join(process.cwd(), "../public")));

const PORT = 3000;

// JWTの秘密鍵(学習用なのでハードコードだが、実際は環境変数必須)
const JWT_SECRET = "my_jwt_secret_key";

// いつものデモ用ユーザー情報
const user = {
    username: "Bob",
    password: "Happy0123",
}

// ログイン用のエンドポイント
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    // ユーザー名とパスワードが一致するか確認
    if (username !== user.username || password !== user.password) {
        return res.status(401).json({
            message: "不正なユーザー名またはパスワードです。",
        });
    }

    // ==============================
    // JWTを発行する
    // ==============================
    const token = jwt.sign(
        {
            sub: username,
            role: "topadmin",
        },
        JWT_SECRET,
        {
            algorithm: "HS256",
            expiresIn: "1h",
        }
    );

    res.json({
        token
    });
});


// JWTを持っている人だけ入れる /me エンドポイント
app.get("/me", (req, res) => {
    const authHEader = req.headers.authorization;

    // Authorizationヘッダーがない場合は401
    if (!authHEader) {
        return res.status(401).json({
            message: "Authorizationヘッダーがありません。",
        });
    }

    // shceme : 方式でBearerが期待される
    // token  : 実際のJWTトークン
    const [shceme, token] = authHEader.split(" ");

    // Bearerスキームじゃない場合は401
    if (shceme !== "Bearer") {
        return res.status(401).json({
            message: "Authorizationヘッダーのスキームが不正です。",
        });
    }

    try {
        // JWTを検証する
        const payload = jwt.verify(token, JWT_SECRET, {
            algorithms: ["HS256"], // 署名アルゴリズムはHS256で固定する
        });

        return res.json({
            message: "JWTの検証に成功しました。",
            user: payload // JWTのペイロードを返す
        });
    } catch (err) {
        return res.status(401).json({
            message: "JWTの検証に失敗しました。",
        });
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});