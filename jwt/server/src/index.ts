import express from "express";
import jwt from "jsonwebtoken";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const app = express();
app.use(express.json());
app.use(express.static(path.join(process.cwd(), "../public")));

const PORT = 3000;

// JWTの秘密鍵(学習用なのでハードコードだが、実際は環境変数必須)
const JWT_SECRET = "my_jwt_secrets_key_Bob_Happy0123";

// いつものデモ用ユーザー情報
const user = {
    username: "Bob",
    password: "Happy0123",
}

// 公開鍵と秘密鍵
const PRIVATE_KEY = fs.readFileSync(
    path.join(process.cwd(), "keys/private.pem"),
    "utf8"
);

const PUBLIC_KEY = fs.readFileSync(
    path.join(process.cwd(), "keys/public.pem"),
    "utf8"
);



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

// 脆弱なエンドポイントの例
app.get("/me-vulnerable", (req, res) => {
    const authHeader = req.headers.authorization;

    // Authorizationヘッダーがない場合は401
    if (!authHeader) {
        return res.status(401).json({
            message: "Authorization header is required",
        });
    }

    // AuthorizationヘッダーからJWTを取得
    const [, token] = authHeader.split(" ");

    try {
        // わざと alg: none を許可
        const payload = jwt.verify(token, "", {
            algorithms: ["none"],
        });

        return res.json({
            message: "JWTの検証に成功しました。",
            user: payload,
        });
    } catch {
        return res.status(401).json({
            message: "JWTの検証に失敗しました。",
        });
    }
});

// RS256署名のJWTを発行するエンドポイント
app.post("/login-rs256", (req, res) => {
    const { username, password } = req.body;

    if (username !== "Bob" || password !== "Happy0123") {
        return res.status(401).json({
            message: "認証に失敗しました。",
        });
    }

    const token = jwt.sign(
        {
            sub: username,
            role: "user",
        },
        PRIVATE_KEY,
        {
            algorithm: "RS256",
            expiresIn: "1h",
        }
    );

    return res.json({ token });
});

// RS256署名のJWTを検証するエンドポイント
app.get("/me-rs256", (req, res) => {
    const authHeader = req.headers.authorization;

    // Authorizationヘッダーがない場合は401
    if (!authHeader) {
        return res.status(401).json({
            message: "Authorization header is required",
        });
    }

    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({
            message: "Invalid Authorization header",
        });
    }

    try {
        const payload = jwt.verify(token, PUBLIC_KEY, {
            algorithms: ["RS256"], // 署名アルゴリズムはRS256で固定する(正しい実装)
        });

        return res.json({
            message: "JWTの検証に成功しました。",
            user: payload,
        });
    } catch {
        return res.status(401).json({
            message: "JWTの検証に失敗しました。",
        });
    }
});

// RS256署名のJWTを検証する脆弱なエンドポイント
// 署名アルゴリズムが、固定ではなく、JWTのヘッダーに書かれたalgの値によって切り替わる
app.get("/me-rs256-vulnerable", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            message: "Authorization header is required",
        });
    }

    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({
            message: "Invalid Authorization header",
        });
    }

    try {
        const [encodedHeader, encodedPayload, encodedSignature] =
            token.split(".");

        const header = JSON.parse(
            Buffer.from(encodedHeader, "base64url").toString()
        );

        const signingInput = `${encodedHeader}.${encodedPayload}`;

        let valid = false;

        // わざと alg の値によって検証方法を切り替える
        if (header.alg === "RS256") {
            const verifier = crypto.createVerify("RSA-SHA256");

            verifier.update(signingInput);
            verifier.end();

            valid = verifier.verify(
                PUBLIC_KEY,
                Buffer.from(encodedSignature, "base64url")
            );
        }

        if (header.alg === "HS256") {
            const expectedSignature = crypto
                .createHmac("sha256", PUBLIC_KEY)
                .update(signingInput)
                .digest();

            valid = crypto.timingSafeEqual(
                expectedSignature,
                Buffer.from(encodedSignature, "base64url")
            );
        }

        if (!valid) {
            return res.status(401).json({
                message: "JWTの検証に失敗しました。",
            });
        }

        const payload = JSON.parse(
            Buffer.from(encodedPayload, "base64url").toString()
        );

        return res.json({
            message: "JWTの検証に成功しました。",
            user: payload,
        });
    } catch {
        return res.status(401).json({
            message: "JWTの検証に失敗しました。",
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});