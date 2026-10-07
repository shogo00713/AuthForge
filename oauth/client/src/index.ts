/**
 * クライアントのエントリーポイント
 * 
 * クライアントのエントリーポイントとなるファイルで、Expressアプリケーションを作成し、ルーティングを設定している
 */

import "dotenv/config";
import express from "express";
import authRouter from "./routes/auth";
import session from "express-session";
import { SESSION_SECRET, INSECURE } from "./config";

if (INSECURE.skipNonceCheck || INSECURE.skipAudCheck) {
    console.warn("!!! 危険: 検証を外すスイッチがオンです " + JSON.stringify(INSECURE) + " (学習用の再現専用。本番では使わないこと) !!!");
}

const app = express();
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000 },
}));
app.use(authRouter);

// ポートは環境変数で変えられる (検証スクリプトが、別ポートでテスト用のクライアントを起動するため)
const PORT = Number(process.env.PORT ?? 3000);

app.listen(PORT, () => {
    console.log(`Auth Client is running on http://localhost:${PORT}`);
});