/**
 * クライアントのエントリーポイント
 * 
 * クライアントのエントリーポイントとなるファイルで、Expressアプリケーションを作成し、ルーティングを設定している
 */

import "dotenv/config";
import express from "express";
import authRouter from "./routes/auth";
import session from "express-session";
import { SESSION_SECRET } from "./config";

const app = express();
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000 },
}));
app.use(authRouter);

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`Auth Client is running on http://localhost:${PORT}`);
});