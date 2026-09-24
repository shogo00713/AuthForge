/**
 * クライアントのエントリーポイント
 * 
 * クライアントのエントリーポイントとなるファイルで、Expressアプリケーションを作成し、ルーティングを設定している
 */

import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import authRouter from "./routes/auth";

const app = express();
app.use(cookieParser());
app.use(authRouter);

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`Auth Client is running on http://localhost:${PORT}`);
});