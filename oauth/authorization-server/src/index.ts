/**
 * 認可サーバーのエントリーポイント
 * 
 * 認可サーバーのエントリーポイントとなるファイルで、Expressアプリケーションを作成し、ルーティングを設定している
 */
import "dotenv/config";
import express from "express";
import authRouter from "./routes/authorize";
import tokenRouter from "./routes/token";
import jwksRouter from "./routes/jwks";
import userinfoRouter from "./routes/userinfo";
import discoveryRouter from "./routes/discovery";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(authRouter);
app.use(tokenRouter);
app.use(jwksRouter);
app.use(userinfoRouter);
app.use(discoveryRouter);
const PORT = 4000;


app.get("/", (req, res) => {
    // 動作確認用
    res.send("Auth Server is running");
});

app.listen(PORT, () => {
    console.log(`Auth Server is running on http://localhost:${PORT}`);
});
