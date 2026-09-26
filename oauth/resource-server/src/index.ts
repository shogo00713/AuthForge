/**
 * リソースサーバーのエントリーポイント
 * 
 * このファイルは、リソースサーバーのエントリーポイントとなるファイルで、Expressアプリケーションを作成し、ルーティングを設定している
 */

import "dotenv/config";
import express from "express";
import resourcesRouter from "./routes/resources";

const app = express();
app.use(resourcesRouter);
const PORT = 4001;


app.get("/", (req, res) => {
    // 動作確認用
    res.send("Resource Server is running");
});

app.listen(PORT, () => {
    console.log("Resource Server is running on http://localhost:" + PORT);
});
