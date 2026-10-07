/**
 * リソースサーバーのエントリーポイント
 * 
 * このファイルは、リソースサーバーのエントリーポイントとなるファイルで、Expressアプリケーションを作成し、ルーティングを設定している
 */

import "dotenv/config";
import express from "express";
import resourcesRouter from "./routes/resources";
import { INSECURE_SKIP_AUD_CHECK } from "./config";

if (INSECURE_SKIP_AUD_CHECK) {
    console.warn("!!! 危険: audience を検証しないスイッチがオンです (学習用の再現専用。本番では使わないこと) !!!");
}

const app = express();
app.use(resourcesRouter);
// ポートは環境変数で変えられる (検証スクリプトが、別ポートでテスト用のリソースサーバーを起動するため)
const PORT = Number(process.env.PORT ?? 4001);


app.get("/", (req, res) => {
    // 動作確認用
    res.send("Resource Server is running");
});

app.listen(PORT, () => {
    console.log("Resource Server is running on http://localhost:" + PORT);
});
