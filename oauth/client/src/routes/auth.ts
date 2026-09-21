import express from "express"
import { fortuneApp, AUTH_SERVER_URL } from "../config";
import exchangeCodeForToken from "../services/oauthclient";

const router = express.Router();


// ログイン時に認可サーバーの認可エンドポイントにリダイレクトする処理
router.get("/login", (_, res) => {

    // URLを構築する
    const autorizeUrl = new URL("/authorize", AUTH_SERVER_URL);
    autorizeUrl.searchParams.append("client_id", fortuneApp.client_id);
    autorizeUrl.searchParams.append("redirect_uri", fortuneApp.redirect_uris[0]);
    autorizeUrl.searchParams.append("response_type", "code");
    autorizeUrl.searchParams.append("scope", fortuneApp.scope);

    res.redirect(autorizeUrl.toString());
});


// 認可サーバーから認可コードを受け取り、Access Token に交換する処理
router .get("/callback", async (req, res) => {

    const  code = req.query.code as string;

    // 認可コードを取得できなかった場合
    if(!code){
        return res.status(400).send("認可コードが取得できませんでした");
    }
    // 認可コードと Access Token の交換を試みる
    try {
        const token = await exchangeCodeForToken(code);
        res.send(`Access Token: ${token}`);
    } catch (error) {
        res.status(500).send("Access token の交換に失敗しました");
    }

});


export default router;
