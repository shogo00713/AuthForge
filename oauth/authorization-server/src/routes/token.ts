import express from "express";
import { clients } from "../config";
import { checkCodeData, deleteCodeData } from "../services/authorizationCodeStore";
import { issueAccessToken } from "../services/tokenService";

const router = express.Router();

router.post("/token", (req, res) => {

    // Basic認証の検証
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Basic ")) {
        return res.status(401).send("認証情報がありません");
    }
    const base64Credentials = authHeader.split(" ")[1];
    const credentials = Buffer.from(base64Credentials, "base64").toString("ascii");
    const [clientId, clientSecret] = credentials.split(":");
    const client = clients[clientId];

    // クライアントIDとクライアントシークレットの検証を行う
    if (!client || clientSecret !== client.client_secret) {
        return res.status(401).send("不正なクライアントです");
    }

    // Grant Type の検証
    const grantType = req.body.grant_type;
    if (grantType !== "authorization_code") {
        return res.status(400).send("不正な grant_type です");
    }

    // 認可コードの検証
    const code = req.body.code;
    if (!code) {
        return res.status(400).send("認可コードがありません");
    }

    const data = checkCodeData(code);
    if (!data) {
        return res.status(400).send("無効な認可コードです");
    }

    if(data?.client_id !== clientId || data?.redirect_uri !== req.body.redirect_uri){
        return res.status(400).send("不正な認可コードです");
    }

    // JWT形式の Access Token を発行する
    const accessToken = issueAccessToken({ sub: data.sub, scope: data.scope.join(" ") });
    
    // 認可コードを使ったので削除する
    deleteCodeData(code);

    res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600, // 1時間
    });
});

export default router;