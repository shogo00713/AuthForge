/**
 * トークンエンドポイント
 * 
 * 認可サーバーのトークンエンドポイントを実装している
 * POST : 認可コードを受け取り、アクセストークンとリフレッシュトークンを発行するか、もしくはリフレッシュトークンを受け取り、アクセストークンを発行する
 * その操作は grantType によって切り替えている
 */

import express from "express";
import { clients, ACCESS_TOKEN_EXPIRES_IN } from "../config";
import { checkCodeData, deleteCodeData } from "../services/authorizationCodeStore";
import { generateRefreshTokenData, checkRefreshTokenData, saveRefreshTokenData, deleteRefreshTokenData } from "../services/refreshTokenStore";
import { issueAccessToken, issueRefreshToken } from "../services/tokenService";
import crypto from "crypto";

const router = express.Router();

router.post("/token", (req, res) => {

    const body = req.body ?? {};

    // Basic認証でクライアント認証
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Basic ")) {
        return res
        .status(401)
        // クライアント認証失敗 (RFC 6749 3.2.1 / 5.2 参照)
        .set("WWW-Authenticate", 'Basic realm="token"')
        .json({ error: "invalid_client", error_description: "認証情報がありません" });
    }
    const base64Credentials = authHeader.split(" ")[1];
    const credentials = Buffer.from(base64Credentials, "base64").toString("utf-8");
    const [clientId, clientSecret] = credentials.split(":");
    const client = clients[clientId];

    // クライアントIDとクライアントシークレットの検証を行う
    if (!client || clientSecret !== client.client_secret) {
        // クライアント認証が失敗した場合は401を返し、WWW-Authenticateヘッダーで認証方式(Basic)を示す
        return res
            .status(401)
            .set("WWW-Authenticate", 'Basic realm="token"')
            .json({ error: "invalid_client", error_description: "不正なクライアントです" });
    }

    // 認可コードに基づくアクセストークンの発行
    const grantType = body.grant_type;
    if (grantType === "authorization_code") {

        // 認可コードの検証
        const code = body.code;
        if (!code) {
            // 認可コードがない
            return res.status(400).json({ error: "invalid_request", error_description: "認可コードがありません" });
        }

        const data = checkCodeData(code);
        if (!data) {
            // 認可コードが存在しない
            return res.status(400).json({ error: "invalid_grant", error_description: "無効な認可コードです" });
        }

        if(data?.client_id !== clientId || data?.redirect_uri !== body.redirect_uri){
            // クライアントが登録情報と一致しない
            return res.status(400).json({ error: "invalid_grant", error_description: "不正な認可コードです" });
        }

        const codeVerifier = body.code_verifier;
        if (!codeVerifier) {
            return res.status(400).json({ error: "invalid_request", error_description: "code_verifierがありません" });
        }
        const expectedChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");  // S256限定
        if (expectedChallenge !== data.code_challenge) {
            return res.status(400).json({ error: "invalid_grant", error_description: "code_verifierが不正です" });
        }

        // JWT形式の Access Token を発行する
        const accessToken = issueAccessToken({ sub: data.sub, scope: data.scope.join(" ") });
        // New!! JWT形式の Refresh Token を発行する
        const refreshToken = issueRefreshToken();

        // リフレッシュトークンの情報を保存する
        const refreshTokenData = generateRefreshTokenData(clientId, data.scope, data.sub);
        saveRefreshTokenData(refreshToken, refreshTokenData);

        // 認可コードを使ったので削除する
        deleteCodeData(code);

        return res
            .set("Cache-Control", "no-store")
            .set("Pragma", "no-cache")
            .json({
                access_token: accessToken,
                token_type: "Bearer",
                expires_in: ACCESS_TOKEN_EXPIRES_IN,
                refresh_token: refreshToken
        });
    }

    // リフレッシュトークンに基づくアクセストークンの発行
    else if (grantType === "refresh_token") {

        const refreshToken = body.refresh_token;
        if (!refreshToken) {
            return res.status(400).json({ error: "invalid_request", error_description: "リフレッシュトークンがありません" });
        }

        const data = checkRefreshTokenData(refreshToken);
        if (!data) {
            return res.status(400).json({ error: "invalid_grant", error_description: "無効なリフレッシュトークンです" });
        }

        if(data?.client_id !== clientId){
            return res.status(400).json({ error: "invalid_grant", error_description: "不正なリフレッシュトークンです" });
        }

        // JWT形式の Access Token を発行する
        const accessToken = issueAccessToken({ sub: data.sub, scope: data.scope.join(" ") });

        // new!! リフレッシュトークンローテーション
        const newRefreshToken = issueRefreshToken();
        const newRefreshTokenData = generateRefreshTokenData(clientId, data.scope, data.sub);
        saveRefreshTokenData(newRefreshToken, newRefreshTokenData);
        deleteRefreshTokenData(refreshToken);  // 古い方は消す

        return res
            .set("Cache-Control", "no-store")
            .set("Pragma", "no-cache")
            .json({
                access_token: accessToken,
                token_type: "Bearer",
                expires_in: ACCESS_TOKEN_EXPIRES_IN,
                // new !! リフレッシュトークンローテーション
                refresh_token: newRefreshToken 
        });
    }

    else {
        return res.status(400).json({ error: "unsupported_grant_type", error_description: "サポートされていない grant_type です" });
    }

});

export default router;