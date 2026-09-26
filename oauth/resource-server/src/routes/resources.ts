/**
 * リソースサーバーのリソース提供用のルーティング
 * 
 * このファイルは、リソースサーバーが提供するリソースにアクセスするためのルーティングを定義している
 * アクセストークンの検証とスコープに基づくフィルタリングを行い、適切なレスポンスを返す
 */

import express from "express";
import { verifyAccessToken } from "../services/verifyToken";
import { filterProfileByScope } from "../services/scopeFilter";
import { profiles } from "../data/data";

const router = express.Router();

// プロフィールデータにアクセスするためのエンドポイント
router.get("/resources", (req, res) => {

    const authHeader = req.headers.authorization;

    // Authorizationヘッダーが存在するか確認する
    if (!authHeader) {
        return res
        .status(401)
        // 認証情報がなかった (RFC 6750 3.1 参照)
        .set("WWW-Authenticate", 'Bearer')
        .end();
    }

    // Bearer認証か確認する
    if (!authHeader.startsWith("Bearer ")) {
        return res
        .status(401)
        // Bearer認証ではなかった
        .set("WWW-Authenticate", 'Bearer')
        .end();
    }

    const token = authHeader.split(" ")[1];

    // トークンが存在するか確認する
    if (!token) {
        return res
        .status(400)
        // トークンがなかった
        .set("WWW-Authenticate", 'Bearer error="invalid_request", error_description="No token provided"')
        .json({ error: "invalid_request", error_description: "トークンがありません" });
    }

    try {
        const tokenPayload = verifyAccessToken(token);
        const sub = tokenPayload.sub;
        const scope = tokenPayload.scope;

        // subと一致するプロフィールを1人だけ探す
        const myProfile = profiles.find((profile) => profile.id === sub);
        if (!myProfile) {
            // プロフィールが見つからない場合は404を返す(これだけはアプリ側の責務)
            return res.status(404).send("プロフィールが見つかりません");
        }
        const filteredProfile = filterProfileByScope(myProfile, scope);

        res.json({ profile: filteredProfile })

    } catch (error) {
        console.error(error);
        res.status(401)
        // トークンがうまく検証できなかった
        .set("WWW-Authenticate", 'Bearer error="invalid_token", error_description="The access token expired or is invalid"')
        .json({ error: "invalid_token", error_description: "トークンの有効期限切れか、無効なトークンです" });
    }
});

export default router;