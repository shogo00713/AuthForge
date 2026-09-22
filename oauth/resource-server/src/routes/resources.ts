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
        return res.status(401).send("認証情報がありません");
    }

    // Bearer認証か確認する
    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).send("対応していない認証方式です");
    }

    const token = authHeader.split(" ")[1];

    // トークンが存在するか確認する
    if (!token) {
        return res.status(401).send("認証トークンがありません");
    }

    try {
        const tokenPayload = verifyAccessToken(token);
        const scope = tokenPayload.scope;

        // 現状は全てのプロフィールデータを返す
        // 後に、ログイン時にアカウント名からプロフィールを特定するように変更する
        const filteredProfile = profiles.map((profile) => filterProfileByScope(profile, scope));

        res.json({ profiles: filteredProfile })

    } catch (error) {
        console.error(error);
        res.status(401).send("トークンの有効期限切れか、無効なトークンです");
    }
});

export default router;