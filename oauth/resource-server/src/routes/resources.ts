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
        const sub = tokenPayload.sub;
        const scope = tokenPayload.scope;

        // subと一致するプロフィールを1人だけ探す
        const myProfile = profiles.find((profile) => profile.id === sub);
        if (!myProfile) {
            return res.status(404).send("プロフィールが見つかりません");
        }
        const filteredProfile = filterProfileByScope(myProfile, scope);

        res.json({ profile: filteredProfile })

    } catch (error) {
        console.error(error);
        res.status(401).send("トークンの有効期限切れか、無効なトークンです");
    }
});

export default router;