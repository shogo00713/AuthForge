import express from "express";
import { clients } from "../config";
import crypto from "crypto";
import { generateAuthCodeData, saveCodeData } from "../services/authorizationCodeStore";

const router = express.Router();

// 認可エンドポイント
router.get("/authorize", async (req, res) => {

    // クエリパラメータから必要な情報を取得する
    const { client_id, redirect_uri, response_type, scope } = req.query;

    // クライアントが存在するか確認する
    const client = clients[client_id as string];
    if (!client) {
        return res.status(400).send("不正なクライアントです");
        // 絶対にリダイレクトしない
    }

    // リダイレクトURIが一致するか確認する (完全一致で検証)
    if (!client.redirect_uris.includes(redirect_uri as string)) {
        return res.status(400).send("不正なリダイレクトURIです");
    }

    // --- これ以降のエラーはリダイレクトURIに伝える ---

    // Authorization Code Grant 以外はお断り
    if (response_type !== "code") {
        const errorUrl = new URL(redirect_uri as string);
        errorUrl.searchParams.append("error", "unsupported_response_type");
        return res.redirect(errorUrl.toString());
    }

    // スコープが正当なものか確認する
    if (!scope || typeof scope !== "string" || scope.split(" ").some(s => !client.allowed_scopes.includes(s))) {
        const errorUrl = new URL(redirect_uri as string);
        errorUrl.searchParams.append("error", "invalid_scope");
        return res.redirect(errorUrl.toString());
    }

    try{
        // 認可コードを生成する
        const code = crypto.randomBytes(32).toString("hex");
        const codeData = generateAuthCodeData(client_id as string, redirect_uri as string, (scope as string).split(" "));

        // 認可コード・クライアントID・リダイレクトURI・スコープ・有効期限 を一時保存する
        await saveCodeData(code, codeData);

        // redirect_uriに認可コードを付与してリダイレクトする
        const redirectUrl = new URL(redirect_uri as string);
        redirectUrl.searchParams.append("code", code);
        res.redirect(redirectUrl.toString());
    } catch (error) {
        console.error(error);
        return res.status(500).send("サーバーエラーが発生しました");
    }

});

export default router;