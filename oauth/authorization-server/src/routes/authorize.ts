/**
 * 認可エンドポイント
 *
 * 認可サーバーの認可エンドポイントを実装している
 * GET : ユーザーに同意を求める画面を表示する
 * POST : ユーザーの同意を受け取り、認可コードを発行する
 */

import express from "express";
import { AUTH_SERVER_URL } from "../config";
import crypto from "crypto";
import { generateAuthCodeData, saveCodeData } from "../services/authorizationCodeStore";
import fs from "fs";
import { verifyCredentials } from "../services/verifyCredentials";
import { validateAuthorizeRequest, str, type AuthorizeParams, type AuthorizeResult } from "../services/authorizeRequest";

const router = express.Router();

// HTMLエスケープヘルパー関数
function escapeHtml(s: string): string {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// リクエスト (query / body) から検証対象のパラメータを取り出す
function pickParams(src: Record<string, unknown>): AuthorizeParams {
    return {
        client_id      : str(src.client_id),
        redirect_uri   : str(src.redirect_uri),
        response_type  : str(src.response_type),
        scope          : str(src.scope),
        state          : str(src.state),
        code_challenge : str(src.code_challenge),
    };
}

// 検証エラーを返す共通処理 (fatal は画面に表示、redirect は redirect_uri にエラーを付けて返す)
function respondError(res: express.Response, r: Extract<AuthorizeResult, { ok: false }>, params: AuthorizeParams) {
    if (r.kind === "fatal") {
        return res.status(400).send(r.message);
        // 絶対にリダイレクトしない
    }
    return res.redirect(buildAuthorizationResponseUrl(params, {
        error: r.error,
        ...(r.description ? { error_description: r.description } : {}),
    }));
}

// 認可レスポンスのURLを組み立てる
function buildAuthorizationResponseUrl(params: AuthorizeParams, extra: Record<string, string>): string {
    const url = new URL(params.redirect_uri);
    for (const [key, value] of Object.entries(extra)) {
        url.searchParams.append(key, value);
    }
    if (params.state) url.searchParams.append("state", params.state);
    url.searchParams.append("iss", AUTH_SERVER_URL);
    return url.toString();
}

// 認可エンドポイント -> GETとPOSTに分ける
// GET : ユーザーに同意を求める画面を表示する
router.get("/authorize", async (req, res) => {

    const params = pickParams(req.query);

    // GET と POST で共通の検証を行う
    const result = validateAuthorizeRequest(params);
    if (!result.ok) return respondError(res, result, params);

    // 同意を求める画面を表示する
    const html = fs.readFileSync(__dirname + "/../views/index.html", "utf-8");
    const values: Record<string, string> = { ...params };

    res.send(html.replace(/<%= (\w+) %>/g, (_, key) => escapeHtml(values[key] ?? "")));
});

// 認可エンドポイント -> GETとPOSTに分ける
// POST : ユーザーの同意を受け取り、認可コードを発行する
router.post("/authorize", async(req, res) => {

    // GETと同じ検証
    const params = pickParams(req.body ?? {});
    const result = validateAuthorizeRequest(params);
    if (!result.ok) return respondError(res, result, params);

    // 同意が取れなかったら、直ちににクライアントにリダイレクトする
    if (req.body.decision === "deny") {
        return res.redirect(buildAuthorizationResponseUrl(params, { error: "access_denied" }));
    }

    // ユーザー認証を行う (簡易的だが)
    const user = verifyCredentials(str(req.body.username), str(req.body.password));

    // ユーザー認証失敗時のリダイレクト処理
    if (!user) {
        const retryUrl = new URL("/authorize", AUTH_SERVER_URL);
        for (const [key, value] of Object.entries(params)) {
            retryUrl.searchParams.append(key, value);
        }
        retryUrl.searchParams.append("error", "認証に失敗しました");

        return res.redirect(retryUrl.toString());
    }

    try{

        // 認可コードを生成する
        const code = crypto.randomBytes(32).toString("hex");

        // 認可コードに紐づく情報を生成する (scope は検証済みの result.scopes を使う)
        const codeData = generateAuthCodeData(params.client_id, params.redirect_uri, result.scopes, user.id, params.code_challenge);

        // 認可コード・クライアントID・リダイレクトURI・スコープ・有効期限 を一時保存する
        saveCodeData(code, codeData);

        // redirect_uriに認可コードを付与してリダイレクトする
        res.redirect(buildAuthorizationResponseUrl(params, { code }));
    } catch (error) {
        console.error(error);
        return res.status(500).send("サーバーエラーが発生しました");
    }
});

export default router;
