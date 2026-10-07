/**
 * UserInfoエンドポイント
 *
 * アクセストークンを検証し、スコープに応じたユーザー情報(クレーム)を返す
 * GET /userinfo
 *   openid                      -> sub
 *   profile:basic / profile:full -> preferred_username
 * アクセストークンの aud に UserInfo が含まれていないトークン (IDトークンなど) は受け付けない
 */

import express from "express";
import jwt from "jsonwebtoken";
import { AUTH_SERVER_URL, USERINFO_URL, PUBLIC_KEY, users } from "../config";

const router = express.Router();

// UserInfo のアクセストークン検証は、認可サーバー自身の公開鍵で行う
function verifyUserInfoToken(token: string): { sub: string; scope: string } {
    const verified = jwt.verify(token, PUBLIC_KEY, {
        algorithms: ["RS256"],
        issuer: AUTH_SERVER_URL,
        audience: USERINFO_URL,
    });
    if (typeof verified === "string") {
        throw new Error("トークンのペイロードが不正です");
    }

    // jwt.verify は exp が「無いトークン」も通してしまうので、必須クレームの存在を自分で確認する
    if (
        typeof verified.exp !== "number" ||
        typeof verified.iat !== "number" ||
        typeof verified.sub !== "string" || verified.sub === "" ||
        typeof verified.scope !== "string"
    ) {
        throw new Error("アクセストークンの必須クレームが不足しています");
    }
    return { sub: verified.sub, scope: verified.scope };
}

router.get("/userinfo", (req, res) => {

    res.set("Cache-Control", "no-store").set("Pragma", "no-cache");

    // Bearer認証でアクセストークンを受け取る (RFC 6750 参照)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).set("WWW-Authenticate", "Bearer").end();
    }
    const token = authHeader.split(" ")[1];
    if (!token) {
        return res
            .status(400)
            .set("WWW-Authenticate", 'Bearer error="invalid_request", error_description="No token provided"')
            .json({ error: "invalid_request", error_description: "トークンがありません" });
    }

    let payload: { sub: string; scope: string };
    try {
        payload = verifyUserInfoToken(token);
    } catch (error) {
        console.error(error);
        return res
            .status(401)
            .set("WWW-Authenticate", 'Bearer error="invalid_token", error_description="The access token expired or is invalid"')
            .json({ error: "invalid_token", error_description: "トークンの有効期限切れか、無効なトークンです" });
    }

    // UserInfo は openid スコープのトークンだけが使える
    const scopes = typeof payload.scope === "string" ? payload.scope.split(" ") : [];
    if (!scopes.includes("openid")) {
        return res
            .status(403)
            .set("WWW-Authenticate", 'Bearer error="insufficient_scope", scope="openid"')
            .json({ error: "insufficient_scope", error_description: "openid スコープが必要です" });
    }

    const user = users.find((u) => u.id === payload.sub);
    if (!user) {
        return res
            .status(401)
            .set("WWW-Authenticate", 'Bearer error="invalid_token", error_description="Unknown user"')
            .json({ error: "invalid_token", error_description: "ユーザーが見つかりません" });
    }

    // スコープに応じたクレームだけを返す
    const claims: Record<string, string> = { sub: user.id };
    if (scopes.includes("profile:basic") || scopes.includes("profile:full")) {
        claims.preferred_username = user.username;
    }
    res.json(claims);
});

export default router;
