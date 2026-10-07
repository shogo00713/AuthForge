/**
 * リソースサーバーのアクセストークン検証サービス
 * 
 * このファイルは、リソースサーバーで使用されるアクセストークンの検証ロジックを実装している
 * 署名の検証には固定でRS256を使用し、JWKSから取得した公開鍵(kidで選択)で署名を検証する
 */

import jwt from "jsonwebtoken";
import { AUTH_SERVER_URL, RESOURCE_SERVER_URL, INSECURE_SKIP_AUD_CHECK } from "../config";
import { getSigningKey } from "./jwksClient";

export type AccessTokenPayload = {
    sub:   string;
    scope: string;
    iat:   number;
    exp:   number;
    iss:   string;
};

// アクセストークンを検証する関数 (署名はRS256で固定検証)
export async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    // トークンから kid を取得
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === "string") {
        throw new Error("トークンの形式が不正です");
    }
    const { header } = decoded;
    const kid = header.kid;

    const publicKey = await getSigningKey(kid);
    const verified = jwt.verify(token, publicKey, {
        algorithms: ["RS256"],
        // アクセストークンはリソースサーバー当てであることを明示 (【危険スイッチ】オンのときだけ検証しない)
        audience: INSECURE_SKIP_AUD_CHECK ? undefined : RESOURCE_SERVER_URL,
        issuer: AUTH_SERVER_URL,
    });
    if (typeof verified === "string") {
        throw new Error("トークンのペイロードが不正です");
    }

    // jwt.verify は exp などが「無いトークン」も通してしまう (期限のないトークンが永久に使えてしまう)
    // ので、必須クレームの存在を自分で確認する
    const payload = verified as Partial<AccessTokenPayload>;
    if (
        typeof payload.exp !== "number" ||
        typeof payload.iat !== "number" ||
        typeof payload.sub !== "string" || payload.sub === "" ||
        typeof payload.scope !== "string"
    ) {
        throw new Error("アクセストークンの必須クレームが不足しています");
    }
    return payload as AccessTokenPayload;
}