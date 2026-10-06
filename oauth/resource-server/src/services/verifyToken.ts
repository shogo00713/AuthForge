/**
 * リソースサーバーのアクセストークン検証サービス
 * 
 * このファイルは、リソースサーバーで使用されるアクセストークンの検証ロジックを実装している
 * 署名の検証には固定でRS256を使用し、JWKSから取得した公開鍵(kidで選択)で署名を検証する
 */

import jwt from "jsonwebtoken";
import { AUTH_SERVER_URL } from "../config";
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
    return jwt.verify(token, publicKey, {
        algorithms: ["RS256"],
        issuer: AUTH_SERVER_URL,
    }) as AccessTokenPayload;
}