/**
 * リソースサーバーのアクセストークン検証サービス
 * 
 * このファイルは、リソースサーバーで使用されるアクセストークンの検証ロジックを実装している
 * 署名の検証には固定でRS256を使用し、公開鍵を使用してアクセストークンの署名を検証する
 */

import jwt from "jsonwebtoken";
import { PUBLIC_KEY } from "../config";

export type AccessTokenPayload = {
    sub:   string;
    scope: string;
    iat:   number;
    exp:   number;
};

// アクセストークンを検証する関数 (署名はRS256で固定検証)
export function verifyAccessToken(token: string): AccessTokenPayload {
    return jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] }) as AccessTokenPayload;
}