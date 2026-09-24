/**
 * トークン発行のサービス
 *
 * アクセストークンとリフレッシュトークンを発行するためのサービス
 * アクセストークンはJWT形式で発行され、リフレッシュトークンはランダムな文字列で発行される
 */

import jwt, { type SignOptions } from "jsonwebtoken";
import { ACCESS_TOKEN_EXPIRES_IN, PRIVATE_KEY} from "../config";
import crypto from "crypto";

// アクセストークンを発行する関数 (署名はRS256で固定)
export function issueAccessToken(payload: { sub: string, scope: string }): string {
    return jwt.sign(payload, PRIVATE_KEY!, {
        algorithm: "RS256",
        expiresIn: ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
    });
}

// リフレッシュトークンを発行する関数 (32バイトのランダムな文字列を生成)
export function issueRefreshToken(): string {
    return crypto.randomBytes(32).toString("hex");
}