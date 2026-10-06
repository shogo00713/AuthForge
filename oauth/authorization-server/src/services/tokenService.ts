/**
 * トークン発行のサービス
 *
 * アクセストークンとリフレッシュトークンを発行するためのサービス
 * アクセストークンはJWT形式で発行され、リフレッシュトークンはランダムな文字列で発行される
 */

import jwt, { type SignOptions } from "jsonwebtoken";
import { RESOURCE_SERVER_URL, ACCESS_TOKEN_EXPIRES_IN, ID_TOKEN_EXPIRES_IN, PRIVATE_KEY, AUTH_SERVER_URL } from "../config";
import crypto from "crypto";
import { KID } from "./jwks";

// アクセストークンを発行する関数 (署名はRS256で固定)
export function issueAccessToken(payload: { sub: string, scope: string }): string {
    return jwt.sign(payload, PRIVATE_KEY!, {
        algorithm: "RS256",
        expiresIn: ACCESS_TOKEN_EXPIRES_IN,
        issuer: AUTH_SERVER_URL.toString(),
        audience: RESOURCE_SERVER_URL,  // new!! 宛先はリソースサーバー (IDトークンとの取り違え防止)
        keyid: KID,
    });
}

// リフレッシュトークンを発行する関数 (32バイトのランダムな文字列を生成)
export function issueRefreshToken(): string {
    return crypto.randomBytes(32).toString("hex");
}

// IDトークンを発行する関数 (署名はRS256で固定)
// aud は発行先クライアント (client_id)。scope は入れない (アクセストークンとの取り違え防止)
export function issueIdToken(payload: { sub: string; aud: string; nonce: string; auth_time: number }): string {
    return jwt.sign({ nonce: payload.nonce, auth_time: payload.auth_time }, PRIVATE_KEY!, {
        algorithm: "RS256",
        expiresIn: ID_TOKEN_EXPIRES_IN,
        issuer: AUTH_SERVER_URL.toString(),
        subject: payload.sub,
        audience: payload.aud,  // 宛先は発行先クライアント
        keyid: KID,
    });
}
