/**
 * IDトークンの検証サービス
 *
 * OIDC Core 3.1.3.7 に沿って、次を確認する
 *   署名 / alg (RS256のみ) / iss / aud / exp / nonce
 */

import jwt from "jsonwebtoken";
import { AUTH_SERVER_URL, fortuneApp, INSECURE } from "../config";
import { getSigningKey } from "./jwksClient";

export type IdTokenPayload = {
    iss: string;
    sub: string;
    aud: string | string[];
    exp: number;
    iat: number;
    auth_time: number;
    nonce: string;
};

export async function verifyIdToken(idToken: string, expectedNonce: string): Promise<IdTokenPayload> {
    const decoded = jwt.decode(idToken, { complete: true });

    if (!decoded || typeof decoded === "string" || !decoded.header.kid) {
        throw new Error("IDトークンのkidが見つかりません");
    }

    // 鍵を元に署名を検証する
    const publicKey = await getSigningKey(decoded.header.kid);
    const verified = jwt.verify(idToken, publicKey, {
        algorithms: ["RS256"],
        issuer: AUTH_SERVER_URL,
        // 【危険スイッチ】オンのときだけ aud を検証しない (既定は client_id を検証する)
        audience: INSECURE.skipAudCheck ? undefined : fortuneApp.client_id,
    });

    if (typeof verified === "string") {
        throw new Error("IDトークンのペイロードが不正です");
    }

    const payload = verified as Partial<IdTokenPayload>;

    // jwt.verify は exp などが「無いトークン」も通してしまうので、必須クレームの存在を自分で確認する
    if (
        typeof payload.iss !== "string" ||
        typeof payload.sub !== "string" || payload.sub === "" ||
        typeof payload.exp !== "number" ||
        typeof payload.iat !== "number" ||
        typeof payload.auth_time !== "number"
    ) {
        throw new Error("IDトークンの必須クレームが不足しています");
    }

    // nonce の照合 (IDトークンのリプレイ・差し替え対策)。期待値が空のときも通さない
    // 【危険スイッチ】オンのときだけ nonce を照合しない
    if (!INSECURE.skipNonceCheck && (!expectedNonce || typeof payload.nonce !== "string" || payload.nonce !== expectedNonce)) {
        throw new Error("IDトークンのnonceが一致しません");
    }

    return payload as IdTokenPayload;
}
