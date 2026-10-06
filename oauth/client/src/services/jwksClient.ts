/**
 * JWKSクライアント (リソースサーバー用と全く同じ)
 *
 * 認可サーバーの /jwks.json から公開鍵を取得し、kid で鍵を選べるようにする
 * - 取得した鍵は kid をキーにしてキャッシュする (Mapでの実装)
 * - 未知の kid が来たときだけ、JWKS を取得し直す
 */

import crypto from "crypto";
import { JWKS_URI } from "../config";

// 取り直しの最短間隔 (10秒)で、未知の kid を大量に送られても、取得が連発しないようにする
const REFETCH_INTERVAL_MS = 10_000;

let keyCache = new Map<string, crypto.KeyObject>();
let lastFetchedAt = 0;
let refreshing: Promise<void> | null = null;

// JWKS を取得して keyCache を作り直す
async function fetchKeys(): Promise<void> {
    lastFetchedAt = Date.now();

    const res = await fetch(JWKS_URI);
    if (!res.ok) {
        throw new Error(`JWKS を取得できませんでした: ${res.status} ${res.statusText}`);
    }

    const jwks = await res.json();
    if (!Array.isArray(jwks.keys)) {
        throw new Error("JWKS の形式が不正です (keys が配列ではありません)");
    }

    // 新しい Map に詰めてから入れ替える
    const nextCache = new Map<string, crypto.KeyObject>();
    for (const jwk of jwks.keys) {
        if (jwk.kty !== "RSA") continue;
        if (jwk.use && jwk.use !== "sig") continue;
        if (jwk.alg && jwk.alg !== "RS256") continue;
        if (!jwk.kid) continue;

        const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
        nextCache.set(jwk.kid, publicKey);
    }
    keyCache = nextCache;
}

// 取得中ならその Promise を共有し、取得が二重に走らないようにする
function refreshKeys(): Promise<void> {
    refreshing ??= fetchKeys().finally(() => {
        refreshing = null;
    });
    return refreshing;
}

// kid に合う公開鍵を返す
export async function getSigningKey(kid: string | undefined): Promise<crypto.KeyObject> {
    if (!kid) {
        throw new Error("kid が指定されていません");
    }

    const cachedKey = keyCache.get(kid);
    if (cachedKey) {
        return cachedKey;
    }

    // 取得中ならその完了を待つ。そうでなければ、前回から間隔が空いているときだけ取得する
    if (refreshing || Date.now() - lastFetchedAt >= REFETCH_INTERVAL_MS) {
        await refreshKeys();
    }

    const refreshedKey = keyCache.get(kid);
    if (!refreshedKey) {
        throw new Error(`kid に対応する公開鍵が見つかりません: ${kid}`);
    }

    return refreshedKey;
}