/**
 * Discoveryクライアント
 *
 * 認可サーバーの /.well-known/openid-configuration から、各エンドポイントのURLなどを取得する
 * - 取得結果はキャッシュする (取得中の Promise は共有し、同時に何度も取りに行かない)
 * - 取得した issuer が、設定の AUTH_SERVER_URL と完全一致しなければエラーにする (OIDC Discovery 4.3)
 *   一致を確認しないと、別の認可サーバーのメタデータを信用してしまう
 */

import { AUTH_SERVER_URL } from "../config";

// キャッシュの有効期間 (ms)
const CACHE_TTL_MS = 10 * 60 * 1000;

export type DiscoveryDocument = {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    jwks_uri: string;
    id_token_signing_alg_values_supported: string[];
};

let cached: { doc: DiscoveryDocument; fetchedAt: number } | null = null;
let loading: Promise<DiscoveryDocument> | null = null;

async function fetchDiscovery(): Promise<DiscoveryDocument> {
    // issuer に /.well-known/openid-configuration を付けたURLから取得する
    const url = `${AUTH_SERVER_URL.replace(/\/$/, "")}/.well-known/openid-configuration`;
    const res = await fetch(url);
    if (!res.ok) {
        throw new Error(`Discovery を取得できませんでした: ${res.status} ${res.statusText}`);
    }
    const doc = await res.json();

    // issuer の完全一致を確認する
    if (doc.issuer !== AUTH_SERVER_URL) {
        throw new Error(`Discovery の issuer が一致しません: expected=${AUTH_SERVER_URL} actual=${doc.issuer}`);
    }

    // 使うエンドポイントが文字列で揃っていることを確認する
    for (const key of ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"] as const) {
        if (typeof doc[key] !== "string" || !doc[key]) {
            throw new Error(`Discovery に ${key} がありません`);
        }
    }

    // 署名アルゴリズムは RS256 だけを使うので、対応していなければエラーにする
    if (!Array.isArray(doc.id_token_signing_alg_values_supported) || !doc.id_token_signing_alg_values_supported.includes("RS256")) {
        throw new Error("Discovery が RS256 に対応していません");
    }
    return doc as DiscoveryDocument;
}

export async function getDiscovery(): Promise<DiscoveryDocument> {
    if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
        return cached.doc;
    }
    // 取得中なら、その Promise を共有する (失敗したときはキャッシュしない)
    loading ??= fetchDiscovery()
        .then((doc) => {
            cached = { doc, fetchedAt: Date.now() };
            return doc;
        })
        .finally(() => {
            loading = null;
        });
    return loading;
}
