/**
 * Discoveryエンドポイント
 *
 * GET /.well-known/openid-configuration
 * 認可サーバーの issuer・各エンドポイントのURL・対応している方式を一覧で公開する (OpenID Connect Discovery 1.0)
 * issuer は、発行するトークンの iss と完全一致させる (クライアントが突き合わせて確認する)
 */

import express from "express";
import { AUTH_SERVER_URL, USERINFO_URL, clients } from "../config";

const router = express.Router();

const endpoint = (path: string) => new URL(path, AUTH_SERVER_URL).toString();

// 登録クライアントが使えるスコープを、重複なしでまとめる
const scopesSupported = [...new Set(Object.values(clients).flatMap((c) => c.allowed_scopes))];

const configuration = {
    // トークンの iss と同じ値 (tokenService.ts / userinfo.ts と揃える)
    issuer: AUTH_SERVER_URL,
    authorization_endpoint: endpoint("/authorize"),
    token_endpoint: endpoint("/token"),
    userinfo_endpoint: USERINFO_URL,
    jwks_uri: endpoint("/jwks.json"),

    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: scopesSupported,
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "preferred_username"],
    // 認可レスポンスに iss が付く (RFC 9207)
    authorization_response_iss_parameter_supported: true,
};

router.get("/.well-known/openid-configuration", (req, res) => {
    res.set("Cache-Control", "public, max-age=300").json(configuration);
});

export default router;
