/**
 * 認可リクエストの検証サービス
 *
 * GET /authorize と POST /authorize の両方で同じ検証を行うための共通関数
 * POST は hidden フィールドを経由しているだけでブラウザから直接送れるため、GET を通った値を信用せず、必ずここで再検証する
 */

import { clients, RegisteredClient } from "../config";

export type AuthorizeParams = {
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope: string;
    state: string;
    code_challenge: string;
};

export type AuthorizeResult =
    | { ok: true; client: RegisteredClient; scopes: string[] }
    | { ok: false; kind: "fatal"; message: string }                         // リダイレクトしない
    | { ok: false; kind: "redirect"; error: string; description?: string }; // redirect_uri へ返す

// 文字列以外 (配列・オブジェクト・undefined) は空文字扱いにする
export const str = (v: unknown): string => (typeof v === "string" ? v : "");

// S256 のcode_challengeの形式保証
const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
// stateの形式保証
const STATE_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

export function validateAuthorizeRequest(p: AuthorizeParams): AuthorizeResult {

    // --- ここまでのエラーは絶対にリダイレクトしない ---
    const client = Object.hasOwn(clients, p.client_id) ? clients[p.client_id] : undefined;
    if (!client) {
        return { ok: false, kind: "fatal", message: "不正なクライアントです" };
    }

    // リダイレクトURIが一致するか確認する (完全一致で検証)
    if (!client.redirect_uris.includes(p.redirect_uri)) {
        return { ok: false, kind: "fatal", message: "不正なリダイレクトURIです" };
    }

    // --- これ以降のエラーはリダイレクトURIに伝える ---

    // 認可コードグラント以外はお断り
    if (p.response_type !== "code") {
        return { ok: false, kind: "redirect", error: "unsupported_response_type" };
    }

    // スコープが正当なものか確認する
    const scopes = p.scope.split(" ");
    if (!p.scope || scopes.some(s => !client.allowed_scopes.includes(s))) {
        return { ok: false, kind: "redirect", error: "invalid_scope" };
    }

    // PKCE: code_challenge の形式を確認する
    if (!CODE_CHALLENGE_PATTERN.test(p.code_challenge)) {
        return { ok: false, kind: "redirect", error: "invalid_request", description: "code_challengeが不正です" };
    }

    // state の形式を確認する
    if (!STATE_PATTERN.test(p.state)) {
        return { ok: false, kind: "redirect", error: "invalid_request", description: "stateが不正です" };
    }

    return { ok: true, client, scopes };
}
