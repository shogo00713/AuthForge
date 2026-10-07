/**
 * リソースサーバーの設定
 */

// サーバーの設定
export const RESOURCE_SERVER_URL: string = process.env.RESOURCE_SERVER_URL as string;
export const AUTH_SERVER_URL: string = process.env.AUTH_SERVER_URL as string;

// スコープの定義
export const SCOPES = {
    BASIC: "profile:basic",
    FULL: "profile:full",
} as const;
// 【学習用・危険】scripts/check_token_confusion.py が「audience を検証しなかったら何が通ってしまうか」を再現するためのスイッチ。
// 既定はオフ。オンにすると、他の宛先向けのトークンも受け入れてしまうので、本番では絶対に使わない。起動時に警告を出す
export const INSECURE_SKIP_AUD_CHECK = process.env.INSECURE_SKIP_AUD_CHECK === "1";
