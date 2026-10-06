/**
 * リソースサーバーの設定
 */

// サーバーの設定
export const RESOURCE_SERVER_URL: string = process.env.RESOURCE_SERVER_URL as string;
export const AUTH_SERVER_URL: string = process.env.AUTH_SERVER_URL as string;

// new!! JWKSのパス
export const JWKS_URI: string = process.env.JWKS_URI as string;

// スコープの定義
export const SCOPES = {
    BASIC: "profile:basic",
    FULL: "profile:full",
} as const;