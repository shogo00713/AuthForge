/**
 * クライアントの設定ファイル
 */

// サーバーの設定
export const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL!;
export const RESOURCE_SERVER_URL = process.env.RESOURCE_SERVER_URL!;

// セッションの秘密鍵
export const SESSION_SECRET = process.env.SESSION_SECRET!;

// クライアントの情報
export const fortuneApp = {
    client_id: process.env.CLIENT_ID!,
    client_secret: process.env.CLIENT_SECRET!,
    redirect_uris: [process.env.REDIRECT_URI!],
    scope: process.env.SCOPE ?? "profile:basic",
};


// 【学習用・危険】scripts/ の検証スクリプトが「検証を外したら何が通ってしまうか」を再現するためのスイッチ。
// 既定はオフ。オンにすると認証の安全性が失われるので、本番では絶対に使わない。起動時に警告を出す
export const INSECURE = {
    skipNonceCheck: process.env.INSECURE_SKIP_NONCE_CHECK === "1",
    skipAudCheck: process.env.INSECURE_SKIP_AUD_CHECK === "1",
};
