/**
 * クライアントのOAuth2.0認可フローに関するサービス
 * 
 * このサービスは、クライアントが認可サーバーと通信してトークンを取得するための機能を提供し、次の2つがある
 * 1. 認可コードをアクセストークンに交換する処理
 * 2. リフレッシュトークンを使用して新しいアクセストークンを取得する処理
 */

import { fortuneApp, AUTH_SERVER_URL } from "../config";

// 認可コードを Access Token に交換する処理
export async function exchangeCodeForToken(code: string) {
    
    const response = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: "POST",
        // Basic認証を使用してクライアントの認証情報を送信する
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",    
            "Authorization": "Basic " + Buffer.from(`${fortuneApp.client_id}:${fortuneApp.client_secret}`).toString("base64")
        },
        body: new URLSearchParams({
            grant_type: "authorization_code",
            code: code,
            redirect_uri: fortuneApp.redirect_uris[0]
        })
    });
    if (!response.ok) throw new Error("トークンの取得に失敗しました");
    const data = await response.json();
    return { access_token: data.access_token, refresh_token: data.refresh_token };
}

// リフレッシュトークンを使用して新しい Access Token を取得する処理
export async function refreshAccessToken(refreshToken: string) {
    const response = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic " + Buffer.from(`${fortuneApp.client_id}:${fortuneApp.client_secret}`).toString("base64")
        },
        body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken
        })
    });
    if (response.status !== 200) return null;
    const data = await response.json();
    return data.access_token;
}