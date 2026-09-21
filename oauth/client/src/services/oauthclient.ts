import { fortuneApp, AUTH_SERVER_URL } from "../config";

// 認可コードを Access Token に交換する処理
export default async function exchangeCodeForToken(code: string) {
    
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
    const data = await response.json();
    return data.access_token;
}