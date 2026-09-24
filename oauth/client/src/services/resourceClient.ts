/**
 * リソースサーバーからリソースを取得するサービス
 * 
 * このサービスは、リソースサーバーからリソースを取得するための機能を提供する
 * 各ユーザーに対する分岐は、リソースサーバー側で行われるため、クライアント側ではアクセストークンを使ってリソースを取得するだけである
 * 認証にはBearer認証を使用し、アクセストークンをAuthorizationヘッダーに付与してリクエストを送信する
 */

import { RESOURCE_SERVER_URL } from "../config";

export default async function fetchResources(token: string) {
    const response = await fetch(`${RESOURCE_SERVER_URL}/resources`, {
        method: "GET",
        headers: {
            "Authorization": "Bearer " + token
        }
    });
    if (response.status === 401) {
        return null;
    }
    const data = await response.json();
    return data;
}