import fs from "fs";

// サーバーの設定
export const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL!;
export const TOKEN_EXPIRES_IN = process.env.TOKEN_EXPIRES_IN!;

// 鍵のパス
export const PRIVATE_KEY = fs.readFileSync(process.env.PRIVATE_KEY_PATH!, "utf-8");
export const PUBLIC_KEY = fs.readFileSync(process.env.PUBLIC_KEY_PATH!, "utf-8");

// 登録済みクライアントの台帳
type RegisteredClient = {
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
    allowed_scopes: string[];
};

export const clients: Record<string, RegisteredClient> = {
    "fortune-app": {
        client_id: process.env.FORTUNE_APP_CLIENT_ID!,
        client_secret: process.env.FORTUNE_APP_CLIENT_SECRET!,
        redirect_uris: [process.env.FORTUNE_APP_REDIRECT_URI!],
        allowed_scopes: process.env.FORTUNE_APP_SCOPES!.split(","),
    },
};