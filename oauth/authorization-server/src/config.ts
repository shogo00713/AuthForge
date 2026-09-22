import fs from "fs";

// サーバーの設定
export const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL!;

// アクセストークンの有効期限（秒）
export const TOKEN_EXPIRES_IN = process.env.TOKEN_EXPIRES_IN!;

// 鍵
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


export type User = {
    id: string;
    username: string;
    password: string;
}

export const users: User[] = [
    { id: "u01", username: "saeki_haruna", password: "QZpGdjCXN1wG" },
    { id: "u02", username: "kuroda_ren", password: "ViLaFYVMgyix" },
    { id: "u03", username: "mikami_yuko", password: "yRK8BMHOyHB" },
    { id: "u04", username: "shinonome_yuma", password: "aCmiaBeMg03l" },
    { id: "u05", username: "saotome_chinatsu", password: "KHikDlmcK2X" },
    { id: "u06", username: "kiryu_yamato", password: "6CDGD4zxYIs" },
    { id: "u07", username: "shiratori_mizuki", password: "bhCxcstUjrx9" },
    { id: "u08", username: "kagurazaka_takumi", password: "LjSCXFiYcy6u" },
    { id: "u09", username: "hoshino_aoi", password: "QHHnANgPgwL" },
    { id: "u10", username: "rokudou_kei", password: "PP7sVQdQ96vh" },
]