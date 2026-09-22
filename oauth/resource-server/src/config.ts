import fs from "fs";

// サーバーの設定
export const RESOURCE_SERVER_URL: string = process.env.RESOURCE_SERVER_URL as string;

// 鍵
export const PUBLIC_KEY: string = fs.readFileSync(process.env.PUBLIC_KEY_PATH as string, "utf-8");

// スコープの定義
export const SCOPES = {
    BASIC: "profile:basic",
    FULL: "profile:full",
} as const;