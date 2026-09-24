/**
 * リフレッシュトークン保存のサービス
 *
 * リフレッシュトークンとその関連情報を保存するためのサービス
 * ここでは簡易的にメモリ上の Map を使用しているが、実際の運用ではデータベースなどに保存することが望ましい
 *
 * アクセストークンはJWT形式なのでサーバー側での保存は不要だが、リフレッシュトークンはただの文字列なのでサーバー側での保存が必要
 */

import ms from "ms";
import type { StringValue } from "ms";
import { REFRESH_TOKEN_EXPIRES_IN } from "../config";

type RefreshTokenData = {
    client_id: string;
    scope: string[];
    expires_at: number;
    sub : string;
};

// リフレッシュトークンの一時保存は、メモリ上の Map を使用する
const refreshTokens = new Map<string, RefreshTokenData>();

// リフレッシュトークンを生成する関数
export function generateRefreshTokenData(client_id: string, scope: string[], sub: string): RefreshTokenData {
    return {
        client_id,
        scope,
        expires_at: Date.now() + ms(REFRESH_TOKEN_EXPIRES_IN as StringValue), // 7日後
        sub,
    };
}

// リフレッシュトークンを保存する関数
export function saveRefreshTokenData(token: string, data: RefreshTokenData): void {
    refreshTokens.set(token, data);
}

// リフレッシュトークンの有効性を確認する関数
export function checkRefreshTokenData(token: string): RefreshTokenData | null {
    const data = refreshTokens.get(token);
    if (!data) {
        return null;
    }
    if (data.expires_at < Date.now()) {
        refreshTokens.delete(token);
        return null;
    }
    return data;
}

// リフレッシュトークンを削除する関数
export function deleteRefreshTokenData(token: string): void {
    refreshTokens.delete(token);
}