/**
 * 認可コード一時保存のサービス
 *
 * 認可コードとその関連情報を一時的に保存するためのサービス
 * 
 * ここでは簡易的にメモリ上の Map を使用しているが、実際の運用ではデータベースなどに保存することが望ましい
 */

import ms from "ms";
import type { StringValue } from "ms";
import { AUTH_CODE_EXPIRES_IN } from "../config";


type AuthCodeData = {
    client_id: string;
    redirect_uri: string;
    scope: string[];
    expires_at: number;
    sub : string; // 認可コードに紐づくユーザーID
};

// 認可コードの一時保存は、メモリ上の Map を使用する
const codes = new Map<string, AuthCodeData>();

// 認可コードを生成する関数
export function generateAuthCodeData(client_id: string, redirect_uri: string, scope: string[], sub: string): AuthCodeData {
    return {
        client_id,
        redirect_uri,
        scope,
        expires_at: Date.now() + ms(AUTH_CODE_EXPIRES_IN as StringValue), // 5分後
        sub,
    };
}

// 認可コードを保存する関数
export function saveCodeData(code: string, data: AuthCodeData): void {
    codes.set(code, data);
}

// 認可コードの有効性を確認する関数
export function checkCodeData(code: string): AuthCodeData | null {
    const data = codes.get(code);
    if (!data) {
        return null;
    }
    if (data.expires_at < Date.now()) {
        codes.delete(code);
        return null;
    }
    return data;
}

// 認可コードを削除する関数
export function deleteCodeData(code: string): void {
    codes.delete(code);
}