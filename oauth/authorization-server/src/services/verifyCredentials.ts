/**
 * ユーザー認証のサービス
 *
 * 認証&同意画面でユーザー名とパスワードを検証するためのサービス
 * 単純に find でユーザーを検索しているだけなので、実際の運用ではデータベースなどに保存することが望ましい
 */

import { users, User } from "../config";

// 認証&同意画面でユーザー名とパスワードを検証する関数
export function verifyCredentials(username: string, password: string): User | null {

    const user = users.find((user) => user.username === username);

    if (user && user.password === password) {
        return user;
    }
    return null;

}