/**
 * UserInfoエンドポイントからユーザー情報を取得するサービス
 *
 * アクセストークンを Bearer で送り、スコープに応じたクレームを受け取る
 */

import { getDiscovery } from "./discoveryClient";

export type UserInfo = {
    sub: string;
    preferred_username?: string;
};

export async function fetchUserInfo(accessToken: string): Promise<UserInfo> {
    // new!! UserInfo エンドポイントは Discovery から取得する
    const { userinfo_endpoint } = await getDiscovery();
    const response = await fetch(userinfo_endpoint, {
        headers: { "Authorization": "Bearer " + accessToken },
    });
    if (!response.ok) throw new Error(`UserInfo の取得に失敗しました: ${response.status}`);

    const data = await response.json();
    if (typeof data?.sub !== "string") throw new Error("UserInfo に sub がありません");
    return data as UserInfo;
}
