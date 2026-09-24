/**
 * クライアントの認可ルーティング
 * 
 * クライアントのOAuth2.0認可フローに関するルーティングを実装している
 * GET /login : 認可サーバーの認可エンドポイントにリダイレクトする
 * GET /callback : 認可サーバーから認可コードを受け取り、アクセストークンとリフレッシュトークンを取得する
 * GET /fortune : アクセストークンを使ってリソースサーバーからユーザー情報を取得し、占い結果を表示する
 * GET /logout : クッキーに保存されているアクセストークンを削除し、ログアウトする
 */

import express from "express"
import { fortuneApp, AUTH_SERVER_URL } from "../config";
import { exchangeCodeForToken, refreshAccessToken } from "../services/oauthclient";
import fetchResources from "../services/resourceClient";
import path from "path";
import generateFortune from "../services/fortune";
import fs from "fs";    

const router = express.Router();

// アクセストークンを持っているときにのみ fortune.html を表示するようにする
router.get("/", (req, res) => {
    if (!req.cookies.access_token) {
        res.sendFile(path.join(__dirname + "/..", "views", "index.html"));
    } else {
        res.sendFile(path.join(__dirname + "/..", "views", "fortune.html"));
    }
});


// ログイン時に認可サーバーの認可エンドポイントにリダイレクトする処理
router.get("/login", (req, res) => {

    const scope = req.query.scope as string;

    // URLを構築する
    const autorizeUrl = new URL("/authorize", AUTH_SERVER_URL);
    autorizeUrl.searchParams.append("client_id", fortuneApp.client_id);
    autorizeUrl.searchParams.append("redirect_uri", fortuneApp.redirect_uris[0]);
    autorizeUrl.searchParams.append("response_type", "code");
    autorizeUrl.searchParams.append("scope", scope);

    res.redirect(autorizeUrl.toString());
});


// 認可サーバーから認可コードを受け取り、Access Token に交換する処理
router .get("/callback", async (req, res) => {

    const error = req.query.error as string;

    if(error === "access_denied"){
        return res.redirect("/?error=" + encodeURIComponent("ログインの連携がキャンセルされました"));
    }

    const code = req.query.code as string;

    // 認可コードを取得できなかった場合
    if(!code){
        return res.redirect("/?error=" + encodeURIComponent("認可コードが取得できませんでした"));
    }
    // 認可コードと Access Token の交換を試みる
    try {
        const { access_token, refresh_token } = await exchangeCodeForToken(code);

        // Access Token をクッキーに保存する
        res.cookie("access_token", access_token, { httpOnly: true, maxAge: 3600 * 1000 }); // 1時間
        // new Refresh Token をクッキーに保存する
        res.cookie("refresh_token", refresh_token, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 }); // 7日間

        res.redirect("/");

    } catch (error) {
        res.redirect("/?error=" + encodeURIComponent("アクセストークンの取得に失敗しました"));
    }
});

// Access_token を使って必要となる情報を埋めた fortune.html を表示する処理
router.get("/fortune", async (req, res) => {
    const accessToken = req.cookies.access_token;

    let data = accessToken ? await fetchResources(accessToken) : null;

    // <<アクセストークンが無効な場合>>
    if (!data) {

        // Access Token が無効な場合、リフレッシュトークンを使って新しい Access Token を取得する
        const refreshToken = req.cookies.refresh_token;
        // <<リフレッシュトークンが無効な場合>>
        if (!refreshToken) return res.redirect("/");

        const newAccessToken = await refreshAccessToken(refreshToken);
        if (!newAccessToken) return res.redirect("/");

        res.cookie("access_token", newAccessToken, { httpOnly: true, maxAge: 3600 * 1000 });
        data = await fetchResources(newAccessToken);
        if (!data) return res.redirect("/");
    }

    const profile = data.profile;
    const hasFullAccess = profile.birthday !== undefined;
    const fortuneSection = hasFullAccess
    ?  (() => {
          const fortune = generateFortune(profile.name, profile.birthday);
          return `<div class="fortune-box">
                    <p class="fortune-label">誕生日: ${profile.birthday}</p>
                    <p class="fortune-text">${fortune.label}</p>
                    <p class="fortune-message">${fortune.message}</p>
                  </div>`;
       })()
    :  `<div class="locked-box">
          占いには誕生日の情報が必要です。<br>
          full権限でログインし直してください。
        </div>`;

    res.send(
        fs.readFileSync(path.join(__dirname, "..", "views", "result.html"), "utf-8")
            .replace(/<%= name %>/g, profile.name)
            .replace(/<%= favoriteFood %>/g, profile.favoriteFood)
            .replace(/<%= fortuneSection %>/g, fortuneSection)
    );
});

// クッキーに保存されているアクセストークンを削除し、ログアウトする処理
router.get("/logout", (req, res) => {
    res.clearCookie("access_token");
    res.clearCookie("refresh_token");
    res.redirect("/");
});

export default router;
