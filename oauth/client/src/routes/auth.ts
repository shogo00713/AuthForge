/**
 * クライアントの認可ルーティング
 * 
 * クライアントのOAuth2.0認可フローに関するルーティングを実装している
 * GET /login : 認可サーバーの認可エンドポイントにリダイレクトする
 * GET /callback : 認可サーバーから認可コードを受け取り、アクセストークンとリフレッシュトークンを取得する
 * GET /fortune : アクセストークンを使ってリソースサーバーからユーザー情報を取得し、占い結果を表示する
 * GET /logout : セッションに保存されているアクセストークンを削除し、ログアウトする
 */

import express from "express"
import { fortuneApp, AUTH_SERVER_URL } from "../config";
import { exchangeCodeForToken, refreshAccessToken } from "../services/oauthclient";
import { verifyIdToken } from "../services/idTokenVerifier";
import { getDiscovery } from "../services/discoveryClient";
import { fetchUserInfo } from "../services/userinfoClient";
import fetchResources from "../services/resourceClient";
import path from "path";
import generateFortune from "../services/fortune";
import fs from "fs";    
import crypto from "crypto";
import session from "express-session";

declare module "express-session" {
    interface SessionData {
        access_token?: string;
        refresh_token?: string;
        state?: string;
        code_verifier?: string;
        issuer?: string;
        nonce?: string; // new!! nonceをセッションに保存する
        sub?: string; // new!! 検証済みIDトークンの sub (ログイン中のユーザー)
        auth_time?: number; // new!! 検証済みIDトークンの auth_time
        username?: string; // new!! UserInfo の preferred_username
    }
}

const router = express.Router();

// HTMLエスケープ
function escapeHtml(s: string): string {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// auth_time (秒) を日本時間の日時文字列にする
function formatAuthTime(authTime: number): string {
    return new Date(authTime * 1000).toLocaleString("ja-JP", { timeZone: "Asia/Tokyo" });
}

// IDトークンの検証を経てログインが成立しているときにのみ fortune.html を表示するようにする
router.get("/", (req, res) => {
    if (!req.session.sub || !req.session.access_token) {
        res.sendFile(path.join(__dirname + "/..", "views", "index.html"));
    } else {
        res.sendFile(path.join(__dirname + "/..", "views", "fortune.html"));
    }
});


// ログイン時に認可サーバーの認可エンドポイントにリダイレクトする処理
router.get("/login", async (req, res) => {

    // new!! 認可エンドポイントは Discovery から取得する (issuer の一致もここで確認される)
    let authorizationEndpoint: string;
    try {
        authorizationEndpoint = (await getDiscovery()).authorization_endpoint;
    } catch (error) {
        console.error(error);
        return res.redirect("/?error=" + encodeURIComponent("認可サーバーの情報を取得できませんでした"));
    }

    // スコープにはもう必ずopenidを含めるようにする
    const scope = `openid ${req.query.scope as string}`;

    // new!! stateでCSRF対策をする
    const state = crypto.randomBytes(32).toString("hex");
    req.session.state = state;

    // new!! Mix-up 攻撃対策のため、どの認可サーバーとのフローを開始したかを覚えておく
    req.session.issuer = AUTH_SERVER_URL;

    // new!! PKCE対応のため、code_challengeを生成する
    const codeVerifier = crypto.randomBytes(32).toString("base64url"); // RFC7636の文字集合的にbase64urlが楽
    req.session.code_verifier = codeVerifier;
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    // new!! nonceを生成してセッションに保存する
    const nonce = crypto.randomBytes(32).toString("hex");
    req.session.nonce = nonce;

    // URLを構築する
    const autorizeUrl = new URL(authorizationEndpoint);
    autorizeUrl.searchParams.append("client_id", fortuneApp.client_id);
    autorizeUrl.searchParams.append("redirect_uri", fortuneApp.redirect_uris[0]);
    autorizeUrl.searchParams.append("response_type", "code");
    autorizeUrl.searchParams.append("scope", scope);
    autorizeUrl.searchParams.append("state", state);
    autorizeUrl.searchParams.append("code_challenge", codeChallenge);
    autorizeUrl.searchParams.append("nonce", nonce); // new!! nonceを追加する
    res.redirect(autorizeUrl.toString());
});


// 認可サーバーから認可コードを受け取り、Access Token に交換する処理
router .get("/callback", async (req, res) => {

    // --- new!! issでMix-up攻撃対策をする ---
    const iss = req.query.iss;
    const expectedIssuer = req.session.issuer;

    // issは使い終わったら破棄する
    delete req.session.issuer;

    // フローを開始していない (expectedIssuer が無い)・iss が無い・iss が一致しない場合はエラーにする
    if(!expectedIssuer || typeof iss !== "string" || iss !== expectedIssuer){
        return res.redirect("/?error=" + encodeURIComponent("不正な認可サーバーからの応答です"));
    }
    // -------------------------------------

    const error = req.query.error as string;

    if(error === "access_denied"){
        return res.redirect("/?error=" + encodeURIComponent("ログインの連携がキャンセルされました"));
    }

    const code = req.query.code as string;


    // --- new!! stateでCSRF対策をする ---
    const state = req.query.state as string;

    // stateが一致しない場合はCSRF攻撃の可能性があるのでエラーにする
    if(state !== req.session.state){
        return res.redirect("/?error=" + encodeURIComponent("不正なリクエストです"));
    }

    // stateは使い終わったら破棄する
    delete req.session.state;
    // ----------------------------------

    // 認可コードを取得できなかった場合
    if(!code){
        return res.redirect("/?error=" + encodeURIComponent("認可コードが取得できませんでした"));
    }
    // 認可コードと Access Token / IDトークン の交換を試みる
    let tokens;
    try {
        tokens = await exchangeCodeForToken(code, req.session.code_verifier as string);
    } catch (error) {
        console.error(error);
        return res.redirect("/?error=" + encodeURIComponent("アクセストークンの取得に失敗しました"));
    }
    delete req.session.code_verifier; // code_verifierは使い終わったら破棄する

    // --- new!! IDトークンを検証して、認証を成立させる ---
    // nonce は regenerate でセッションごと消えるので、先に取り出し、使い終わったら破棄する
    const expectedNonce = req.session.nonce;
    delete req.session.nonce;

    let idTokenPayload;
    let userInfo;
    try {
        if (!tokens.id_token || !expectedNonce) {
            throw new Error("IDトークンまたは nonce がありません");
        }
        idTokenPayload = await verifyIdToken(tokens.id_token, expectedNonce);

        // new!! UserInfo の sub が IDトークンの sub と一致することを確認する (OIDC Core 5.3.2)
        userInfo = await fetchUserInfo(tokens.access_token);
        if (userInfo.sub !== idTokenPayload.sub) {
            throw new Error("UserInfo の sub が IDトークンの sub と一致しません");
        }
    } catch (error) {
        console.error(error);
        // 検証に失敗したら、トークンはセッションに保存せず、ログイン済みにもしない
        return res.redirect("/?error=" + encodeURIComponent("IDトークンの検証に失敗しました"));
    }
    // ----------------------------------------------------

    req.session.regenerate((err) => {
        if (err) {
            console.error(err);
            return res.redirect("/?error=" + encodeURIComponent("セッションの再生成に失敗しました"));
        }
        req.session.access_token = tokens.access_token;
        req.session.refresh_token = tokens.refresh_token;
        // new!! 検証済みIDトークンの sub を「ログイン中のユーザー」として保存する
        req.session.sub = idTokenPayload.sub;
        req.session.auth_time = idTokenPayload.auth_time;
        req.session.username = userInfo.preferred_username;
        res.redirect("/");
    });
});

// Access_token を使って必要となる情報を埋めた fortune.html を表示する処理
router.get("/fortune", async (req, res) => {
    // IDトークンの検証を経ていない (ログイン済みでない) 場合は、ログイン画面に戻す
    if (!req.session.sub) return res.redirect("/");

    // Access_token を取得する
    const accessToken = req.session.access_token;

    let data = accessToken ? await fetchResources(accessToken) : null;

    // <<アクセストークンが無効な場合>>
    if (!data) {

        // Access Token が無効な場合、リフレッシュトークンを使って新しい Access Token を取得する
        const refreshToken = req.session.refresh_token;
        // <<リフレッシュトークンが無効な場合>>
        // トークンの情報は全部消す -> ログイン画面に戻れる
        delete req.session.access_token;
        delete req.session.refresh_token;
        if (!refreshToken) return res.redirect("/");

        const { newAccessToken, newRefreshToken } = await refreshAccessToken(refreshToken);
        if (!newAccessToken) return res.redirect("/"); // リフレッシュトークンが無効な場合はログイン画面に戻し最初からやり直す

        req.session.access_token = newAccessToken;
        req.session.refresh_token = newRefreshToken; // リフレッシュトークンローテーションする
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
            // new!! IDトークン由来の情報 (ログイン中のユーザーと認証時刻)
            .replace(/<%= sub %>/g, () => escapeHtml(req.session.sub!))
            .replace(/<%= authTime %>/g, () => formatAuthTime(req.session.auth_time!))
            .replace(/<%= username %>/g, () => escapeHtml(req.session.username ?? "-"))
            .replace(/<%= fortuneSection %>/g, fortuneSection)
    );
});

// セッションに保存されているアクセストークンを削除し、ログアウトする処理
router.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            return res.status(500).send("ログアウトに失敗しました");
        }
        res.clearCookie("connect.sid");
        res.redirect("/");
    });
});

export default router;
