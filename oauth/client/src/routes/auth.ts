import express from "express"
import { fortuneApp, AUTH_SERVER_URL } from "../config";
import exchangeCodeForToken from "../services/oauthclient";
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
router.get("/login", (_, res) => {

    // URLを構築する
    const autorizeUrl = new URL("/authorize", AUTH_SERVER_URL);
    autorizeUrl.searchParams.append("client_id", fortuneApp.client_id);
    autorizeUrl.searchParams.append("redirect_uri", fortuneApp.redirect_uris[0]);
    autorizeUrl.searchParams.append("response_type", "code");
    autorizeUrl.searchParams.append("scope", fortuneApp.scope);

    res.redirect(autorizeUrl.toString());
});


// 認可サーバーから認可コードを受け取り、Access Token に交換する処理
router .get("/callback", async (req, res) => {


    const decision = req.query.decision as string;

    if(decision === "deny"){
        return res.status(403).send("ユーザーがアクセスを拒否しました");
    }

    const code = req.query.code as string;

    // 認可コードを取得できなかった場合
    if(!code){
        return res.status(400).send("認可コードが取得できませんでした");
    }
    // 認可コードと Access Token の交換を試みる
    try {
        const token = await exchangeCodeForToken(code);

        // Access Token をクッキーに保存する
        res.cookie("access_token", token, { httpOnly: true, maxAge: 3600 * 1000 }); // 1時間
        res.redirect("/");

    } catch (error) {
        res.status(500).send("Access token の交換に失敗しました");
    }
});


router.get("/fortune", async (req, res) => {
    const token = req.cookies.access_token;
    if (!token) return res.redirect("/login");

    const data = await fetchResources(token);
    if (!data) return res.redirect("/login");

    const profile = data.profile;
    const hasFullAccess = profile.birthday !== undefined;

    const fortuneSection = hasFullAccess
        ?  `<div class="fortune-box">
              <p class="fortune-label">誕生日: ${profile.birthday}</p>
              <p class="fortune-text">${generateFortune(profile.name, profile.birthday)}</p>
            </div>`
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


router.get("/logout", (req, res) => {
    res.clearCookie("access_token");
    res.redirect("/");
});

export default router;
