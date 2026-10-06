import express from "express";
import { getJwks } from "../services/jwks";

const router = express.Router();

router.get("/jwks.json", (req, res) => {
    // 公開鍵はキャッシュされてよいので、短めのCache-Controlを付ける
    res.set("Cache-Control", "public, max-age=300");
    res.json(getJwks());
});

export default router;