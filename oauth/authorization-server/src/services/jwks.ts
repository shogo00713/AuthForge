import crypto from "crypto";
import { PUBLIC_KEY } from "../config";

// 鍵のID (鍵が1本だけなので固定値)
export const KID = "oidc-key-1";

// この公開鍵の情報をエンドポイントとして公開する
const jwk = crypto.createPublicKey(PUBLIC_KEY).export({ format: "jwk" });

export function getJwks() {
    return {
        keys: [
            {
                kty: jwk.kty,
                e: jwk.e,
                n: jwk.n,
                alg: "RS256",
                use: "sig",
                kid: KID,
            },
        ],
    };
}
