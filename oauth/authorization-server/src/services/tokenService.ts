import jwt, { type SignOptions } from "jsonwebtoken";
import { TOKEN_EXPIRES_IN, PRIVATE_KEY} from "../config";

// アクセストークンを発行する関数 (署名はRS256で固定)
export function issueAccessToken(payload: { sub: string, scope: string }): string {
    return jwt.sign(payload, PRIVATE_KEY!, {
        algorithm: "RS256",
        expiresIn: TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
    });
}