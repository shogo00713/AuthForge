import jwt, { type SignOptions } from "jsonwebtoken";
import { TOKEN_EXPIRES_IN, PRIVATE_KEY} from "../config";

export function issueAccessToken(payload: { sub: string, scope: string }): string {
    return jwt.sign(payload, PRIVATE_KEY!, {
        algorithm: "RS256",
        expiresIn: TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
    });
}