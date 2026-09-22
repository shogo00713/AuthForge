import crypto from "crypto";

export default function generateFortune(name: string, birthday: string): string {

    const FORTUNES = ["大吉", "中吉", "小吉", "吉", "末吉", "凶", "大凶"];

    // 占い？？？
    const hash = crypto.createHash("sha256").update(name + birthday).digest("hex");
    const hashNumber = parseInt(hash.slice(0, 8), 16);
    const index = hashNumber % FORTUNES.length;
    return FORTUNES[index];
}