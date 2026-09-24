/**
 * 占いを実行するサービス
 * 
 * このサービスは、ユーザーの名前と誕生日をもとに占い結果を生成する機能を提供する
 * 占いと言っているが、実際にはユーザーの名前と誕生日をもとにハッシュ値を生成し、そのハッシュ値を使って占い結果を決定するもので、信憑性はない
 */

import crypto from "crypto";

type Fortune = {
    label: string;
    message: string;
};

const FORTUNES: Fortune[] = [
    { label: "大吉", message: "何をやってもうまくいく日。思い切って挑戦してみましょう。" },
    { label: "中吉", message: "良い流れが来ています。焦らず着実に進めましょう。" },
    { label: "小吉", message: "小さな幸運がありそう。周りへの感謝を忘れずに。" },
    { label: "吉", message: "穏やかで安定した一日になりそうです。" },
    { label: "末吉", message: "今はまだ助走の時期。焦らずコツコツいきましょう。" },
    { label: "凶", message: "少し慎重に。無理せず一歩ずつ進みましょう。" },
    { label: "大凶", message: "今日は守りの日。大きな決断は先延ばしにしましょう。" },
];


export default function generateFortune(name: string, birthday: string): Fortune {

    // 占い？？？？
    const today = new Date().toISOString().slice(0, 10); // "2026-09-22"のような形
    const hash = crypto.createHash("sha256").update(name + birthday + today).digest("hex");
    const hashNumber = parseInt(hash.slice(0, 8), 16);
    return FORTUNES[hashNumber % FORTUNES.length];
}