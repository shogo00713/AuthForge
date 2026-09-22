import { Profile } from "../data/data";
import { SCOPES } from "../config";

type PartialProfile = Partial<Profile>;

// 指定されたスコープに基づいて、プロフィール情報をフィルタリングする関数
// 現状のプロフィールは、基本情報(Basic)と詳細情報(full)の2つのスコープに分かれている
export function filterProfileByScope(profile: Profile, scope: string): PartialProfile {
    const scopes = scope.split(" ");
    const result: PartialProfile = {};

    if (scopes.includes(SCOPES.BASIC) || scopes.includes(SCOPES.FULL)) {
        result.name = profile.name;
        result.favoriteFood = profile.favoriteFood;
    }

    if (scopes.includes(SCOPES.FULL)) {
        result.birthday = profile.birthday;
        result.bloodType = profile.bloodType;
        result.motto = profile.motto;
    }
    return result;
}