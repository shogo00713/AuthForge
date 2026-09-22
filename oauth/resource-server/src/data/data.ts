export type BloodType = "A" | "B" | "O" | "AB";

export interface Profile {
  id: string;
  name: string;
  birthday: string; // YYYY-MM-DD
  bloodType: BloodType;
  favoriteFood: string;
  motto: string;
}

// 架空のプロフィールデータ

export const profiles: Profile[] = [
  {
    id: "u01",
    name: "佐伯 陽菜",
    birthday: "1994-03-12",
    bloodType: "A",
    favoriteFood: "抹茶ロールケーキ",
    motto: "石の上にも三年",
  },
  {
    id: "u02",
    name: "黒田 蓮",
    birthday: "1988-11-05",
    bloodType: "B",
    favoriteFood: "豚骨ラーメン",
    motto: "七転び八起き",
  },
  {
    id: "u03",
    name: "三上 優子",
    birthday: "1979-07-22",
    bloodType: "O",
    favoriteFood: "天ぷらそば",
    motto: "継続は力なり",
  },
  {
    id: "u04",
    name: "東雲 悠真",
    birthday: "2001-01-30",
    bloodType: "AB",
    favoriteFood: "タコライス",
    motto: "一期一会",
  },
  {
    id: "u05",
    name: "早乙女 千夏",
    birthday: "1996-09-08",
    bloodType: "A",
    favoriteFood: "生姜焼き定食",
    motto: "初心忘るべからず",
  },
  {
    id: "u06",
    name: "桐生 大和",
    birthday: "1985-04-17",
    bloodType: "O",
    favoriteFood: "味噌カツ",
    motto: "温故知新",
  },
  {
    id: "u07",
    name: "白鳥 美月",
    birthday: "2000-12-25",
    bloodType: "B",
    favoriteFood: "いちごのショートケーキ",
    motto: "為せば成る",
  },
  {
    id: "u08",
    name: "神楽坂 拓海",
    birthday: "1992-06-03",
    bloodType: "AB",
    favoriteFood: "カツカレー",
    motto: "有言実行",
  },
  {
    id: "u09",
    name: "星野 あおい",
    birthday: "1990-02-14",
    bloodType: "A",
    favoriteFood: "塩ラーメン",
    motto: "明日は明日の風が吹く",
  },
  {
    id: "u10",
    name: "六道 慧",
    birthday: "1983-10-09",
    bloodType: "O",
    favoriteFood: "餃子",
    motto: "泰然自若",
  },
  {
    id: "u11",
    name: "Bob",
    birthday: "1995-05-15",
    bloodType: "B",
    favoriteFood: "Pizza",
    motto: "Keep it simple.",
  },
];