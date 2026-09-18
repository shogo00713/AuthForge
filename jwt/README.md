# JWT編

JWTの発行・検証の仕組みを、**実装・観察・攻撃・対策**の流れで体験するハンズオンです。

Node.js（TypeScript）でJWTの発行・検証サーバーを構築し、DevToolsやjwt.io、Wiresharkで観察したうえで、Pythonで署名の検証ロジックを自作します。さらに`alg: none`・アルゴリズム混同・弱い鍵のオフライン攻撃という実装依存の脆弱性を再現し、最後にJWT特有の「失効の難しさ」を確認します。

## 使用技術

* Docker Compose
* Node.js + TypeScript（Express）
* `jsonwebtoken`ライブラリ
* Browser DevTools / jwt.io
* Wireshark
* Python（検証・攻撃スクリプト）
* OpenSSL（RS256用の鍵ペア生成）

## ディレクトリ構成

```text
jwt/
├── docker-compose.yml
├── server/
│   ├── package.json
│   └── src/
│       ├── index.ts
├── public/
│   ├── index.html
├── scripts/
│   ├── decode_jwt.py
│   ├── verify_jwt_hs256.py
│   ├── crack_jwt_secret.py
│   └── forge_alg_confusion.py
└── README.md
```

## ハンズオンの流れ

### 1. Node.js（TypeScript）でJWT発行・検証サーバー構築

Express + `jsonwebtoken`で`/login`と`/me`を実装し、HS256でJWTを発行・検証できるところから始めます。

### 2. DevTools/jwt.ioでJWTの中身を観察

発行したJWTをjwt.ioやブラウザで確認し、Header/PayloadがBase64URLエンコードされているだけで、暗号化はされていないことを確認します。

### 3. Wireshark/tcpdumpで通信を観察

`Authorization: Bearer <JWT>`が平文で流れることを確認し、盗聴されればそのまま使われてしまうリスクを整理します。

### 4. 実装依存の脆弱性を再現する

`alg: none`を許容してしまう実装や、RS256の公開鍵をHMACの共通鍵として悪用するアルゴリズム混同攻撃を再現し、`alg`のホワイトリスト固定で防げることを確認します。

### 5. 弱い署名鍵のオフライン攻撃を体験する

弱い共通鍵でJWTを発行し、発行済みトークンだけを材料にワードリストで鍵をオフライン推測できてしまうことを確認します。

### 6. 失効の難しさを体験する

無効化したユーザーのJWTが`exp`まで有効であり続けることを確認し、ブラックリストやリフレッシュトークンのトレードオフを整理します。

## このハンズオンで学ぶこと

* JWTの基本構成(Header/Payload/Signature)とBase64URLエンコード
* 署名は改ざん検知のためのものであり、内容を秘匿するものではないこと
* `alg`ヘッダーの扱いを誤ると、`alg: none`やアルゴリズム混同で簡単に突破されてしまうこと
* 弱い署名鍵はオフラインで容易に推測されてしまうこと
* ステートレスであることの代償としての、即時失効の難しさ

> **注意:** このハンズオンでは、すべて自分で構築したローカル環境・テストアカウントのみを対象とします。