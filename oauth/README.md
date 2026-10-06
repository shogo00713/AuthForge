# OAuth 2.0編

OAuth 2.0（認可コードフロー）の仕組みを、**実装・観察・攻撃・対策**の流れで体験するハンズオンです。

Node.js（TypeScript）で認可サーバー・リソースサーバー・クライアントの3つを自作し、占いアプリ（Fortune App）がユーザーの誕生日などをプロフィール情報として取得するシナリオで、認可コードフローを一通り動かします。そのうえで`redirect_uri`の検証不備・`state`未検証によるCSRF・認可コードの使い回し・PKCEなしでの認可コード横取りといった実装依存の脆弱性を再現し、RFC 6749/6750/7636に沿った対策を入れて塞いでいきます。

## 使用技術

* Node.js + TypeScript（Express）
* `jsonwebtoken`ライブラリ（アクセストークンはJWT / RS256）
* `express-session`（クライアント側のトークン保管）
* Browser DevTools
* Python（検証・攻撃スクリプト）
* OpenSSL（RS256用の鍵ペア生成）

## ディレクトリ構成

```text
oauth/
├── package.json
├── authorization-server/        # 認可サーバー (:4000)
│   └── src/
│       ├── index.ts
│       ├── config.ts
│       ├── routes/
│       │   ├── authorize.ts
│       │   └── token.ts
│       ├── services/
│       │   ├── authorizeRequest.ts
│       │   ├── authorizationCodeStore.ts
│       │   ├── refreshTokenStore.ts
│       │   ├── tokenService.ts
│       │   └── verifyCredentials.ts
│       ├── views/
│       │   └── index.html
│       └── keys/
├── resource-server/             # リソースサーバー (:4001)
│   └── src/
│       ├── index.ts
│       ├── config.ts
│       ├── data/
│       ├── routes/
│       │   └── resources.ts
│       └── services/
│           ├── verifyToken.ts
│           └── scopeFilter.ts
├── client/                      # クライアント: Fortune App (:3000)
│   └── src/
│       ├── index.ts
│       ├── config.ts
│       ├── routes/
│       │   └── auth.ts
│       ├── services/
│       │   ├── oauthclient.ts
│       │   ├── resourceClient.ts
│       │   └── fortune.ts
│       └── views/
├── scripts/
│   ├── common.py
│   ├── check_redirect_uri.py
│   ├── check_state_csrf.py
│   ├── check_code_reuse.py
│   ├── check_pkce.py
│   ├── check_refresh_rotation.py
│   └── evil_consent_form.html
└── README.md
```

## ハンズオンの流れ

### 1. 認可サーバー・リソースサーバー・クライアントを構築する

認可サーバー（認可エンドポイント・トークンエンドポイント）、リソースサーバー（`/resources`）、クライアント（`/login`・`/callback`）をそれぞれ実装し、認可コードを`access_token`に交換して、プロフィール情報を取得できるところまで動かします。アクセストークンはRS256のJWTで発行し、リソースサーバーは公開鍵だけで検証します。

### 2. スコープとリフレッシュトークンを実装する

`profile:basic`と`profile:full`の2つのスコープで、取得できる項目を出し分けます。さらに、アクセストークンの期限切れをリフレッシュトークンで更新する流れを、認可サーバーとクライアントの両方に実装します。

### 3. RFC 6749/6750に沿ったエラー応答とトークンの扱いを整える

`invalid_client`・`invalid_grant`・`invalid_token`などのエラー応答と`WWW-Authenticate`ヘッダー、`Cache-Control: no-store`を、RFCに合わせて整えます。クライアント側では、トークンをブラウザに渡さずサーバー側のセッションに保管します。

### 4. `redirect_uri`の検証不備を攻撃する

`redirect_uri`の検証が甘い（前方一致・POST側の検証漏れ）と、認可コードが攻撃者のサーバーに渡ったり、オープンリダイレクトに悪用されたりすることを再現します。登録済みURIとの**完全一致**による検証と、不正な場合は絶対にリダイレクトしないことで防げることを確認します。

### 5. 認可コードの使い回しを攻撃する

同じ認可コードで複数回トークンを取得できてしまう実装を再現します。認可コードを**ワンタイム化**し、並行リクエストでの二重消費でも成功が1回だけになることを確認します。

### 6. `state`未検証によるCSRFを攻撃する

`state`を検証しないクライアントに、攻撃者が用意した認可コードを流し込み、被害者のセッションを攻撃者のアカウントに紐づけるCSRFを再現します。ログイン開始時に`state`を生成してセッションに保存し、コールバックで照合することで防げることを確認します。

### 7. PKCEで認可コードの横取りを防ぐ

認可コードだけを盗まれた場合に、攻撃者が単独でトークンに交換できてしまうことを再現します。`code_challenge`（S256）と`code_verifier`によるPKCE（RFC 7636）を実装し、`plain`へのダウングレードや`code_verifier`の省略も拒否できることを確認します。

### 8. リフレッシュトークンローテーションを実装する

リフレッシュトークンを使い回せてしまう実装を再現し、更新のたびに新しいリフレッシュトークンを発行して古いものを失効させる**ローテーション**を実装します。

### 9. 実装を見直し、抜け漏れを塞ぐ

自作した実装を振り返り、同意画面のXSS（`state`などの未エスケープ）、POST側の`scope`再検証漏れ、パスワード間違い時に再入力画面へ戻れない問題、クライアントがローテーション後のリフレッシュトークンを捨てていた問題などを洗い出して修正します。あわせてアクセストークンに`iss`を載せ、有効期限の単位を秒に統一します。

## このハンズオンで学ぶこと

* 認可コードフローの全体像（認可サーバー・リソースサーバー・クライアント・ユーザーの4者の役割）
* 認可とスコープ、そして「認証ではない」というOAuth 2.0の立ち位置
* `redirect_uri`は完全一致で検証し、不正なときはエラーを返してリダイレクトしないこと
* `state`・認可コードのワンタイム化・PKCEが、それぞれ何の攻撃を防いでいるのか
* アクセストークンを短命にし、リフレッシュトークンのローテーションで補う設計
* 入力値をそのままHTMLに埋め込まない・同じ検証をGETとPOSTの両方に適用するといった、実装レベルの落とし穴

> **注意:** このハンズオンでは、すべて自分で構築したローカル環境・テストアカウントのみを対象とします。
