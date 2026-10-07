# OAuth 2.0・OpenID Connect編

このディレクトリには、第5弾「OAuth 2.0編」と第6弾「OpenID Connect（OIDC）編」の実装がまとまっています。OIDCはOAuth 2.0の実装の**上に**機能を足す形で作ったため（OAuthのコードをコピーして、ほぼ同じコードを二重に持つのを避けたかったため）、フォルダ名は`oauth`のままにしています。以下では、OAuth 2.0編、OIDC編の順に説明します。

OAuth 2.0（認可コードフロー）の仕組みを、**実装・観察・攻撃・対策**の流れで体験するハンズオンです。

Node.js（TypeScript）で認可サーバー・リソースサーバー・クライアントの3つを自作し、占いアプリ（Fortune App）がユーザーの誕生日などをプロフィール情報として取得するシナリオで、認可コードフローを一通り動かします。そのうえで`redirect_uri`の検証不備・`state`未検証によるCSRF・認可コードの使い回し・PKCEなしでの認可コード横取りといった実装依存の脆弱性を再現し、RFC 6749/6750/7636に沿った対策を入れて塞いでいきます。

OIDC編では、この実装に署名鍵のJWKS配布・IDトークンの発行と検証・UserInfo・Discoveryを足して、「誰がログインしたか」までクライアント自身が検証して確かめられるようにします。そのうえで、`nonce`や`aud`の検証をわざと外した実装を作り、IDトークンのリプレイやトークンの取り違えといった攻撃を再現します。

## 関連記事

このディレクトリの内容は、次の記事にまとめています。理論編で仕組みを整理し、実践編でこのディレクトリの実装を作っています。

### OAuth 2.0（第5弾）

* 理論編 Part1：[OAuth 2.0とは？認可コードフローの流れをわかりやすく](https://zenn.dev/shogo00713/articles/openauthorization-theory1)
* 理論編 Part2：[OAuth 2.0のセキュリティ：PKCE・stateが必要な理由](https://zenn.dev/shogo00713/articles/openauthorization-theory2)
* 実践編 Part1：[OAuth 2.0の認可サーバーとクライアントを自作してフローを追う](https://zenn.dev/shogo00713/articles/openauthorization-forge1)
* 実践編 Part2：[OAuth 2.0の自作認可サーバーに実際に攻撃して、PKCE・state などの対策を入れる](https://zenn.dev/shogo00713/articles/openauthorization-forge2)

### OpenID Connect（第6弾）

* 理論編：[OpenID Connectとは？OAuthとの違いとIDトークンの仕組み](https://zenn.dev/shogo00713/articles/openidconnect-theory)
* 実践編：[自作した OAuth 認可基盤に OpenID Connect を足して、ID トークンを検証する](https://zenn.dev/shogo00713/articles/openidconnect-forge)

## 使用技術

* Node.js + TypeScript（Express）
* `jsonwebtoken`ライブラリ（アクセストークンはJWT / RS256）
* `express-session`（クライアント側のトークン保管）
* Browser DevTools
* Python（検証・攻撃スクリプト）
* OpenSSL（RS256用の鍵ペア生成）
* OpenID Connect（IDトークン・UserInfo・Discovery）
* JWKS（JSON Web Key Set。署名検証用の公開鍵を`kid`付きで配布する）
* Pythonで書いたモック認可サーバー（`scripts/mock_as.py`。細工したIDトークンを返し、クライアントの検証を確かめる）

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
│       │   ├── token.ts
│       │   ├── jwks.ts
│       │   ├── discovery.ts
│       │   └── userinfo.ts
│       ├── services/
│       │   ├── authorizeRequest.ts
│       │   ├── authorizationCodeStore.ts
│       │   ├── refreshTokenStore.ts
│       │   ├── tokenService.ts
│       │   ├── verifyCredentials.ts
│       │   └── jwks.ts
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
│           ├── scopeFilter.ts
│           ├── jwksClient.ts
│           └── discoveryClient.ts
├── client/                      # クライアント: Fortune App (:3000)
│   └── src/
│       ├── index.ts
│       ├── config.ts
│       ├── routes/
│       │   └── auth.ts
│       ├── services/
│       │   ├── oauthclient.ts
│       │   ├── resourceClient.ts
│       │   ├── fortune.ts
│       │   ├── idTokenVerifier.ts
│       │   ├── jwksClient.ts
│       │   ├── discoveryClient.ts
│       │   └── userinfoClient.ts
│       └── views/
├── scripts/
│   ├── common.py
│   ├── check_redirect_uri.py
│   ├── check_state_csrf.py
│   ├── check_code_reuse.py
│   ├── check_pkce.py
│   ├── check_refresh_rotation.py
│   ├── check_iss.py
│   ├── check_userinfo.py
│   ├── check_rs_token.py
│   ├── check_client_id_token.py
│   ├── check_nonce.py
│   ├── check_id_token_aud.py
│   ├── check_token_confusion.py
│   ├── mock_as.py
│   ├── show_token.py
│   └── evil_consent_form.html
└── README.md
```

OIDC編で追加した主なファイルは次のとおりです。

* 認可サーバー: `routes/jwks.ts`・`routes/discovery.ts`・`routes/userinfo.ts`・`services/jwks.ts`
* リソースサーバー・クライアント（それぞれに同じ役割のものを置いています）: `services/jwksClient.ts`・`services/discoveryClient.ts`
* クライアント: `services/idTokenVerifier.ts`・`services/userinfoClient.ts`
* `scripts/`: `show_token.py`・`mock_as.py`・`check_userinfo.py`・`check_rs_token.py`・`check_client_id_token.py`・`check_nonce.py`・`check_id_token_aud.py`・`check_token_confusion.py`

## ハンズオンの流れ（OAuth 2.0編）

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

## ハンズオンの流れ（OpenID Connect編）

ここまでのOAuth 2.0の実装の上に、OpenID Connect（OIDC）を次の6ステップで足していきます（実践編の「ステップ1〜6」に対応しています）。

### 1. JWKSで署名鍵を配布する

認可サーバーに`GET /jwks.json`を追加し、署名用の公開鍵を**JWKS**（JSON Web Key Set）として公開します。鍵には`oidc-key-1`という`kid`を付け、発行するトークンの署名ヘッダーにも同じ`kid`を載せます。リソースサーバーは、固定の公開鍵で検証する方式をやめ、JWKSを取得してトークンの`kid`に対応する鍵で検証する方式に書き直します（鍵は`kid`ごとにキャッシュし、未知の`kid`が来たときだけ取得し直します）。`show_token.py`で、発行したトークンのヘッダーに`kid`が載っていることを確認します。

### 2. IDトークンを発行する

クライアントが認可リクエストの`scope`に必ず`openid`を付ける形にし、このクライアントはOIDCとしてしか動かないようにします。認可サーバーは、`openid`を含む認可リクエストに`nonce`を必須とし、形式を確認します。認可コードの発行時に`auth_time`を記録して`nonce`とともに認可コードに紐づけて保存し、トークンエンドポイントで認可コードを交換するときに、アクセストークンに加えて**IDトークン**を発行します。IDトークンには`iss`・`sub`・`aud`・`exp`・`iat`に加えて`nonce`と`auth_time`を載せ、`scope`は載せません。あわせてアクセストークンにも`aud`を足し、クライアント宛てのIDトークンと宛先を分けます。

### 3. クライアントでIDトークンを検証する

IDトークンは、クライアントが自分で検証して初めて意味を持ちます。クライアントに検証サービス（`idTokenVerifier.ts`）を追加し、`kid`に対応する鍵をJWKSから取得して、署名（RS256のみ）・`iss`・`aud`・`exp`を検証し、必須クレームの存在と`nonce`の一致も確認します。検証に成功したときだけ`sub`と`auth_time`をセッションに保存し、IDトークンの文字列そのものは保存しません。

### 4. UserInfoとDiscoveryを実装する

認可サーバーに**UserInfo**（`GET /userinfo`）を追加します。アクセストークンを提示すると、`openid`スコープがなければエラー、`openid`だけなら`sub`のみ、`profile:basic`・`profile:full`もあれば`preferred_username`も返します。クライアントは、UserInfoの`sub`がIDトークンの`sub`と一致することを確認します（OIDC Core 5.3.2）。さらに、各エンドポイントのURLと対応方式を公開する**Discovery**（`GET /.well-known/openid-configuration`）を追加し、クライアントとリソースサーバーは、URLを直書きする代わりにDiscoveryから取得する形に切り替えます。取得した`issuer`が設定値と完全一致しなければエラーにします（OIDC Discovery 4.3）。

### 5. 動作確認する

まずブラウザとDevToolsで、同意画面に「あなたが誰かの確認（ログイン）」の項目が増えること、認可サーバーへのリダイレクトURLに`scope=openid`と`nonce`が加わること、占い結果の画面に認証時刻・ログイン名・ユーザーIDが表示されることを観察します。Discovery・JWKSはブラウザで、UserInfoはアクセストークンを付けて`curl`で確認します。

次に、エッジケースをスクリプトで確かめます。`check_userinfo.py`と`check_rs_token.py`で、別の鍵での署名・`alg=none`・期限切れ・`iss`や`aud`の食い違い・IDトークンの流用といった細工したトークンが、UserInfoとリソースサーバーに弾かれることを確認します。この過程で、`jwt.verify`が`exp`の無いトークンを通してしまう穴が見つかるので、`exp`・`iat`・`sub`・`scope`といった必須クレームの存在を自分で確認するコードを足して塞ぎます（UserInfoも同様です）。

クライアントのIDトークン検証は、細工したIDトークンを返すモック認可サーバー（`mock_as.py`）に向けたテスト用クライアントを別ポートで起動し、`check_client_id_token.py`で確認します。`nonce`・`aud`・`iss`の不一致、署名やアルゴリズムの細工、UserInfoの`sub`の食い違い、Discoveryの`issuer`の不一致などが弾かれます。

### 6. 実装をわざと壊して攻撃を再現する

検証をわざと外した実装を用意し、何が通ってしまうかを再現します。外す箇所は、環境変数の**危険スイッチ**（クライアントの`INSECURE_SKIP_NONCE_CHECK=1`・`INSECURE_SKIP_AUD_CHECK=1`、リソースサーバーの`INSECURE_SKIP_AUD_CHECK=1`）で切り替えます。既定ではすべてオフで、オンにすると起動時に警告を出します。検証スクリプトは、スイッチをオンにしたテスト用のクライアントやリソースサーバーを別ポートで起動して試します。

* **`nonce`の未検証**（`check_nonce.py`）: 過去のログインで発行された有効なIDトークンを差し込まれ、他人のIDトークンでログインが成立してしまうこと（IDトークンのリプレイ）を再現します。`state`は別の層で守っているので、`nonce`を外しても`state`の不一致は弾かれることも確認します。
* **`aud`の未検証**（`check_id_token_aud.py`）: 別のクライアント宛てのIDトークンや、リソースサーバー宛てのトークンをIDトークンとして渡しても、ログインが成立してしまうことを再現します。
* **トークンの取り違え**（`check_token_confusion.py`）: リソースサーバーが`aud`を確認しないと、`scope`を載せたIDトークンや別のAPI宛てのアクセストークンでも、データを取得できてしまうことを再現します。本物のIDトークンは`scope`を持たないため、`aud`の確認を外しても必須クレームの確認で弾かれ、2つの検証が独立した二重の防御になっていることも確認します。

## このハンズオンで学ぶこと

* 認可コードフローの全体像（認可サーバー・リソースサーバー・クライアント・ユーザーの4者の役割）
* 認可とスコープ、そして「認証ではない」というOAuth 2.0の立ち位置
* `redirect_uri`は完全一致で検証し、不正なときはエラーを返してリダイレクトしないこと
* `state`・認可コードのワンタイム化・PKCEが、それぞれ何の攻撃を防いでいるのか
* アクセストークンを短命にし、リフレッシュトークンのローテーションで補う設計
* 入力値をそのままHTMLに埋め込まない・同じ検証をGETとPOSTの両方に適用するといった、実装レベルの落とし穴
* OIDCは、OAuth 2.0の上に「誰がログインしたか」を伝える仕組み（IDトークン）を足したものであること
* IDトークンは受け取るだけでは認証にならず、クライアントが署名・`iss`・`aud`・`exp`・`nonce`を自分で検証して初めて成立すること
* `state`（CSRF対策）と`nonce`（IDトークンのリプレイ対策）は、似たランダム値でも守る対象が違うこと
* `aud`で「このトークンは自分宛てか」を確かめないと、別の宛先向けのトークンを受け入れてしまうこと
* 署名鍵をJWKSと`kid`で配布し、Discoveryでエンドポイントの在りかを知る設計
* IDトークンとUserInfoの役割の違いと、両者の`sub`を突き合わせる確認
* `jwt.verify`だけでは必須クレームの欠落（`exp`が無いトークンなど）まで防げないため、自分で確認するコードを足す必要があること

> **注意:** このハンズオンでは、すべて自分で構築したローカル環境・テストアカウントのみを対象とします。
