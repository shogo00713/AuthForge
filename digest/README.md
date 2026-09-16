# Digest認証編

Digest認証の仕組みを、**実装・観察・攻撃・対策**の流れで体験するハンズオンです。

Apache + Dockerを使ってDigest認証を構築し、ブラウザのDevToolsやWiresharkで通信を観察します。さらに、Pythonで認証レスポンスの計算を再現し、オフライン攻撃によってDigest認証の限界を確認します。

## 使用技術

* Docker Compose
* Apache HTTP Server (`httpd:2.4`)
* Browser DevTools
* Wireshark / tcpdump
* Python
* mkcert

## ディレクトリ構成

```text
digest/

├── docker-compose.yml
├── httpd.conf
├── www/
│   ├── .htdigest
│   └── index.html
├── scripts/
│   ├── verify_digest_response.py
│   └── crack_digest_offline.py
└── README.md
```

## ハンズオンの流れ

### 1. Apache + `mod_auth_digest` でDigest認証を構築

Docker上でApacheを起動し、`mod_auth_digest`と`.htdigest`を使ってDigest認証を設定します。

### 2. DevToolsでHTTPヘッダーを観察

ブラウザのNetworkタブから、

```text
WWW-Authenticate: Digest ...
Authorization: Digest ...
```

を確認し、`nonce`、`cnonce`、`nc`、`qop`、`response`などDigest認証で使用される値を観察します。

### 3. パケットキャプチャで通信を観察

Wireshark / tcpdumpを利用してHTTP通信をキャプチャし、Digest認証ではパスワードそのものではなく、ハッシュ計算された`response`が送信されていることを確認します。

### 4. PythonでDigestレスポンスを検証

取得した`nonce`、`realm`、`uri`、`nc`、`cnonce`、`qop`などを使って、HA1・HA2・`response`を計算します。

実際にキャプチャした`response`と計算結果を比較し、Digest認証の仕組みを再現します。

### 5. オフライン攻撃を体験

テスト用ユーザーを用意し、キャプチャした認証情報を利用してパスワード候補をオフラインで検証します。

Digest認証ではパスワードそのものは送信されませんが、認証レスポンスを取得されると、弱いパスワードに対して辞書攻撃や総当たり攻撃が可能であることを確認します。

また、取得した`Authorization`ヘッダーを再送し、`nonce`や`nc`によるリプレイ対策についても確認します。

### 6. HTTPSについて整理

Digest認証とHTTPSがそれぞれ何を保護するのかを整理します。

Digest認証はパスワードそのものの送信を避けますが、HTTPでは`nonce`や`response`などの認証情報が平文で流れます。

HTTPSでは通信全体が暗号化されるため、Digest認証とHTTPSを併用する意味を確認します。

## このハンズオンで学ぶこと

* Digest認証の基本的な仕組み
* `nonce`、`cnonce`、`nc`、`qop`の役割
* HA1・HA2・`response`の計算方法
* Basic認証との違い
* Digest認証におけるリプレイ対策
* オフライン辞書・総当たり攻撃の仕組み
* 認証方式と通信路の暗号化は別の問題であること
* Digest認証が現代のWebであまり使われなくなった理由

> **注意:** このハンズオンでは、すべて自分で構築したローカル環境・テストアカウントのみを対象とします。
