# Basic認証編

Basic認証の仕組みを、**実装・観察・攻撃・対策**の流れで体験するハンズオンです。

Apache + Dockerを使ってBasic認証を構築し、ブラウザのDevToolsやWiresharkで通信を観察します。さらに、HTTP通信では認証情報がどのように送信されるのかを確認し、HTTPS化によってどのように保護されるのかを比較します。

## 使用技術

* Docker Compose
* Apache HTTP Server (`httpd:2.4`)
* Browser DevTools
* Wireshark / tcpdump
* Python
* mkcert

## ディレクトリ構成

```text
basic/
├── docker-compose.yml
├── httpd.conf
├── www/
│   ├── .htaccess
│   └── index.html
├── scripts/
│   └── decode_auth_header.py
└── README.md
```

## ハンズオンの流れ

### 1. Apache + `.htaccess` でBasic認証を構築

Docker上でApacheを起動し、`.htaccess` と `.htpasswd` を使ってBasic認証を設定します。

### 2. DevToolsでHTTPヘッダーを観察

ブラウザのNetworkタブから、リクエストに含まれる

```text
Authorization: Basic <Base64文字列>
```

を確認します。

### 3. パケットキャプチャで通信を観察

Wireshark / tcpdumpを利用してHTTP通信をキャプチャし、TCPストリームからAuthorizationヘッダーを確認します。

### 4. PythonでAuthorizationヘッダーを解析

取得したBase64文字列をデコードし、送信されたユーザー名とパスワードを復元します。

```text
username:password
```

の形式で認証情報が送信されていることを確認します。

### 5. 傍受した認証情報を使ってアクセス

別のテストユーザーを用意し、通信から取得した認証情報を使って認証を通過できることを確認します。

### 6. HTTPS化して再検証

`mkcert` で証明書を作成し、ApacheをHTTPS化します。

HTTPの場合と同じように通信を観察し、

* DevToolsではAuthorizationヘッダーを確認できる
* パケットキャプチャではHTTPのように中身を直接確認できない
* HTTPSでは通信内容が暗号化される

といった違いを確認します。

## このハンズオンで学ぶこと

* Basic認証の基本的な仕組み
* `Authorization` ヘッダーの役割
* Base64は暗号化やハッシュではなく、可逆なエンコードであること
* HTTP通信における認証情報の漏洩リスク
* HTTPSが通信をどのように保護するか
* 認証方式と通信路の暗号化は別の問題であること

> **注意:** このハンズオンでは、すべて自分で構築したローカル環境・テストアカウントのみを対象とします。
