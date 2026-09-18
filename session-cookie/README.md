# Session/Cookie認証編

Session/Cookieを使った認証の仕組みを、**実装・観察・攻撃・対策**の流れで体験するハンズオンです。

Basic/Digestと違い、認証の仕組みそのものをPythonの標準ライブラリだけで自作するところから始めます。ブラウザのDevToolsやWiresharkで通信を観察したうえで、セッションハイジャック・XSS・セッション固定攻撃・CSRFという4種類の攻撃を実際に成立させ、それぞれの対策を確認します。

## 使用技術

* Docker Compose
* Python標準ライブラリ (`http.server`) による自作サーバー
* Redis（セッションストア）
* Browser DevTools
* Wireshark
* Python（攻撃・検証スクリプト） / 簡単なHTML+JS

## ディレクトリ構成

```text
session-cookie/
├── docker-compose.yml
├── app/
│   ├── server.py
│   ├── templates/
│   │   ├── login.html
│   │   └── dashboard.html
│   └── requirements.txt
├── scripts/
│   ├── hijack_replay.py
│   ├── xss_steal_cookie.html
│   ├── session_fixation_demo.py
│   └── csrf_demo.html
└── README.md
```

## ハンズオンの流れ

### 1. 自作サーバーでSession/Cookie認証を実装

Pythonの標準ライブラリでログイン・セッション発行・Cookie照合・ログアウトまでを自作し、まずは属性なしの素朴な状態から始めます。

### 2. 開発者ツールでヘッダー・属性を観察

`Set-Cookie`の発行、以降のリクエストへの`Cookie`の自動付与、ログアウト時の失効(`Max-Age=0`)などをDevToolsで確認します。

### 3. Wiresharkで通信をキャプチャし、セッションハイジャックを体験する

HTTP環境でセッションIDを盗聴し、それだけでログインなしになりすませることを確認したうえで、`Secure`属性とHTTPS化で成立しなくなることを整理します。

### 4. XSSによるCookie窃取を体験する

入力を無害化しない実装であえてXSSを発生させ、`document.cookie`からセッションIDを盗み出せることを確認し、`HttpOnly`で対策します。

### 5. セッション固定攻撃(Session Fixation)を体験する

ログイン時にセッションIDを再発行しない実装で、攻撃者が用意したIDをそのまま使われてしまうことを確認し、再発行するよう直して対策します。

### 6. CSRFを体験する

`SameSite`未指定のまま別オリジンの罠ページから自動送信フォームで意図しない操作を実行させ、`SameSite=Lax`で防げることを確認します。

### 7. セッションストアをRedisに差し替える

インメモリ実装では再起動や複数プロセス間でセッションが失われることを確認したうえで、Redisに差し替えて状態を共有できるようにします。

## このハンズオンで学ぶこと

* Session/Cookie認証の基本的な仕組み(`Set-Cookie`/`Cookie`ヘッダー、サーバー側のセッションストア)
* セッションIDはパスワードと同格の機密情報であること
* セッションハイジャック・セッション固定・CSRFという、状態を持つこと特有の攻撃手法
* `Secure`/`HttpOnly`/`SameSite`属性とセッションID再発行がそれぞれ何を防ぐか
* インメモリなセッションストアがスケールしない理由と、Redis導入による状態共有

> **注意:** このハンズオンでは、すべて自分で構築したローカル環境・テストアカウントのみを対象とします。