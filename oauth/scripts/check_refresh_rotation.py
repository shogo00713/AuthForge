"""
リフレッシュトークンローテーションのテスト

現状(実装前)は refresh_token を使っても新しい refresh_token が
発行されず、古いものをそのまま使い続けられるため、以下は
すべて VULNERABLE になるはず。実装後に再実行し、SAFE に変わることを確認する。

使い方:
    cd oauth/scripts
    AS_URL=http://localhost:4000 \
    CLIENT_ID=fortune-app \
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    REDIRECT_URI=http://localhost:3000/callback \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_refresh_rotation.py
"""

import sys

from common import (
    login_and_get_tokens,
    refresh_token_exchange,
    report,
    summary,
)


def test_a_no_new_refresh_token_issued():
    """A: refresh_token で更新した際、新しい refresh_token が発行されない(=ローテーション無し)ことの確認"""
    tokens = login_and_get_tokens()
    if not tokens or not tokens.get("refresh_token"):
        report("A[ローテーション無し]: 更新時に新しいrefresh_tokenが来ない", False, "前提のトークン取得に失敗")
        return

    resp = refresh_token_exchange(tokens["refresh_token"])
    if resp.status_code != 200:
        report("A[ローテーション無し]: 更新時に新しいrefresh_tokenが来ない", False, f"更新自体が失敗 status={resp.status_code}")
        return

    new_tokens = resp.json()
    vulnerable = "refresh_token" not in new_tokens or not new_tokens.get("refresh_token")
    report(
        "A[ローテーション無し]: refresh_token更新時に新しいrefresh_tokenが発行されない",
        vulnerable,
        f"status={resp.status_code} body_keys={list(new_tokens.keys())}",
    )


def test_b_old_refresh_token_reusable():
    """B: 同じ refresh_token を2回連続で使って、両方成功してしまわないか"""
    tokens = login_and_get_tokens()
    if not tokens or not tokens.get("refresh_token"):
        report("B[使い回し]: 同じrefresh_tokenを2回使える", False, "前提のトークン取得に失敗")
        return

    refresh_token = tokens["refresh_token"]
    first = refresh_token_exchange(refresh_token)
    second = refresh_token_exchange(refresh_token)

    vulnerable = first.status_code == 200 and second.status_code == 200
    report(
        "B[使い回し]: 同じrefresh_tokenを2回連続で使用",
        vulnerable,
        f"1回目={first.status_code} 2回目={second.status_code} body2={second.text[:150]}",
    )


if __name__ == "__main__":
    from common import AS_URL

    print(f"=== リフレッシュトークンローテーションテスト against {AS_URL} ===\n")
    test_a_no_new_refresh_token_issued()
    test_b_old_refresh_token_reusable()

    sys.exit(summary())
