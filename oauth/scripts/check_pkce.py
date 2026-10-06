"""
PKCE (RFC 7636) のテスト

現状(実装前)は code_challenge / code_verifier という概念自体が
AS に存在しないため、以下はすべて VULNERABLE になるはず。
これを実装した後に再実行し、SAFE に変わることを確認する。

使い方:
    cd oauth/scripts
    AS_URL=http://localhost:4000 \
    CLIENT_ID=fortune-app \
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    REDIRECT_URI=http://localhost:3000/callback \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_pkce.py
"""

import sys

from common import (
    code_challenge_s256,
    exchange_code,
    generate_code_verifier,
    login_and_get_code,
    report,
    summary,
)


def test_a_no_pkce_at_all():
    """A: code_challenge を一切付けずに認可した上で、
    code_verifier も付けずにトークン交換できてしまわないか
    (PKCE 自体が必須化されていないことの確認)"""
    code = login_and_get_code()
    if not code:
        report("A[PKCE無し]: code_verifier無しで交換", False, "前提の認可コード取得に失敗")
        return

    resp = exchange_code(code)
    vulnerable = resp.status_code == 200
    report(
        "A[PKCE無し]: code_challenge/code_verifier を一切使わずに交換",
        vulnerable,
        f"status={resp.status_code} body={resp.text[:150]}",
    )


def test_b_wrong_code_verifier():
    """B: 正規に code_challenge 付きで認可したのに、
    トークン交換時に全く違う code_verifier を使っても通ってしまわないか
    (盗んだ認可コードを、正しい verifier を知らない第三者が使えてしまうケースの再現)"""
    correct_verifier = generate_code_verifier()
    challenge = code_challenge_s256(correct_verifier)

    code = login_and_get_code(
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    if not code:
        report("B[verifier不一致]: 違うcode_verifierで交換", False, "前提の認可コード取得に失敗")
        return

    attacker_verifier = generate_code_verifier()  # 正しい verifier とは別物
    resp = exchange_code(code, code_verifier=attacker_verifier)
    vulnerable = resp.status_code == 200
    report(
        "B[verifier不一致]: 間違った code_verifier で交換",
        vulnerable,
        f"status={resp.status_code} body={resp.text[:150]}",
    )


def test_c_missing_code_verifier():
    """C: 正規に code_challenge 付きで認可したのに、
    トークン交換時に code_verifier を省略しても通ってしまわないか"""
    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)

    code = login_and_get_code(
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    if not code:
        report("C[verifier省略]: code_verifier無しで交換", False, "前提の認可コード取得に失敗")
        return

    resp = exchange_code(code)  # code_verifier を付けない
    vulnerable = resp.status_code == 200
    report(
        "C[verifier省略]: code_challenge付きなのに code_verifier を省略して交換",
        vulnerable,
        f"status={resp.status_code} body={resp.text[:150]}",
    )


def test_d_plain_method_downgrade():
    """D: code_challenge_method=plain(ダウングレード)が許されてしまわないか
    plain の場合、code_verifier == code_challenge の生の文字列一致になるため、
    盗聴者が code_challenge(平文)を見ただけで検証を突破できてしまう"""
    verifier = generate_code_verifier()
    # plain の場合、challenge は verifier そのもの
    code = login_and_get_code(
        code_challenge=verifier,
        code_challenge_method="plain",
    )
    if not code:
        report("D[plainダウングレード]: plain方式が通る", False, "前提の認可コード取得に失敗(SAFE寄り)")
        return

    # 認可コードと code_challenge(=verifier そのもの)さえ分かれば、
    # 正規クライアントでなくても verifier を "知っている" ことになってしまう
    resp = exchange_code(code, code_verifier=verifier)
    vulnerable = resp.status_code == 200
    report(
        "D[plainダウングレード]: code_challenge_method=plain が許可される",
        vulnerable,
        f"status={resp.status_code} body={resp.text[:150]}",
    )


if __name__ == "__main__":
    from common import AS_URL

    print(f"=== PKCE テスト against {AS_URL} ===\n")
    test_a_no_pkce_at_all()
    test_b_wrong_code_verifier()
    test_c_missing_code_verifier()
    test_d_plain_method_downgrade()

    sys.exit(summary())
