"""
認可コード使い回し(リプレイ・二重使用)のテスト

使い方は check_redirect_uri.py と同じ環境変数。
    cd oauth/scripts
    AS_URL=http://localhost:4000 \
    CLIENT_ID=fortune-app \
    CLIENT_SECRET=<.env の FORTUNE_APP_CLIENT_SECRET> \
    REDIRECT_URI=http://localhost:3000/callback \
    TEST_USERNAME=Bob \
    TEST_PASSWORD=<config.ts の Bob のパスワード> \
    python3 check_code_reuse.py
"""

import sys
import threading

from common import (
    exchange_code,
    login_and_get_code,
    report,
    summary,
)


def test_a_sequential_reuse():
    """A: 同じコードを逐次2回交換する(基本の使い回し)"""
    code = login_and_get_code()
    if not code:
        report("A[sequential reuse]: 認可コード使い回し", False, "前提の認可コード取得に失敗")
        return

    first = exchange_code(code)
    second = exchange_code(code)

    # 1回目は成功し、2回目は invalid_grant で弾かれているべき
    vulnerable = first.status_code == 200 and second.status_code == 200
    report(
        "A[sequential reuse]: 同じコードを2回連続で交換",
        vulnerable,
        f"1回目={first.status_code} 2回目={second.status_code} body2={second.text[:150]}",
    )


def test_b_concurrent_double_spend():
    """B: 同じコードを同時に(並行して)交換し、2つとも成功しないか"""
    code = login_and_get_code()
    if not code:
        report("B[concurrent double-spend]: 認可コード二重発行", False, "前提の認可コード取得に失敗")
        return

    results = [None, None]

    def worker(idx: int):
        results[idx] = exchange_code(code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    # できるだけ同時に発火させる
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    success_count = sum(1 for r in results if r is not None and r.status_code == 200)
    vulnerable = success_count >= 2
    report(
        "B[concurrent double-spend]: 同時リクエストでの二重発行",
        vulnerable,
        f"成功数={success_count}/2 statuses={[r.status_code if r else None for r in results]}",
    )


def test_c_repeated_reuse():
    """C: 使用済みコードへの繰り返し攻撃(3回)がすべて弾かれ続けるか"""
    code = login_and_get_code()
    if not code:
        report("C[repeated reuse]: 繰り返し使い回し", False, "前提の認可コード取得に失敗")
        return

    first = exchange_code(code)
    retries = [exchange_code(code) for _ in range(3)]

    vulnerable = first.status_code == 200 and any(r.status_code == 200 for r in retries)
    report(
        "C[repeated reuse]: 使用済みコードへの3回の再試行",
        vulnerable,
        f"1回目={first.status_code} retries={[r.status_code for r in retries]}",
    )


if __name__ == "__main__":
    from common import AS_URL

    print(f"=== 認可コード使い回しテスト against {AS_URL} ===\n")
    test_a_sequential_reuse()
    test_b_concurrent_double_spend()
    test_c_repeated_reuse()

    sys.exit(summary())
