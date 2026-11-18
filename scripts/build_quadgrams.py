"""영어 quadgram(4글자 연속) 통계표를 만든다.

치환 암호 솔버가 "이 문자열이 얼마나 영어다운가"를 점수 매길 때 쓴다.
원문은 Project Gutenberg 의 공개 도메인 소설들(GITenberg 미러)이다.

사용법:
    python3 scripts/build_quadgrams.py <책 txt 파일들...>
    → src/data/quadgrams.js 생성

출력 형식 (용량을 줄이려고 압축):
    QUADS  : 상위 N개 quadgram 을 이어 붙인 문자열 (4글자씩)
    SCORES : 각 quadgram 의 log10 확률을 0~255 로 양자화한 값 (base64)
    MIN, MAX : 양자화 범위,  FLOOR : 표에 없는 quadgram 의 log10 확률
"""

import base64
import collections
import math
import pathlib
import re
import sys

TOP_N = 40000
TOP_WORDS = 15000


def body(text: str) -> str:
    # 구텐베르크 머리말/꼬리말 제거
    start = re.search(r"\*\*\* ?START OF[^\n]*\n", text)
    end = re.search(r"\*\*\* ?END OF", text)
    return text[start.end() if start else 0 : end.start() if end else len(text)]


def main(paths):
    counts = collections.Counter()
    words = collections.Counter()
    for p in paths:
        text = body(pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")).upper()
        letters = re.sub(r"[^A-Z]", "", text)
        counts.update(letters[i : i + 4] for i in range(len(letters) - 3))
        words.update(w for w in re.findall(r"[A-Z]+", text) if len(w) >= 2 or w in ("A", "I"))
    # CTF 에서 자주 나오는 단어도 넣어 둔다
    extra = "FLAG CTF KEY XOR CIPHER CRYPTO DECODE ENCODE BASE HEX SECRET PASSWORD HACK HACKER ADMIN ROOT SHELL PWN FLAG".split()
    total = sum(counts.values())
    top = counts.most_common(TOP_N)
    logs = [math.log10(c / total) for _, c in top]
    lo, hi = min(logs), max(logs)
    quant = bytes(round((v - lo) / (hi - lo) * 255) for v in logs)
    floor = math.log10(0.01 / total)

    out = pathlib.Path(__file__).resolve().parent.parent / "src" / "data" / "quadgrams.js"
    out.parent.mkdir(exist_ok=True)
    out.write_text(
        "// 자동 생성 파일: scripts/build_quadgrams.py\n"
        f"// 원문: Project Gutenberg 공개 도메인 소설 {len(paths)}권, quadgram {total:,}개 중 상위 {TOP_N:,}개\n"
        f"export const MIN = {lo:.6f};\n"
        f"export const MAX = {hi:.6f};\n"
        f"export const FLOOR = {floor:.6f};\n"
        f"export const QUADS = '{''.join(q for q, _ in top)}';\n"
        f"export const SCORES = '{base64.b64encode(quant).decode()}';\n"
        f"// 자주 나오는 단어 상위 {TOP_WORDS:,}개 (치환 암호 솔버의 단어 보너스용)\n"
        f"export const WORDS = '{' '.join(sorted(set([w for w, _ in words.most_common(TOP_WORDS)] + extra)))}';\n",
        encoding="utf-8",
    )
    covered = sum(c for _, c in top) / total
    print(f"{out}: {out.stat().st_size:,} bytes, 상위 {TOP_N}개가 전체의 {covered:.1%}")


if __name__ == "__main__":
    main(sys.argv[1:])
