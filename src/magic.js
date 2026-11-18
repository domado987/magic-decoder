// "Magic" 탐색 엔진.
//
// 입력에서 출발해 모든 디코더를 시도하고, 나온 결과에 다시 디코더를 시도하는 식으로
// 최대 maxDepth 단계까지 빔 서치(beam search)를 한다. 각 결과는 score.js 로 점수를 매겨
// "그럴듯한 순서"로 정렬해 돌려준다.

import { OPERATIONS } from './operations.js';
import { scoreBytes } from './score.js';
import { utf8Encode, bytesToText, bytesKey } from './bytes.js';
import { identify } from './identify.js';

export const DEFAULTS = {
  maxDepth: 4, // 최대 몇 단계까지 연쇄 디코딩할지
  beamWidth: 14, // 단계마다 다음으로 확장할 후보 수
  timeLimit: 4000, // ms
  maxResults: 40,
  crib: '', // 알려진 평문/플래그 형식 (예: "flag{")
  improve: 8, // 약한 변환이 후보로 남으려면 올려야 하는 최소 점수
  maxBytes: 1 << 20,
};

const STRONG = OPERATIONS.filter((o) => o.strong);

const yieldToEventLoop = () => new Promise((r) => setTimeout(r, 0));

/**
 * @param {string|Uint8Array} input
 * @param {Partial<typeof DEFAULTS> & {signal?: AbortSignal}} options
 */
export async function magic(input, options = {}) {
  const o = { ...DEFAULTS, ...options };
  const ctx = { crib: (o.crib || '').trim() };
  const started = Date.now();
  const rootBytes = typeof input === 'string' ? utf8Encode(input) : input;

  const root = { bytes: rootBytes, recipe: [], analysis: scoreBytes(rootBytes, ctx), depth: 0 };
  const seen = new Set([bytesKey(rootBytes)]);
  const results = [];
  let frontier = [root];
  let tried = 0;
  let truncated = false;
  let lastYield = Date.now();

  const aborted = () => o.signal?.aborted;
  const timeUp = () => Date.now() - started > o.timeLimit;

  // 약한 변환 결과에 strong 디코더를 한 번 더 걸어보고 점수가 크게 오르면 true
  async function unlocksStrong(bytes, text, baseline) {
    for (const op of STRONG) {
      let res;
      try {
        res = await op.run(bytes, text, ctx);
      } catch {
        continue;
      }
      for (const r of res || []) {
        if (r.out?.length && scoreBytes(r.out, ctx).score > baseline + 10) return true;
      }
    }
    return false;
  }

  outer: for (let depth = 1; depth <= o.maxDepth; depth++) {
    const next = [];
    for (const node of frontier) {
      if (node.bytes.length > o.maxBytes) continue;
      const text = bytesToText(node.bytes);
      const last = node.recipe[node.recipe.length - 1];

      for (const op of OPERATIONS) {
        if (aborted()) return null;
        if (timeUp()) {
          truncated = true;
          break outer;
        }
        if (op.needsCrib && !ctx.crib) continue;
        if (op.noRepeat && last?.id === op.id) continue;

        let res;
        tried++;
        try {
          res = await op.run(node.bytes, text, ctx);
        } catch {
          res = null;
        }
        if (!res?.length) continue;

        for (const r of res) {
          if (!r.out?.length) continue;
          const key = bytesKey(r.out);
          if (seen.has(key)) continue;
          const a = scoreBytes(r.out, ctx);

          let keep = !!op.strong && (!op.gate || op.gate(a));
          if (!keep) keep = a.score >= node.analysis.score + o.improve;
          if (!keep && op.lookahead && text.length <= 4096) {
            keep = await unlocksStrong(r.out, bytesToText(r.out), Math.max(node.analysis.score, a.score));
          }
          if (!keep) continue;

          seen.add(key);
          const child = {
            bytes: r.out,
            recipe: [...node.recipe, { id: op.id, name: op.name, category: op.category, note: r.note || '' }],
            analysis: a,
            depth,
          };
          results.push(child);
          next.push(child);
        }

        // 브라우저가 멈추지 않도록 가끔 양보
        if (Date.now() - lastYield > 30) {
          await yieldToEventLoop();
          lastYield = Date.now();
        }
      }
    }
    if (!next.length) break;
    next.sort((a, b) => b.analysis.score - a.analysis.score);
    frontier = next.slice(0, o.beamWidth);
  }

  // 같은 점수면 단계가 짧은 레시피를 우선
  const rank = (n) => n.analysis.score - n.depth * 1.2;
  results.sort((a, b) => rank(b) - rank(a));

  return {
    input: root,
    hints: identify(bytesToText(rootBytes)),
    results: results.slice(0, o.maxResults).map((n) => ({
      bytes: n.bytes,
      text: n.analysis.text,
      score: Math.round(n.analysis.score * 10) / 10,
      isText: n.analysis.isText,
      flag: n.analysis.flag,
      crib: n.analysis.crib,
      fileType: n.analysis.fileType,
      recipe: n.recipe,
      depth: n.depth,
    })),
    stats: { candidates: results.length, tried, ms: Date.now() - started, truncated },
  };
}
