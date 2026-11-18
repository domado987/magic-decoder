// "Magic" 탐색 엔진.
//
// 입력에서 출발해 모든 디코더를 시도하고, 나온 결과에 다시 디코더를 시도한다.
// 단계별로 넓게 훑는 대신 A* 처럼 "지금까지 나온 후보 중 가장 유망한 것"부터 확장한다 (최선 우선 탐색).
//
//   우선순위 f = 점수(그럴듯함) + 강한 디코더 보너스 − 단계 수 × 비용
//
// 강한 디코더(형식이 엄격히 맞아야 동작)로 나온 결과는 아직 읽을 수 없는 바이너리여도
// "제대로 된 길"일 가능성이 높으므로 보너스를 준다 (예: Base64 → [gzip 바이너리] → 평문).
// 확장 횟수(maxExpansions)와 시간 제한 안에서 탐색하고, 모든 결과를 점수순으로 돌려준다.

import { OPERATIONS } from './operations.js';
import { scoreBytes } from './score.js';
import { utf8Encode, bytesToText, bytesKey } from './bytes.js';
import { identify } from './identify.js';
import { deriveKeyMaterial } from './keyed.js';

export const DEFAULTS = {
  maxDepth: 4, // 최대 몇 단계까지 연쇄 디코딩할지
  maxExpansions: 0, // 확장할 노드 수 상한 (0이면 maxDepth × 14)
  stepCost: 4, // 우선순위 계산 시 단계 하나당 비용
  strongBonus: 20, // 강한 디코더로 나온 노드의 우선순위 보너스
  timeLimit: 4000, // ms
  maxResults: 40,
  crib: '', // 알려진 평문/플래그 형식 (예: "flag{")
  keys: [], // 키/IV 후보 문자열들 (예: ["YELLOW SUBMARINE", "0x00112233..."])
  improve: 8, // 약한 변환이 후보로 남으려면 올려야 하는 최소 점수
  maxBytes: 1 << 20,
};

const STRONG = OPERATIONS.filter((o) => o.strong);

const yieldToEventLoop = () => new Promise((r) => setTimeout(r, 0));

/** 섀넌 엔트로피가 길이 대비 최대치에 가까우면 무작위(암호문/압축) 데이터로 본다 */
function looksRandom(bytes) {
  const n = bytes.length;
  if (n < 12) return false;
  const counts = new Map();
  for (const b of bytes) counts.set(b, (counts.get(b) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) h -= (c / n) * Math.log2(c / n);
  return h / Math.log2(Math.min(n, 256)) > 0.85;
}

/**
 * @param {string|Uint8Array} input
 * @param {Partial<typeof DEFAULTS> & {signal?: AbortSignal}} options
 */
export async function magic(input, options = {}) {
  const o = { ...DEFAULTS, ...options };
  const ctx = { crib: (o.crib || '').trim(), keyMaterial: null };
  const keyList = (Array.isArray(o.keys) ? o.keys : String(o.keys || '').split('\n')).map((k) => k.trim()).filter(Boolean);
  if (keyList.length) ctx.keyMaterial = await deriveKeyMaterial(keyList);
  const started = Date.now();
  const rootBytes = typeof input === 'string' ? utf8Encode(input) : input;

  const root = { bytes: rootBytes, recipe: [], analysis: scoreBytes(rootBytes, ctx), depth: 0 };
  const seen = new Set([bytesKey(rootBytes)]);
  const results = [];
  const open = [root]; // 확장 대기 중인 노드들
  const budget = o.maxExpansions || o.maxDepth * 14;
  let expansions = 0;
  let tried = 0;
  let truncated = false;
  let lastYield = Date.now();

  const aborted = () => o.signal?.aborted;
  const timeUp = () => Date.now() - started > o.timeLimit;

  // 약한 변환(ROT 등)의 결과에 강한 디코더를 한 번 더 걸어 본다. 이런 경우 true:
  //   (a) 점수가 크게 오른다 (ROT13 → Base64 → 평문)
  //   (b) 변환 전에는 바이너리 쓰레기만 나오던 디코더가, 변환 후에는 깨끗한 텍스트를 낸다
  //       (ROT13 → Base64 → "68656c6c6f…" 처럼 또 다른 인코딩이 나오는 깊은 연쇄)
  const parentDecodeCache = new Map();
  async function strongOutputs(op, bytes, text) {
    try {
      return (await op.run(bytes, text, ctx)) || [];
    } catch {
      return [];
    }
  }
  async function unlocksStrong(bytes, text, baseline, parent, parentText) {
    for (const op of STRONG) {
      const res = await strongOutputs(op, bytes, text);
      for (const r of res) {
        if (!r.out?.length) continue;
        const a = scoreBytes(r.out, ctx);
        if (a.score > baseline + 10) return true;
        if (a.printable >= 0.97 && r.out.length >= 8) {
          const cacheKey = `${op.id}:${bytesKey(parent)}`;
          if (!parentDecodeCache.has(cacheKey)) {
            const pres = await strongOutputs(op, parent, parentText);
            parentDecodeCache.set(cacheKey, pres.some((x) => x.out?.length && scoreBytes(x.out, ctx).printable >= 0.97));
          }
          if (!parentDecodeCache.get(cacheKey)) return true;
        }
      }
    }
    return false;
  }

  const priority = (n) => n.analysis.score + (n.viaStrong ? o.strongBonus : 0) - n.depth * o.stepCost;

  outer: while (open.length && expansions < budget) {
    // 가장 유망한 노드 꺼내기 (후보 수가 많지 않아 선형 탐색으로 충분)
    let bi = 0;
    for (let i = 1; i < open.length; i++) if (priority(open[i]) > priority(open[bi])) bi = i;
    const node = open.splice(bi, 1)[0];
    if (node.depth >= o.maxDepth || node.bytes.length > o.maxBytes) continue;
    expansions++;
    const depth = node.depth + 1;
    {
      const text = bytesToText(node.bytes);
      const last = node.recipe[node.recipe.length - 1];

      for (const op of OPERATIONS) {
        if (aborted()) return null;
        if (timeUp()) {
          truncated = true;
          break outer;
        }
        if (op.needsCrib && !ctx.crib) continue;
        if (op.needsKey && !ctx.keyMaterial) continue;
        if (op.noRepeat && last?.id === op.id) continue;
        if (op.notAfter && last && op.notAfter.includes(last.id)) continue;

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
            keep = await unlocksStrong(r.out, bytesToText(r.out), Math.max(node.analysis.score, a.score), node.bytes, text);
          }
          if (keep && op.accept && !op.accept(a)) keep = false;
          if (!keep) continue;

          seen.add(key);
          const child = {
            bytes: r.out,
            recipe: [...node.recipe, { id: op.id, name: op.name, category: op.category, note: r.note || '' }],
            analysis: a,
            depth,
            viaStrong: !!op.strong,
          };
          results.push(child);
          open.push(child);
        }

        // 브라우저가 멈추지 않도록 가끔 양보
        if (Date.now() - lastYield > 30) {
          await yieldToEventLoop();
          lastYield = Date.now();
        }
      }
    }
  }
  if (open.some((n) => n.depth < o.maxDepth)) truncated = truncated || expansions >= budget;

  // 같은 점수면 단계가 짧은 레시피를 우선
  const rank = (n) => n.analysis.score - n.depth * 1.2;
  results.sort((a, b) => {
    const d = rank(b) - rank(a);
    // 점수가 사실상 같으면 더 긴 결과(정보를 덜 잃은 쪽)를 앞에
    return Math.abs(d) < 0.5 ? b.bytes.length - a.bytes.length : d;
  });

  let hints = identify(bytesToText(rootBytes));
  const best = results[0]?.analysis.score ?? 0;
  // Hex 로 이미 잘 풀렸으면 "Hex 일 가능성" 힌트는 군더더기
  if (best >= 45 && results[0].recipe[0].id === 'hex') hints = hints.filter((h) => !h.title.includes('Hex(16진수)'));
  const isHash = hints.some((h) => h.title.includes('해시'));
  const inputIsProse = root.analysis.lang >= 0.4; // 입력 자체가 이미 문장이면 암호문 힌트는 부적절
  if (best < 45 && !isHash && !inputIsProse) {
    // 형식은 맞아서 풀렸는데 결과가 무작위 바이트처럼 보이면: 키가 필요한 암호문일 가능성
    const randoms = results.filter((n) => n.depth === 1 && !n.analysis.isText && !n.analysis.fileType && looksRandom(n.bytes));
    // 0-9a-f 만 쓰인 입력이면 Hex 쪽 해석을 우선 (위의 Hex 힌트와 일관되게)
    const randomish = randoms.find((n) => n.recipe[0].id === 'hex') ?? randoms[0];
    if (randomish) {
      hints.push({
        title: '암호화된 데이터일 수 있음',
        detail:
          `${randomish.recipe[0].name}(으)로 풀면 ${randomish.bytes.length}바이트가 나오지만, 바이트 분포가 무작위에 가깝습니다. ` +
          '인코딩이 아니라 키가 필요한 암호(AES, RC4, 반복 키 XOR 등)일 가능성이 높아요. ' +
          (ctx.keyMaterial
            ? '입력한 키 후보로는 풀리지 않았어요. 키 형식(텍스트/hex)이나 암호 방식(모드, IV)을 다시 확인해 보세요.'
            : '키로 짐작되는 값이 있으면 "키 후보" 칸에 넣어 보세요. 평문 앞부분(예: flag{)을 알면 crib 칸에 넣어도 됩니다.'),
      });
    }
  }

  return {
    input: root,
    hints,
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
