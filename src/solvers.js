// 키를 몰라도 통계로 키를 찾아내는 솔버들
//   - 단일 치환 암호: quadgram 점수 힐클라이밍
//   - 반복 키 XOR: 해밍 거리로 키 길이 추정 → 열마다 1바이트 XOR 최적화

import { utf8Encode, isPrintableByte } from './bytes.js';
import { quadScore, quadScoreWeighted, quadFitness, loadNgrams, wordSet } from './ngram.js';

const te = utf8Encode;
const ENGLISH_ORDER = 'ETAOINSHRDLCUMWFGYPBVKJXQZ';

// 결정적인 의사 난수 (같은 입력이면 같은 결과가 나오도록)
function rng(seed) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 4294967296;
  };
}

function indexOfCoincidence(letters) {
  const counts = new Array(26).fill(0);
  for (const c of letters) counts[c]++;
  let sum = 0;
  for (const c of counts) sum += c * (c - 1);
  return letters.length > 1 ? sum / (letters.length * (letters.length - 1)) : 0;
}

/**
 * 단일 치환 암호 풀기.
 * key[c] = c(암호문 글자)에 대응하는 평문 글자 (0~25)
 */
export async function solveSubstitution(_, text) {
  const cipher = [];
  const wordStart = []; // 이 글자 앞에 단어 경계(공백/기호)가 있었는지
  let gap = false;
  for (const ch of text.toUpperCase()) {
    const c = ch.charCodeAt(0) - 65;
    if (c >= 0 && c < 26) {
      cipher.push(c);
      wordStart.push(gap);
      gap = false;
    } else gap = true;
  }
  const nonSpace = text.replace(/\s/g, '').length;
  if (cipher.length < 40 || cipher.length > 20000 || cipher.length / nonSpace < 0.8) return null;
  // 단일 치환은 글자 빈도 분포(IoC)를 그대로 보존 → 영어(≈0.066)에 가까워야 함
  if (indexOfCoincidence(cipher) < 0.052) return null;
  await loadNgrams();
  // 이미 영어면 풀 필요 없음
  if (quadFitness(text) > -3.3) return null;

  // 너무 긴 글은 앞부분만으로 키를 찾는다 (속도)
  const sample = cipher.slice(0, 600);
  // 단어 경계를 넘는 quadgram 은 가중치를 낮춘다 (띄어쓰기가 거의 없으면 모두 1)
  const spaced = wordStart.filter(Boolean).length > cipher.length / 12;
  const weights = sample.map((_, i) => {
    if (!spaced) return 1;
    for (let j = i + 1; j <= i + 3 && j < sample.length; j++) if (wordStart[j]) return 0.35;
    return 1;
  });
  const decode = (key, arr) => arr.map((c) => key[c]);

  // 띄어쓰기가 있으면 "해독된 단어가 실제 영어 단어인가"도 점수에 더한다.
  // quadgram 만으로는 WISDOM/WISCOM 처럼 통계가 비슷한 후보를 못 가르는 경우가 있어서.
  const dict = wordSet();
  const spans = [];
  if (spaced) {
    for (let i = 0; i < sample.length; ) {
      let j = i + 1;
      while (j < sample.length && !wordStart[j]) j++;
      spans.push([i, j]);
      i = j;
    }
  }
  const WORD_BONUS = 1.6; // 사전 단어 한 글자당 보너스 (quadgram 로그 확률 단위)
  const fit = (key) => {
    const dec = decode(key, sample);
    let s = quadScoreWeighted(dec, weights);
    for (const [a, b] of spans) {
      if (b - a > 20) continue;
      let w = '';
      for (let i = a; i < b; i++) w += String.fromCharCode(65 + dec[i]);
      if (dict.has(w)) s += WORD_BONUS * (b - a);
    }
    return s;
  };

  // 시작 키: 빈도순 매칭
  const freq = new Array(26).fill(0);
  for (const c of cipher) freq[c]++;
  const byFreq = [...Array(26).keys()].sort((a, b) => freq[b] - freq[a]);
  const startKey = new Array(26);
  byFreq.forEach((c, i) => (startKey[c] = ENGLISH_ORDER.charCodeAt(i) - 65));

  const rand = rng(cipher.length * 7919 + cipher[0] * 31 + cipher[1]);
  const climb = (key) => {
    let score = fit(key);
    let stale = 0;
    while (stale < 1200) {
      const a = Math.floor(rand() * 26);
      const b = Math.floor(rand() * 26);
      if (a === b) continue;
      [key[a], key[b]] = [key[b], key[a]];
      const s = fit(key);
      if (s > score) {
        score = s;
        stale = 0;
      } else {
        [key[a], key[b]] = [key[b], key[a]];
        stale++;
      }
    }
    return score;
  };

  let bestKey = startKey.slice();
  let bestScore = climb(bestKey);
  const deadline = Date.now() + 1200;
  let sinceImprove = 0;
  // 재시작: 짝수 회차는 최선의 키를 조금 흔들고, 홀수 회차는 완전히 무작위 키에서 시작 (지역 최적 탈출)
  for (let restart = 1; Date.now() < deadline && sinceImprove < 25; restart++) {
    let key;
    if (restart % 2 === 0) {
      key = bestKey.slice();
      for (let k = 0; k < 3 + (restart % 5); k++) {
        const a = Math.floor(rand() * 26);
        const b = Math.floor(rand() * 26);
        [key[a], key[b]] = [key[b], key[a]];
      }
    } else {
      key = [...Array(26).keys()];
      for (let i = 25; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [key[i], key[j]] = [key[j], key[i]];
      }
    }
    const score = climb(key);
    if (score > bestScore + 1e-9) {
      bestScore = score;
      bestKey = key.slice();
      sinceImprove = 0;
    } else sinceImprove++;
  }

  // 마무리: 모든 쌍 교환과 3-순환을 다 시도 (예: c→d, d→g, g→c 처럼 한 번의 교환으로는 못 고치는 경우)
  let polishScore = fit(bestKey);
  for (let improved = true, guard = 0; improved && guard < 6; guard++) {
    improved = false;
    for (let a = 0; a < 26; a++) {
      for (let b = a + 1; b < 26; b++) {
        [bestKey[a], bestKey[b]] = [bestKey[b], bestKey[a]];
        const s1 = fit(bestKey);
        if (s1 > polishScore + 1e-9) {
          polishScore = s1;
          improved = true;
          continue;
        }
        for (let c = b + 1; c < 26; c++) {
          for (const [x, y] of [[a, c], [b, c]]) {
            [bestKey[x], bestKey[y]] = [bestKey[y], bestKey[x]];
            const s2 = fit(bestKey);
            if (s2 > polishScore + 1e-9) {
              polishScore = s2;
              improved = true;
              break;
            }
            [bestKey[x], bestKey[y]] = [bestKey[y], bestKey[x]];
          }
          if (improved) break;
        }
        if (improved) break;
        [bestKey[a], bestKey[b]] = [bestKey[b], bestKey[a]];
      }
      if (improved) break;
    }
  }

  let out = '';
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (code >= 65 && code <= 90) out += String.fromCharCode(65 + bestKey[code - 65]);
    else if (code >= 97 && code <= 122) out += String.fromCharCode(97 + bestKey[code - 97]);
    else out += ch;
  }
  // 치환표: 평문 a~z 가 암호문에서 무엇이었는지
  const inverse = new Array(26).fill('?');
  bestKey.forEach((p, c) => (inverse[p] = String.fromCharCode(65 + c)));
  return [{ out: te(out), note: `치환표 ABC…Z → ${inverse.join('')}` }];
}

// ---------------------------------------------------------------------------
// 반복 키 XOR (키 모름)

function hamming(a, b) {
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    let x = a[i] ^ b[i];
    while (x) {
      d += x & 1;
      x >>= 1;
    }
  }
  return d;
}

// 영어 텍스트 바이트 가중치 (공백과 흔한 글자일수록 높음)
const BYTE_WEIGHT = new Float32Array(256).fill(-10);
(() => {
  for (let b = 0x20; b < 0x7f; b++) BYTE_WEIGHT[b] = 0.5;
  BYTE_WEIGHT[9] = BYTE_WEIGHT[10] = BYTE_WEIGHT[13] = 0.5;
  const freq = { e: 12.7, t: 9.1, a: 8.2, o: 7.5, i: 7.0, n: 6.7, s: 6.3, h: 6.1, r: 6.0, d: 4.3, l: 4.0, c: 2.8, u: 2.8, m: 2.4, w: 2.4, f: 2.2, g: 2.0, y: 2.0, p: 1.9, b: 1.5, v: 1.0, k: 0.8, j: 0.2, x: 0.2, q: 0.1, z: 0.1 };
  for (const [ch, f] of Object.entries(freq)) {
    BYTE_WEIGHT[ch.charCodeAt(0)] = f;
    BYTE_WEIGHT[ch.toUpperCase().charCodeAt(0)] = f * 0.6;
  }
  BYTE_WEIGHT[0x20] = 13;
  for (const ch of '_{}') BYTE_WEIGHT[ch.charCodeAt(0)] = 2; // 플래그에 흔한 기호
})();

export async function solveRepeatingXor(bytes, text, ctx, looksNatural) {
  const n = bytes.length;
  if (n < 24 || n > 200000) return null;
  let printable = 0;
  for (const b of bytes) if (isPrintableByte(b)) printable++;
  if (printable / n > 0.97 && looksNatural(text)) return null;
  await loadNgrams();

  // 1) 키 길이 후보: 인접 블록 사이의 정규화 해밍 거리가 작을수록 유력
  //    (같은 키로 XOR 된 두 블록의 거리 = 평문 두 블록의 거리 → 영어끼리라 작음)
  const maxLen = Math.min(40, Math.floor(n / 3));
  const cands = [];
  for (let L = 2; L <= maxLen; L++) {
    const blocks = Math.min(Math.floor(n / L) - 1, 24);
    let sum = 0;
    for (let i = 0; i < blocks; i++) sum += hamming(bytes.subarray(i * L, (i + 1) * L), bytes.subarray((i + 1) * L, (i + 2) * L)) / L;
    cands.push({ L, d: sum / blocks });
  }
  cands.sort((a, b) => a.d - b.d);

  // 2) 길이마다 열 단위로 최적의 1바이트 키
  const results = [];
  const seenKeys = new Set();
  for (const { L } of cands.slice(0, 4)) {
    const key = new Uint8Array(L);
    const options = [];
    for (let c = 0; c < L; c++) {
      const scored = [];
      for (let k = 0; k < 256; k++) {
        let s = 0;
        for (let i = c; i < n; i += L) s += BYTE_WEIGHT[bytes[i] ^ k];
        scored.push([s, k]);
      }
      scored.sort((a, b) => b[0] - a[0]);
      options.push(scored.slice(0, 8).map((x) => x[1]));
      key[c] = scored[0][1];
    }
    // 열마다 글자 수가 적으면 빈도만으로는 헷갈림 → 전체 평문의 quadgram 점수로 후보를 다시 고른다
    const fitness = (k) => {
      let s = 0;
      const letters = [];
      for (let i = 0; i < n; i++) {
        const b = bytes[i] ^ k[i % L];
        s += BYTE_WEIGHT[b];
        const u = b & 0xdf;
        if (u >= 65 && u <= 90) letters.push(u - 65);
      }
      // quadgram 로그 확률은 음수 합이라 글자가 적을수록 커지므로, 기준값(-4.5)과의 차이로 더한다
      return s + 3 * (quadScore(letters) + 4.5 * Math.max(0, letters.length - 3));
    };
    for (let pass = 0; pass < 2; pass++) {
      for (let c = 0; c < L; c++) {
        let best = key[c];
        let bestFit = fitness(key);
        for (const cand of options[c]) {
          key[c] = cand;
          const f = fitness(key);
          if (f > bestFit) {
            bestFit = f;
            best = cand;
          }
        }
        key[c] = best;
      }
    }
    // 더 짧은 주기의 반복이면 줄이기 (배수 길이 중복 제거)
    let k = key;
    for (let p = 1; p < L; p++) {
      if (L % p === 0 && key.every((v, i) => v === key[i % p])) {
        k = key.slice(0, p);
        break;
      }
    }
    if (k.length === 1) continue; // 1바이트 XOR 은 별도 연산
    const id = Array.from(k).join(',');
    if (seenKeys.has(id)) continue;
    seenKeys.add(id);
    const out = bytes.map((b, i) => b ^ k[i % k.length]);
    let p = 0;
    for (const b of out) if (isPrintableByte(b)) p++;
    if (p / n < 0.85) continue;
    const ascii = k.every((b) => b >= 0x20 && b < 0x7f) ? ` "${String.fromCharCode(...k)}"` : '';
    results.push({ out, note: `키 길이 ${k.length} · 0x${Array.from(k, (b) => b.toString(16).padStart(2, '0')).join('')}${ascii}` });
  }
  return results.length ? results : null;
}
