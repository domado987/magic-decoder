// "이 결과가 얼마나 그럴듯한가"를 0~100 점으로 매기는 모듈.
//
// 점수 = 출력 가능 문자 비율 + 자연어(영어/한국어/일본어) 유사도 + 보너스(플래그 패턴, crib, JSON, 파일 시그니처)

import { utf8Decode, latin1Decode, isPrintableByte, detectFileType } from './bytes.js';

// 영어 알파벳 빈도 (%)
const ENGLISH_FREQ = [
  8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
  6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.36, 0.15, 1.974, 0.074,
];
const ENGLISH_NORM = Math.sqrt(ENGLISH_FREQ.reduce((a, b) => a + b * b, 0));

// 영어에서 자주 나오는 바이그램
const COMMON_BIGRAMS = new Set(
  ('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce ' +
    'li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol')
    .split(' ')
);

// 자주 쓰는 영어 단어 + CTF 에서 자주 보는 단어
const COMMON_WORDS = new Set(
  ('the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all ' +
    'would there their what so up out if about who get which go me when make can like time no just him know take people into year your ' +
    'good some could them see other than then now look only come its over think also back after use two how our work first well way even ' +
    'new want because any these give day most us is are was were been has had did said very more much many such may must should here ' +
    'where why while each every few own same both through between down off under again once those please thanks thank hello world hi ' +
    'secret flag ctf password key message text hidden answer decode decoded encode encoded cipher crypto welcome congrats congratulations ' +
    'great nice try found easy hard simple this that admin user login code test example the quick brown fox jumps lazy dog attack dawn ' +
    'meet me at noon right left yes not too long short base hex binary ascii rot xor caesar vigenere morse rail fence correct wrong ' +
    'never give gonna let you down run around desert life love home school student university korea korean seoul hack hacker hacking ' +
    'security system data file read write open close start end begin final last next keep going almost there well done good job ' +
    'encoding decoding web safe bytes string ascii unicode')
    .split(/\s+/)
);
// 띄어쓰기 없는 문자열에서 찾을 단어 (4글자 이상)
const SUBSTRING_WORDS = [...COMMON_WORDS].filter((w) => w.length >= 4).sort((a, b) => b.length - a.length);

export const FLAG_RE = /(?:^|[^A-Za-z0-9])[A-Za-z][A-Za-z0-9_\-]{1,19}\{[A-Za-z0-9_\-!?@#$%&*+.:;=~^']*[A-Za-z0-9][A-Za-z0-9_\-!?@#$%&*+.:;=~^']*\}/;
// CryptoHack 입문 문제처럼 crypto/.../ 형식을 쓰는 경우
export const ALT_FLAG_RE = /(?:^|\s)crypto\/[A-Za-z0-9+_\-]{3,}\/(?:\s|$)/;

const clamp01 = (x) => (x < 0 ? 0 : x > 1 ? 1 : x);

/** 영어처럼 보이는 정도 0~1 */
export function englishScore(text) {
  const lower = text.toLowerCase();
  const counts = new Array(26).fill(0);
  let letters = 0;
  let bigramTotal = 0;
  let bigramHit = 0;
  let prev = -1;
  for (let i = 0; i < lower.length; i++) {
    const c = lower.charCodeAt(i) - 97;
    if (c >= 0 && c < 26) {
      counts[c]++;
      letters++;
      if (prev >= 0) {
        bigramTotal++;
        if (COMMON_BIGRAMS.has(lower[i - 1] + lower[i])) bigramHit++;
      }
      prev = c;
    } else {
      prev = -1;
    }
  }
  if (letters < 3) return 0;

  // 1) 글자 빈도 코사인 유사도: 영어 ~0.9+, 무작위 ~0.75
  let dot = 0;
  let norm = 0;
  for (let i = 0; i < 26; i++) {
    dot += counts[i] * ENGLISH_FREQ[i];
    norm += counts[i] * counts[i];
  }
  const cos = dot / (Math.sqrt(norm) * ENGLISH_NORM);
  const freqFit = clamp01((cos - 0.72) / 0.2);

  // 2) 흔한 바이그램 비율
  const bigramFit = bigramTotal ? clamp01((bigramHit / bigramTotal - 0.15) / 0.4) : 0;

  // 3) 사전 단어가 전체(공백 제외) 글자 중 얼마를 덮는지
  const nonSpace = lower.replace(/\s/g, '').length || 1;
  const tokens = lower.match(/[a-z]+/g) || [];
  let covered = 0;
  for (const t of tokens) {
    if (t.length === 1 && t !== 'a' && t !== 'i') continue;
    if (COMMON_WORDS.has(t)) {
      covered += t.length <= 2 ? t.length * 0.5 : t.length; // 짧은 단어는 우연히 맞기 쉬움
    } else if (t.length >= 8) {
      let rest = t;
      let c = 0;
      for (const w of SUBSTRING_WORDS) {
        if (rest.includes(w)) {
          c += w.length;
          rest = rest.split(w).join('\u0000');
        }
      }
      covered += c * 0.8;
    }
  }
  const wordFit = clamp01(covered / nonSpace / 0.55);

  // 글자가 아닌 문자(숫자/기호) 비율이 높으면 자연어가 아님. 영어 문장은 보통 90% 이상이 글자
  const wordish = letters + (lower.match(/[_'\-]/g) || []).length;
  const letterRatio = clamp01((wordish / nonSpace - 0.5) / 0.38);
  // 글자 수가 적으면 통계적 신뢰도가 낮다
  const confidence = clamp01(letters / 12);
  // 단어 안에서 대소문자가 마구 바뀌면(예: NNmsIWEChe) Base64 같은 무작위 문자열
  let flips = 0;
  for (let i = 1; i < text.length; i++) {
    const a = text[i - 1];
    const b = text[i];
    if (/[a-z]/.test(a) && /[A-Z]/.test(b)) flips++;
  }
  const caseFactor = clamp01(1 - (flips / letters) * 6);
  const stat = (0.25 * freqFit + 0.35 * bigramFit + 0.4 * wordFit) * (0.5 + 0.5 * confidence);
  return Math.max(stat, wordFit * 0.9) * letterRatio * caseFactor;
}

/** 한글/일본어/한자 비율 0~1 */
export function cjkScore(text) {
  const nonSpace = text.replace(/\s/g, '');
  if (!nonSpace.length) return 0;
  const m = nonSpace.match(/[가-힣぀-ヿ一-鿿]/g);
  if (!m || m.length < 2) return 0;
  return clamp01((m.length / nonSpace.length) * 1.3);
}

function looksLikeJson(text) {
  const t = text.trim();
  if (!(t.startsWith('{') && t.endsWith('}')) && !(t.startsWith('[') && t.endsWith(']'))) return false;
  try {
    JSON.parse(t);
    return true;
  } catch {
    return false;
  }
}

/**
 * 바이트 배열을 분석해 점수를 매긴다.
 * @returns {{score:number, printable:number, lang:number, isText:boolean, text:string, flag:boolean, crib:boolean, fileType:object|null}}
 */
export function scoreBytes(bytes, ctx = {}) {
  const n = bytes.length;
  if (!n) return { score: 0, printable: 0, lang: 0, isText: false, text: '', flag: false, crib: false, fileType: null };

  const utf8 = utf8Decode(bytes);
  let text;
  let printable;
  if (utf8 !== null) {
    text = utf8;
    let good = 0;
    let total = 0;
    for (const ch of utf8) {
      total++;
      const c = ch.codePointAt(0);
      if ((c >= 0x20 && c !== 0x7f && !(c >= 0x80 && c < 0xa0)) || c === 9 || c === 10 || c === 13) good++;
    }
    printable = good / total;
    // UTF-8 이지만 ASCII 아닌 문자가 섞인 경우, 그게 CJK 가 아니면 약간 감점 (mojibake 방지)
    const nonAscii = (utf8.match(/[^\x00-\x7f]/g) || []).length;
    const cjk = (utf8.match(/[가-힣぀-ヿ一-鿿　-〿＀-￯]/g) || []).length;
    if (nonAscii > cjk) printable *= 1 - ((nonAscii - cjk) / total) * 0.5;
  } else {
    text = latin1Decode(bytes);
    let good = 0;
    for (let i = 0; i < n; i++) if (isPrintableByte(bytes[i])) good++;
    printable = (good / n) * 0.9; // 올바른 UTF-8 이 아니면 살짝 감점
  }

  const fileType = detectFileType(bytes);
  const crib = !!(ctx.crib && text.toLowerCase().includes(ctx.crib.toLowerCase()));
  const lang = Math.max(englishScore(text), cjkScore(text));
  // 플래그 패턴: 쓰레기 문자열 속 우연한 "abc{de}" 를 거르기 위해,
  // 텍스트가 자연어스럽거나 플래그가 텍스트의 대부분을 차지할 때만 인정
  let flag = false;
  if (printable >= 0.9) {
    const m = text.match(FLAG_RE) || text.match(ALT_FLAG_RE);
    if (m) {
      const inner = m[0].slice(m[0].indexOf('{') + 1, -1);
      flag = inner.length >= 3 && (lang >= 0.2 || m[0].trim().length >= text.trim().length * 0.6);
    }
  }

  let score = 35 * Math.pow(printable, 3) + 45 * lang;
  if (flag) score += 22;
  if (crib) score += 30;
  if (looksLikeJson(text)) score += 18;
  if (fileType && printable < 0.9) score += 25;
  if (n < 3) score *= 0.5;
  score = Math.min(100, score);

  return { score, printable, lang, isText: printable >= 0.9, text, flag, crib, fileType };
}
