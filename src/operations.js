// 디코더/복호기 모음.
//
// 각 연산(operation)의 형태:
//   id, name      : 식별자, 화면 표시 이름
//   category      : 'encoding' | 'cipher' | 'xor' | 'compression' | 'format' | 'esoteric' | 'transform'
//   strong        : 입력 형식이 엄격하게 맞을 때만 동작하는 디코더 (Base64, Hex 등).
//                   결과의 점수가 오르지 않아도 다음 단계 후보로 남긴다.
//   gate(a)       : strong 연산의 결과를 남길지 추가로 거르는 함수 (선택)
//   lookahead     : 약한 변환(ROT, 뒤집기 등)이 점수를 직접 올리지 못해도,
//                   그 결과에 strong 디코더가 먹히면 후보로 남긴다.
//   noRepeat      : 같은 연산을 연달아 적용하지 않음 (ROT13 두 번 = 원본)
//   needsCrib     : crib(알려진 평문)이 있어야 동작
//   needsKey      : 사용자가 키 후보를 입력해야 동작 (keyed.js)
//   accept(a)     : 결과를 남기기 위한 추가 필수 조건 (선택)
//   notAfter      : 바로 앞 단계가 이 연산들이면 건너뜀 (From Base64 → To Base64 같은 되돌리기 방지)
//   run(bytes, text, ctx) -> [{ out: Uint8Array, note?: string }] | null   (async 가능)
//
// 새 디코더를 추가하려면 OPERATIONS 배열에 객체 하나만 추가하면 된다.

import { utf8Encode, isPrintableByte } from './bytes.js';
import { scoreBytes, englishScore, cjkScore } from './score.js';
import { KEYED_OPERATIONS } from './keyed.js';
import { solveSubstitution, solveRepeatingXor } from './solvers.js';

const te = utf8Encode;
const one = (out, note) => (out && out.length ? [{ out, note }] : null);

// ---------------------------------------------------------------------------
// 공용 헬퍼

function decodeBits(str, alphabet, bitsPerChar) {
  const map = new Map();
  for (let i = 0; i < alphabet.length; i++) map.set(alphabet[i], i);
  const out = [];
  let buf = 0;
  let bits = 0;
  for (const ch of str) {
    const v = map.get(ch);
    if (v === undefined) return null;
    buf = (buf << bitsPerChar) | v;
    bits += bitsPerChar;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
    }
    buf &= (1 << bits) - 1;
  }
  return Uint8Array.from(out);
}

function printableRatio(bytes) {
  let p = 0;
  for (let i = 0; i < bytes.length; i++) if (isPrintableByte(bytes[i])) p++;
  return bytes.length ? p / bytes.length : 0;
}

function shiftLetters(text, k) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 65 && c <= 90) out += String.fromCharCode(((c - 65 + k) % 26) + 65);
    else if (c >= 97 && c <= 122) out += String.fromCharCode(((c - 97 + k) % 26) + 97);
    else out += text[i];
  }
  return out;
}

const ENGLISH_FREQ = [
  0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406,
  0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.0236, 0.0015, 0.01974, 0.00074,
];

function chiSquared(counts, total) {
  let chi = 0;
  for (let i = 0; i < 26; i++) {
    const e = ENGLISH_FREQ[i] * total;
    chi += ((counts[i] - e) ** 2) / e;
  }
  return chi;
}

function indexOfCoincidence(letters) {
  const counts = new Array(26).fill(0);
  for (const c of letters) counts[c]++;
  const n = letters.length;
  if (n < 2) return 0;
  let sum = 0;
  for (const c of counts) sum += c * (c - 1);
  return sum / (n * (n - 1));
}

// ---------------------------------------------------------------------------
// Base 계열

const B64_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function fromBase64(text) {
  const s = text.replace(/\s+/g, '');
  if (s.length < 4) return null;
  let norm;
  let variant = '';
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s)) norm = s;
  else if (/^[A-Za-z0-9_-]+={0,2}$/.test(s)) {
    norm = s.replace(/-/g, '+').replace(/_/g, '/');
    variant = 'URL-safe';
  } else return null;
  const body = norm.replace(/=+$/, '');
  if (body.length % 4 === 1) return null;
  if (norm.length !== body.length && norm.length % 4 !== 0) return null;
  return one(decodeBits(body, B64_ALPHA, 6), variant);
}

function fromBase32(text) {
  let s = text.replace(/\s+/g, '');
  if (s.length < 8) return null;
  if (s === s.toLowerCase()) s = s.toUpperCase();
  if (!/^[A-Z2-7]+=*$/.test(s)) return null;
  const body = s.replace(/=+$/, '');
  if (![0, 2, 4, 5, 7].includes(body.length % 8)) return null;
  return one(decodeBits(body, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 5));
}

const B58_ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function fromBase58(text) {
  const s = text.trim();
  if (s.length < 5 || s.length > 4000 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(s)) return null;
  let n = 0n;
  for (const ch of s) n = n * 58n + BigInt(B58_ALPHA.indexOf(ch));
  const out = [];
  while (n > 0n) {
    out.push(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of s) {
    if (ch === '1') out.push(0);
    else break;
  }
  return one(Uint8Array.from(out.reverse()));
}

function fromAscii85(text) {
  let s = text.replace(/\s+/g, '');
  const wrapped = s.startsWith('<~') || s.endsWith('~>');
  if (s.startsWith('<~')) s = s.slice(2);
  if (s.endsWith('~>')) s = s.slice(0, -2);
  if (s.length < 5 && !wrapped) return null;
  const out = [];
  let group = [];
  for (const ch of s) {
    if (ch === 'z' && group.length === 0) {
      out.push(0, 0, 0, 0);
      continue;
    }
    const c = ch.charCodeAt(0);
    if (c < 33 || c > 117) return null;
    group.push(c - 33);
    if (group.length === 5) {
      let v = 0;
      for (const g of group) v = v * 85 + g;
      if (v > 0xffffffff) return null;
      out.push(v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
      group = [];
    }
  }
  if (group.length) {
    if (group.length === 1) return null;
    const keep = group.length - 1;
    while (group.length < 5) group.push(84);
    let v = 0;
    for (const g of group) v = v * 85 + g;
    if (v > 0xffffffff) return null;
    out.push(...[v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].slice(0, keep));
  }
  return one(Uint8Array.from(out), wrapped ? '<~ ~>' : '');
}

/** 바이너리 → Base64 (디코딩이 아니라 "다시 인코딩"하는 방향. 예: Hex 를 바이트로 풀어 Base64 로 표현) */
function toBase64(bytes) {
  if (bytes.length < 6 || bytes.length > 65536) return null;
  if (printableRatio(bytes) > 0.9) return null; // 이미 텍스트면 다시 인코딩할 이유가 없음
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return one(te(btoa(bin)));
}

// ---------------------------------------------------------------------------
// 숫자 표현 계열

function fromHex(text) {
  let s = text.trim();
  if (!s) return null;
  s = s.replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[\s:,;]+/g, '');
  if (s.length < 4 || s.length % 2 || !/^[0-9a-fA-F]+$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return one(out);
}

function fromBinary(text) {
  const s = text.trim();
  if (!/^[01\s,]+$/.test(s)) return null;
  const tokens = s.split(/[\s,]+/).filter(Boolean);
  let values;
  if (tokens.length > 1 && tokens.every((t) => t.length >= 5 && t.length <= 8)) {
    values = tokens.map((t) => parseInt(t, 2));
  } else {
    const j = tokens.join('');
    const size = j.length % 8 === 0 ? 8 : j.length % 7 === 0 ? 7 : 0;
    if (!size || j.length < 8) return null;
    values = [];
    for (let i = 0; i < j.length; i += size) values.push(parseInt(j.substr(i, size), 2));
  }
  return one(Uint8Array.from(values), values.length && tokens[0].length === 7 ? '7비트' : '');
}

function fromOctal(text) {
  const tokens = text.trim().split(/[\s,\\]+/).filter(Boolean);
  if (tokens.length < 3 || !tokens.every((t) => /^[0-7]{1,3}$/.test(t))) return null;
  if (tokens.filter((t) => t.length === 3).length < tokens.length / 2) return null;
  const values = tokens.map((t) => parseInt(t, 8));
  if (values.some((v) => v > 255)) return null;
  return one(Uint8Array.from(values));
}

function fromDecimal(text) {
  const tokens = text.trim().split(/[\s,;]+/).filter(Boolean);
  if (tokens.length < 2 || !tokens.every((t) => /^\d{1,7}$/.test(t))) return null;
  const values = tokens.map(Number);
  if (values.some((v) => v > 0x10ffff)) return null;
  // 모두 1~26 이면 A1Z26 쪽이 더 맞을 가능성이 높으므로 그래도 시도는 하되, 점수에 맡긴다
  try {
    return one(te(String.fromCodePoint(...values)));
  } catch {
    return null;
  }
}

function fromA1Z26(text) {
  const s = text.trim();
  if (!/^[\d\s,\-\/|.]+$/.test(s)) return null;
  const words = s.split(/\s*[\/|]\s*|\s{2,}/).filter(Boolean);
  let count = 0;
  const outWords = [];
  for (const w of words) {
    const nums = w.split(/[\s,\-.]+/).filter(Boolean);
    let word = '';
    for (const n of nums) {
      if (!/^\d{1,2}$/.test(n)) return null;
      const v = Number(n);
      if (v < 1 || v > 26) return null;
      word += String.fromCharCode(64 + v);
      count++;
    }
    outWords.push(word);
  }
  if (count < 3) return null;
  return one(te(outWords.join(' ')));
}

// ---------------------------------------------------------------------------
// 웹/텍스트 이스케이프 계열

function fromUrl(text) {
  if (!/%[0-9a-fA-F]{2}/.test(text)) return null;
  const out = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '%' && /^[0-9a-fA-F]{2}$/.test(text.substr(i + 1, 2))) {
      out.push(parseInt(text.substr(i + 1, 2), 16));
      i += 2;
    } else {
      out.push(...te(text[i]));
    }
  }
  return one(Uint8Array.from(out));
}

const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®' };

function fromHtmlEntities(text) {
  if (!/&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/.test(text)) return null;
  const out = text.replace(/&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, e) => {
    try {
      if (e[0] === '#') return String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
    } catch {
      return m;
    }
    return NAMED_ENTITIES[e.toLowerCase()] ?? m;
  });
  return out === text ? null : one(te(out));
}

function fromEscapes(text) {
  if (!/\\(u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|[0-7]{3})/.test(text)) return null;
  // 1) \uXXXX 연속은 한꺼번에 (서로게이트 쌍 보존), \u{...} 는 코드포인트로
  let t = text.replace(/(?:\\u[0-9a-fA-F]{4})+/g, (run) =>
    String.fromCharCode(...run.match(/[0-9a-fA-F]{4}/g).map((h) => parseInt(h, 16)))
  );
  t = t.replace(/\\u\{([0-9a-fA-F]+)\}/g, (m, h) => {
    const cp = parseInt(h, 16);
    return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
  });
  // 2) \xHH, \ooo 는 원시 바이트로 (UTF-8 바이트열이 쪼개진 경우 복원), 나머지는 UTF-8
  const simple = { n: 10, r: 13, t: 9, '0': 0, '\\': 92, "'": 39, '"': 34 };
  const out = [];
  let last = 0;
  for (const m of t.matchAll(/\\(?:x([0-9a-fA-F]{2})|([0-7]{3})|([nrt0\\'"]))/g)) {
    out.push(...te(t.slice(last, m.index)));
    if (m[1]) out.push(parseInt(m[1], 16));
    else if (m[2]) out.push(parseInt(m[2], 8) & 0xff);
    else out.push(simple[m[3]]);
    last = m.index + m[0].length;
  }
  out.push(...te(t.slice(last)));
  return one(Uint8Array.from(out));
}

// ---------------------------------------------------------------------------
// 모스 부호 / 베이컨

const MORSE = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
  '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
  '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z',
  '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
  '.-.-.-': '.', '--..--': ',', '..--..': '?', '.----.': "'", '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
  '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-', '..--.-': '_', '.-..-.': '"', '...-..-': '$', '.--.-.': '@',
  // CTF 에서 자주 쓰는 비표준 표기
  '-.--.-.': '{', '-.--.--': '}',
};

function fromMorse(text) {
  const s = text
    .trim()
    .replace(/[·•∙]/g, '.')
    .replace(/[_−–—]/g, '-');
  if (!/^[.\-\s\/|]+$/.test(s) || !/[.-]/.test(s)) return null;
  const words = s.split(/\s*[\/|]\s*|\s{3,}/).filter(Boolean);
  let unknown = 0;
  let total = 0;
  const out = words.map((w) =>
    w
      .split(/\s+/)
      .filter(Boolean)
      .map((code) => {
        total++;
        if (MORSE[code]) return MORSE[code];
        unknown++;
        return '?';
      })
      .join('')
  );
  if (!total || unknown / total > 0.3) return null;
  return one(te(out.join(' ')));
}

function fromBacon(text) {
  const s = text.replace(/\s+/g, '');
  if (!/^[ABab]+$/.test(s) || s.length < 10 || s.length % 5) return null;
  const up = s.toUpperCase();
  const full = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const classic = 'ABCDEFGHIKLMNOPQRSTUWXYZ'; // I=J, U=V 합친 24자
  const results = [];
  for (const [alpha, note] of [
    [full, '26자'],
    [classic, '24자 (I=J, U=V)'],
  ]) {
    let out = '';
    for (let i = 0; i < up.length; i += 5) {
      const v = parseInt(up.substr(i, 5).replace(/A/g, '0').replace(/B/g, '1'), 2);
      out += alpha[v] ?? '?';
    }
    results.push({ out: te(out), note });
  }
  return results;
}

// ---------------------------------------------------------------------------
// 고전 암호

function caesarAll(_, text) {
  if ((text.match(/[A-Za-z]/g) || []).length < 3) return null;
  const res = [];
  for (let k = 1; k < 26; k++) {
    res.push({ out: te(shiftLetters(text, k)), note: k === 13 ? 'ROT13' : `ROT${k} (시저 키 ${26 - k})` });
  }
  return res;
}

function rot47(_, text) {
  if (!/[!-~]/.test(text)) return null;
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    out += c >= 33 && c <= 126 ? String.fromCharCode(33 + ((c - 33 + 47) % 94)) : text[i];
  }
  return one(te(out));
}

function atbash(_, text) {
  if ((text.match(/[A-Za-z]/g) || []).length < 3) return null;
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 65 && c <= 90) out += String.fromCharCode(155 - c);
    else if (c >= 97 && c <= 122) out += String.fromCharCode(219 - c);
    else out += text[i];
  }
  return one(te(out));
}

function reverse(_, text) {
  if (text.length < 3) return null;
  return one(te(Array.from(text).reverse().join('')));
}

/** 키를 모르는 비즈네르: IoC 로 키 길이 추정 → 열마다 카이제곱으로 시프트 추정 */
function vigenereAuto(_, text) {
  const letters = [];
  for (const ch of text.toUpperCase()) {
    const c = ch.charCodeAt(0) - 65;
    if (c >= 0 && c < 26) letters.push(c);
  }
  if (letters.length < 30 || letters.length > 20000) return null;
  // 고전 암호문은 대부분 글자로 이루어짐 (Base64/JWT 같은 문자열은 제외)
  const nonSpace = text.replace(/\s/g, '').length;
  if (letters.length / nonSpace < 0.85) return null;
  if (indexOfCoincidence(letters) > 0.058) return null; // 이미 단일 치환/평문에 가까움

  const maxLen = Math.min(20, Math.floor(letters.length / 6)); // 열마다 최소 6글자
  const scored = [];
  for (let L = 2; L <= maxLen; L++) {
    let sum = 0;
    for (let c = 0; c < L; c++) {
      const col = [];
      for (let i = c; i < letters.length; i += L) col.push(letters[i]);
      sum += indexOfCoincidence(col);
    }
    scored.push({ L, ioc: sum / L });
  }
  if (!scored.length) return null;
  // 영어 IoC(~0.066)에 가까운 가장 짧은 길이 + 최고 IoC 길이 (배수 길이 중복 방지)
  const firstGood = scored.find((s) => s.ioc >= 0.056);
  const best = scored.reduce((a, b) => (b.ioc > a.ioc ? b : a));
  const candidates = [...new Set([firstGood?.L, best.L].filter(Boolean))];

  const results = [];
  for (const L of candidates) {
    const key = [];
    for (let c = 0; c < L; c++) {
      let bestShift = 0;
      let bestChi = Infinity;
      const col = [];
      for (let i = c; i < letters.length; i += L) col.push(letters[i]);
      for (let k = 0; k < 26; k++) {
        const counts = new Array(26).fill(0);
        for (const x of col) counts[(x - k + 26) % 26]++;
        const chi = chiSquared(counts, col.length);
        if (chi < bestChi) {
          bestChi = chi;
          bestShift = k;
        }
      }
      key.push(bestShift);
    }
    // 키가 더 짧은 주기의 반복이면 줄이기
    let k = key;
    for (let p = 1; p < key.length; p++) {
      if (key.length % p === 0 && key.every((v, i) => v === key[i % p])) {
        k = key.slice(0, p);
        break;
      }
    }
    if (k.length === 1) continue; // 시저는 별도 연산에서 처리
    let idx = 0;
    let out = '';
    for (const ch of text) {
      const c = ch.charCodeAt(0);
      if (c >= 65 && c <= 90) out += String.fromCharCode(((c - 65 - k[idx++ % k.length] + 26) % 26) + 65);
      else if (c >= 97 && c <= 122) out += String.fromCharCode(((c - 97 - k[idx++ % k.length] + 26) % 26) + 97);
      else out += ch;
    }
    results.push({ out: te(out), note: `키 추정: ${k.map((v) => String.fromCharCode(65 + v)).join('')}` });
  }
  return results.length ? results : null;
}

function railFenceDecode(chars, rails) {
  const n = chars.length;
  const pattern = [];
  let r = 0;
  let dir = 1;
  for (let i = 0; i < n; i++) {
    pattern.push(r);
    if (r === 0) dir = 1;
    else if (r === rails - 1) dir = -1;
    r += dir;
  }
  const counts = new Array(rails).fill(0);
  for (const p of pattern) counts[p]++;
  const railsArr = [];
  let pos = 0;
  for (let i = 0; i < rails; i++) {
    railsArr.push(chars.slice(pos, pos + counts[i]));
    pos += counts[i];
  }
  const idx = new Array(rails).fill(0);
  return pattern.map((p) => railsArr[p][idx[p]++]).join('');
}

function railFence(_, text) {
  const chars = Array.from(text);
  if (chars.length < 6 || chars.length > 3000) return null;
  const res = [];
  for (let rails = 2; rails <= Math.min(10, chars.length - 1); rails++) {
    res.push({ out: te(railFenceDecode(chars, rails)), note: `레일 ${rails}개` });
  }
  return res;
}

// ---------------------------------------------------------------------------
// XOR

// 이미 자연어이거나, 글자/숫자/공백만으로 이루어진 텍스트(고전 암호문, Base 인코딩)는 XOR 대상이 아님
const looksNatural = (text) =>
  Math.max(englishScore(text), cjkScore(text)) > 0.35 ||
  (text.match(/[A-Za-z0-9\s.,'"!?+\/=_-]/g) || []).length / text.length > 0.92;

function xorSingleByte(bytes, text) {
  if (bytes.length < 4 || bytes.length > 65536) return null;
  if (printableRatio(bytes) > 0.97 && looksNatural(text)) return null; // 이미 평문이면 시도하지 않음
  const cands = [];
  const out = new Uint8Array(bytes.length);
  for (let k = 1; k < 256; k++) {
    let p = 0;
    for (let i = 0; i < bytes.length; i++) {
      out[i] = bytes[i] ^ k;
      if (isPrintableByte(out[i])) p++;
    }
    if (p / bytes.length < 0.9) continue;
    const copy = out.slice();
    cands.push({ out: copy, note: `키 0x${k.toString(16).padStart(2, '0')}`, s: scoreBytes(copy).score });
  }
  cands.sort((a, b) => b.s - a.s);
  return cands.slice(0, 3).map(({ out: o, note }) => ({ out: o, note }));
}

/** crib(예: flag{) 이 앞에 있다고 가정하고 반복 키 XOR 의 키를 역산 */
function xorWithCrib(bytes, text, ctx) {
  const crib = te(ctx.crib || '');
  if (crib.length < 2 || bytes.length < crib.length) return null;
  if (printableRatio(bytes) > 0.97 && looksNatural(text)) return null;
  const stream = crib.map((c, i) => bytes[i] ^ c);
  const res = [];
  for (let L = 1; L <= crib.length; L++) {
    const key = stream.slice(0, L);
    if (!stream.every((v, i) => v === key[i % L])) continue;
    const out = bytes.map((b, i) => b ^ key[i % L]);
    if (printableRatio(out) < 0.85) continue;
    const ascii = Array.from(key).every((b) => b >= 0x20 && b < 0x7f) ? ` "${String.fromCharCode(...key)}"` : '';
    res.push({ out, note: `키 0x${Array.from(key, (b) => b.toString(16).padStart(2, '0')).join('')}${ascii}` });
    break; // 가장 짧은 일관된 키 하나면 충분
  }
  return res.length ? res : null;
}

// ---------------------------------------------------------------------------
// 압축

async function decompress(bytes, format) {
  if (typeof DecompressionStream === 'undefined') return null;
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

async function gunzip(bytes) {
  if (bytes.length < 10 || bytes[0] !== 0x1f || bytes[1] !== 0x8b) return null;
  return one(await decompress(bytes, 'gzip'));
}

async function zlibInflate(bytes) {
  if (bytes.length < 3 || bytes[0] !== 0x78 || ((bytes[0] << 8) | bytes[1]) % 31 !== 0) return null;
  return one(await decompress(bytes, 'deflate'));
}

// ---------------------------------------------------------------------------
// 포맷

function b64urlToText(seg) {
  const r = fromBase64(seg);
  if (!r) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(r[0].out);
  } catch {
    return null;
  }
}

function jwtDecode(_, text) {
  const s = text.trim();
  const m = s.match(/^([A-Za-z0-9_-]{10,})\.([A-Za-z0-9_-]{2,})\.([A-Za-z0-9_-]*)$/);
  if (!m) return null;
  const h = b64urlToText(m[1]);
  const p = b64urlToText(m[2]);
  if (!h || !p) return null;
  let header;
  let payload;
  try {
    header = JSON.parse(h);
    payload = JSON.parse(p);
  } catch {
    return null;
  }
  if (!header.alg && !header.typ) return null;
  const out = JSON.stringify({ header, payload }, null, 2);
  return one(te(out), `alg=${header.alg ?? '?'}${m[3] ? '' : ' · 서명 없음'}`);
}

// ---------------------------------------------------------------------------
// 난해한 언어

function brainfuck(_, text) {
  const code = text.replace(/[^+\-<>\[\].,]/g, '');
  if (code.length < 10 || !code.includes('.')) return null;
  // 원문 대부분이 BF 문자여야 함
  if (code.length / text.replace(/\s/g, '').length < 0.95) return null;
  const jump = new Map();
  const stack = [];
  for (let i = 0; i < code.length; i++) {
    if (code[i] === '[') stack.push(i);
    else if (code[i] === ']') {
      if (!stack.length) return null;
      const j = stack.pop();
      jump.set(i, j);
      jump.set(j, i);
    }
  }
  if (stack.length) return null;
  const tape = new Uint8Array(30000);
  let ptr = 0;
  const out = [];
  let steps = 0;
  for (let ip = 0; ip < code.length; ip++) {
    if (++steps > 5_000_000 || out.length > 100000) break;
    switch (code[ip]) {
      case '>': ptr = (ptr + 1) % 30000; break;
      case '<': ptr = (ptr + 29999) % 30000; break;
      case '+': tape[ptr]++; break;
      case '-': tape[ptr]--; break;
      case '.': out.push(tape[ptr]); break;
      case ',': tape[ptr] = 0; break;
      case '[': if (!tape[ptr]) ip = jump.get(ip); break;
      case ']': if (tape[ptr]) ip = jump.get(ip); break;
    }
  }
  return one(Uint8Array.from(out));
}

// ---------------------------------------------------------------------------

const textGate = (a) => a.printable >= 0.85 || !!a.fileType;

export const OPERATIONS = [
  // 엄격한 형식의 인코딩 — 형식이 맞으면 항상 후보로
  { id: 'base64', name: 'From Base64', category: 'encoding', strong: true, run: (b, t) => fromBase64(t) },
  { id: 'base32', name: 'From Base32', category: 'encoding', strong: true, run: (b, t) => fromBase32(t) },
  { id: 'hex', name: 'From Hex', category: 'encoding', strong: true, run: (b, t) => fromHex(t) },
  { id: 'binary', name: 'From Binary', category: 'encoding', strong: true, run: (b, t) => fromBinary(t) },
  { id: 'octal', name: 'From Octal', category: 'encoding', strong: true, gate: textGate, run: (b, t) => fromOctal(t) },
  { id: 'decimal', name: 'From Decimal (charcode)', category: 'encoding', strong: true, gate: textGate, run: (b, t) => fromDecimal(t) },
  { id: 'a1z26', name: 'A1Z26 (숫자→알파벳)', category: 'cipher', strong: true, run: (b, t) => fromA1Z26(t) },
  { id: 'base58', name: 'From Base58', category: 'encoding', strong: true, gate: textGate, run: (b, t) => fromBase58(t) },
  {
    id: 'ascii85', name: 'From Ascii85', category: 'encoding', strong: true,
    gate: (a) => a.printable >= 0.9 || !!a.fileType, run: (b, t) => fromAscii85(t),
  },
  { id: 'url', name: 'URL Decode', category: 'format', strong: true, run: (b, t) => fromUrl(t) },
  { id: 'html', name: 'HTML Entity Decode', category: 'format', strong: true, run: (b, t) => fromHtmlEntities(t) },
  { id: 'escape', name: 'Unescape (\\x \\u)', category: 'format', strong: true, run: (b, t) => fromEscapes(t) },
  { id: 'jwt', name: 'JWT Decode', category: 'format', strong: true, run: jwtDecode },
  { id: 'morse', name: 'From Morse', category: 'encoding', strong: true, run: (b, t) => fromMorse(t) },
  { id: 'bacon', name: 'Bacon Cipher', category: 'cipher', strong: true, run: (b, t) => fromBacon(t) },
  { id: 'brainfuck', name: 'Brainfuck 실행', category: 'esoteric', strong: true, run: brainfuck },
  { id: 'gunzip', name: 'Gunzip', category: 'compression', strong: true, run: gunzip },
  { id: 'zlib', name: 'Zlib Inflate', category: 'compression', strong: true, run: zlibInflate },

  // 재인코딩: 무작위 Base64 문자열은 늘 '읽을 수 있는 텍스트'라 점수가 오르므로, 자연어/플래그일 때만 인정
  {
    id: 'tobase64', name: 'To Base64', category: 'encoding', noRepeat: true, notAfter: ['base64'],
    accept: (a) => a.lang >= 0.35 || a.flag || a.crib, run: (b) => toBase64(b),
  },

  // 약한 변환 — 점수를 올리거나 strong 디코더의 길을 열 때만 후보로
  { id: 'caesar', name: 'Caesar / ROT-N', category: 'cipher', lookahead: true, noRepeat: true, run: caesarAll },
  { id: 'rot47', name: 'ROT47', category: 'cipher', lookahead: true, noRepeat: true, run: rot47 },
  { id: 'atbash', name: 'Atbash', category: 'cipher', lookahead: true, noRepeat: true, run: atbash },
  { id: 'reverse', name: 'Reverse', category: 'transform', lookahead: true, noRepeat: true, run: reverse },
  { id: 'vigenere', name: 'Vigenère (키 자동 추정)', category: 'cipher', noRepeat: true, run: vigenereAuto },
  { id: 'railfence', name: 'Rail Fence', category: 'cipher', noRepeat: true, run: railFence },
  { id: 'xor1', name: 'XOR (1바이트 키 전수조사)', category: 'xor', noRepeat: true, run: xorSingleByte },
  { id: 'xorcrib', name: 'XOR (crib로 키 역산)', category: 'xor', needsCrib: true, noRepeat: true, run: xorWithCrib },
  {
    id: 'xorauto', name: 'XOR (반복 키 자동 추정)', category: 'xor', noRepeat: true,
    run: (b, t, ctx) => solveRepeatingXor(b, t, ctx, looksNatural),
  },
  {
    // 다른 글자 변환 뒤에 또 치환을 푸는 건 의미가 없거나(시저/아트바시도 치환의 일종) 쓰레기 해석을 만든다
    id: 'substitution', name: '단일 치환 (자동 풀기)', category: 'cipher', noRepeat: true,
    notAfter: ['caesar', 'rot47', 'atbash', 'railfence', 'vigenere', 'k-poly', 'k-playfair', 'k-columnar', 'reverse'],
    run: solveSubstitution,
  },

  // 키 후보를 입력했을 때만 동작
  ...KEYED_OPERATIONS,
];

export const OPERATION_MAP = Object.fromEntries(OPERATIONS.map((o) => [o.id, o]));
