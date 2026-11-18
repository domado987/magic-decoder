// 사용자가 입력한 "키 후보"로 시도하는 복호화 연산들.
//
// 키 문자열 하나를 여러 방식으로 해석한다:
//   텍스트 그대로 / hex / base64  →  XOR, RC4, 고전 암호에 사용
//   길이가 16/24/32 바이트인 것, 0으로 패딩한 것, MD5(키), SHA-256(키)  →  AES 키로 사용
//   길이 16 바이트인 것  →  AES-CBC/CTR 의 IV 후보로 사용

import { utf8Encode, bytesToHex, isPrintableByte, detectFileType } from './bytes.js';
import { ecbDecrypt, cbcDecrypt, ctrCrypt, stripPkcs7, expandKey } from './aes.js';
import { md5, sha256 } from './hash.js';

const te = utf8Encode;
const short = (s) => (s.length > 24 ? `${s.slice(0, 21)}…` : s);

function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function b64ToBytes(s) {
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function printableRatio(bytes) {
  let p = 0;
  for (let i = 0; i < bytes.length; i++) if (isPrintableByte(bytes[i])) p++;
  return bytes.length ? p / bytes.length : 0;
}

// 복호화 결과가 쓸 만한지 1차로 거르기 (나머지 판단은 엔진의 점수에 맡김)
const plausible = (out) => out.length > 0 && (printableRatio(out) >= 0.6 || !!detectFileType(out));

/**
 * 키 후보 문자열들로부터 실제로 시도할 키 바이트들을 만든다.
 * @param {string[]} keyStrings
 */
export async function deriveKeyMaterial(keyStrings) {
  const sources = [...new Set(keyStrings.map((s) => s.trim()).filter(Boolean))];
  const keys = [];
  const seenKeys = new Set();
  const addKey = (bytes, label, text) => {
    const id = bytesToHex(bytes, '');
    if (!bytes.length || seenKeys.has(id)) return;
    seenKeys.add(id);
    keys.push({ bytes, label, text });
  };

  for (const s of sources) {
    addKey(te(s), `"${short(s)}"`, s);
    const h = s.replace(/^0x/i, '').replace(/[\s:]/g, '');
    if (/^[0-9a-fA-F]+$/.test(h) && h.length % 2 === 0 && h.length >= 2) addKey(hexToBytes(h), `hex ${short(h)}`, null);
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0 && s.length >= 8) {
      try {
        addKey(b64ToBytes(s), `base64 ${short(s)}`, null);
      } catch {
        /* 무시 */
      }
    }
  }

  const aes = [];
  const seenAes = new Set();
  const addAes = (bytes, label) => {
    const id = bytesToHex(bytes, '');
    if (seenAes.has(id)) return;
    seenAes.add(id);
    aes.push({ bytes, label, ks: expandKey(bytes) });
  };
  for (const k of keys) {
    const n = k.bytes.length;
    if (n === 16 || n === 24 || n === 32) addAes(k.bytes, k.label);
    else if (n < 32) {
      const L = n < 16 ? 16 : n < 24 ? 24 : 32;
      const padded = new Uint8Array(L);
      padded.set(k.bytes);
      addAes(padded, `${k.label} + 0 패딩`);
    }
  }
  for (const s of sources) {
    addAes(md5(te(s)), `MD5("${short(s)}")`);
    const d = await sha256(te(s));
    if (d) {
      addAes(d, `SHA-256("${short(s)}")`);
      addAes(d.slice(0, 16), `SHA-256("${short(s)}")[:16]`);
    }
  }

  const ivs = keys.filter((k) => k.bytes.length === 16);
  return { sources, keys, aes, ivs };
}

// ---------------------------------------------------------------------------
// 바이트 단위 암호

function xorWithKeys(bytes, _, ctx) {
  const res = [];
  for (const k of ctx.keyMaterial.keys) {
    const out = bytes.map((b, i) => b ^ k.bytes[i % k.bytes.length]);
    if (plausible(out)) res.push({ out, note: `키 ${k.label}` });
  }
  return res;
}

function rc4(data, key) {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + S[i] + key[i % key.length]) & 255;
    [S[i], S[j]] = [S[j], S[i]];
  }
  const out = new Uint8Array(data.length);
  for (let n = 0, i = 0, j = 0; n < data.length; n++) {
    i = (i + 1) & 255;
    j = (j + S[i]) & 255;
    [S[i], S[j]] = [S[j], S[i]];
    out[n] = data[n] ^ S[(S[i] + S[j]) & 255];
  }
  return out;
}

function rc4WithKeys(bytes, _, ctx) {
  if (bytes.length < 2 || printableRatio(bytes) > 0.9) return null; // RC4 암호문은 텍스트처럼 보이지 않음
  const res = [];
  for (const k of ctx.keyMaterial.keys) {
    const out = rc4(bytes, k.bytes);
    if (plausible(out)) res.push({ out, note: `키 ${k.label}` });
  }
  return res;
}

function aesWithKeys(bytes, _, ctx) {
  if (bytes.length < 16 || bytes.length > 1 << 20) return null;
  if (printableRatio(bytes) > 0.9) return null; // AES 암호문은 텍스트처럼 보이지 않음
  const { aes, ivs } = ctx.keyMaterial;
  const res = [];
  const zeroIv = new Uint8Array(16);
  // 앞 32바이트만 먼저 풀어 보고 그럴듯할 때만 전체를 푼다 (키 후보 × 모드 조합이 많아서)
  const attempt = (decrypt, data, mode, k, extra = '') => {
    const preview = decrypt(data.subarray(0, 32));
    if (printableRatio(preview) < 0.6 && !detectFileType(preview)) return;
    const raw = data.length <= 32 ? preview : decrypt(data);
    const { out, padded } = mode.endsWith('CTR') ? { out: raw, padded: false } : stripPkcs7(raw);
    if (plausible(out)) res.push({ out, note: `${mode}${extra} · 키 ${k.label}${padded ? ' · PKCS#7' : ''}` });
  };
  const aligned = bytes.length % 16 === 0;
  const body = bytes.subarray(16);
  const head = bytes.subarray(0, 16);
  for (const k of aes) {
    const mode = (m) => `AES-${k.bytes.length * 8}-${m}`;
    if (aligned) {
      attempt((d) => ecbDecrypt(d, k.ks), bytes, mode('ECB'), k);
      attempt((d) => cbcDecrypt(d, k.ks, zeroIv), bytes, mode('CBC'), k, ' (IV=0)');
      if (bytes.length >= 32) attempt((d) => cbcDecrypt(d, k.ks, head), body, mode('CBC'), k, ' (IV=앞 16바이트)');
      for (const iv of ivs) attempt((d) => cbcDecrypt(d, k.ks, iv.bytes), bytes, mode('CBC'), k, ` (IV ${iv.label})`);
    }
    attempt((d) => ctrCrypt(d, k.ks, zeroIv), bytes, mode('CTR'), k, ' (카운터 0)');
    if (bytes.length > 16) attempt((d) => ctrCrypt(d, k.ks, head), body, mode('CTR'), k, ' (nonce=앞 16바이트)');
    for (const iv of ivs) attempt((d) => ctrCrypt(d, k.ks, iv.bytes), bytes, mode('CTR'), k, ` (IV ${iv.label})`);
  }
  return res;
}

// ---------------------------------------------------------------------------
// 고전 암호 (키워드)

const keyLetters = (s) => s.toUpperCase().replace(/[^A-Z]/g, '').split('').map((c) => c.charCodeAt(0) - 65);
const letterCount = (t) => (t.match(/[A-Za-z]/g) || []).length;

function polyDecrypt(text, nextShift) {
  let out = '';
  let idx = 0;
  for (const ch of text) {
    const c = ch.charCodeAt(0);
    const base = c >= 65 && c <= 90 ? 65 : c >= 97 && c <= 122 ? 97 : 0;
    if (!base) {
      out += ch;
      continue;
    }
    const p = nextShift(c - base, idx++);
    out += String.fromCharCode(base + p);
  }
  return out;
}

function classicWithKeys(_, text, ctx) {
  if (letterCount(text) < 4) return null;
  const res = [];
  for (const src of ctx.keyMaterial.sources) {
    const k = keyLetters(src);
    if (!k.length) continue;
    const label = `키 "${short(src)}"`;
    // Vigenère: P = C - K
    res.push({ cipher: 'Vigenère', out: polyDecrypt(text, (c, i) => (c - k[i % k.length] + 26) % 26), note: label });
    // Beaufort: P = K - C
    res.push({ cipher: 'Beaufort', out: polyDecrypt(text, (c, i) => (k[i % k.length] - c + 26) % 26), note: label });
    // Autokey: 키 뒤에 평문이 이어 붙는 키스트림
    const stream = [...k];
    res.push({
      cipher: 'Autokey',
      out: polyDecrypt(text, (c, i) => {
        const p = (c - stream[i] + 26) % 26;
        stream.push(p);
        return p;
      }),
      note: label,
    });
  }
  return res;
}

function playfairGrid(key) {
  const seen = new Set();
  const grid = [];
  for (const ch of (key.toUpperCase() + 'ABCDEFGHIKLMNOPQRSTUVWXYZ').replace(/J/g, 'I')) {
    if (ch < 'A' || ch > 'Z' || seen.has(ch)) continue;
    seen.add(ch);
    grid.push(ch);
  }
  const pos = new Map(grid.map((ch, i) => [ch, [Math.floor(i / 5), i % 5]]));
  return { grid, pos };
}

function playfairWithKeys(_, text, ctx) {
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
  if (letters.length < 4 || letters.length % 2) return null;
  // 원문이 거의 글자로만 이루어져 있을 때만
  if (letters.length / text.replace(/\s/g, '').length < 0.9) return null;
  const res = [];
  for (const src of ctx.keyMaterial.sources) {
    if (!keyLetters(src).length) continue;
    const { grid, pos } = playfairGrid(src);
    let out = '';
    for (let i = 0; i < letters.length; i += 2) {
      const [r1, c1] = pos.get(letters[i]);
      const [r2, c2] = pos.get(letters[i + 1]);
      if (r1 === r2) out += grid[r1 * 5 + ((c1 + 4) % 5)] + grid[r2 * 5 + ((c2 + 4) % 5)];
      else if (c1 === c2) out += grid[((r1 + 4) % 5) * 5 + c1] + grid[((r2 + 4) % 5) * 5 + c2];
      else out += grid[r1 * 5 + c2] + grid[r2 * 5 + c1];
    }
    res.push({ out: te(out), note: `키 "${short(src)}"` });
  }
  return res;
}

function columnarDecrypt(chars, order) {
  const n = chars.length;
  const k = order.length;
  const rows = Math.ceil(n / k);
  const full = n % k || k; // 마지막 행까지 꽉 찬 열의 수
  const cols = new Array(k);
  let pos = 0;
  for (const c of order) {
    const len = c < full ? rows : rows - 1;
    cols[c] = chars.slice(pos, pos + len);
    pos += len;
  }
  let out = '';
  for (let r = 0; r < rows; r++) for (let c = 0; c < k; c++) if (r < cols[c].length) out += cols[c][r];
  return out;
}

function columnarWithKeys(_, text, ctx) {
  const chars = Array.from(text);
  if (chars.length < 6 || chars.length > 5000) return null;
  const res = [];
  for (const src of ctx.keyMaterial.sources) {
    const key = src.replace(/\s/g, '');
    if (key.length < 2 || key.length >= chars.length) continue;
    // 숫자 키(예: 3142)는 숫자 순서, 아니면 글자 순서 (같으면 왼쪽 먼저)
    const ks = /^\d+$/.test(key) ? [...key].map(Number) : [...key.toUpperCase()];
    const order = ks.map((v, i) => [v, i]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] - b[1])).map((x) => x[1]);
    res.push({ out: te(columnarDecrypt(chars, order)), note: `키 "${short(src)}"` });
  }
  return res;
}

// ---------------------------------------------------------------------------

const withCipherName = (fn) => (b, t, ctx) => {
  const r = fn(b, t, ctx);
  return r && r.map((x) => ({ out: te(x.out), note: `${x.cipher} · ${x.note}` }));
};

export const KEYED_OPERATIONS = [
  { id: 'k-xor', name: 'XOR (입력한 키)', category: 'key', needsKey: true, noRepeat: true, run: xorWithKeys },
  { id: 'k-aes', name: 'AES 복호화', category: 'key', needsKey: true, run: aesWithKeys },
  { id: 'k-rc4', name: 'RC4', category: 'key', needsKey: true, noRepeat: true, run: rc4WithKeys },
  { id: 'k-poly', name: '다표식 암호 (입력한 키)', category: 'key', needsKey: true, run: withCipherName(classicWithKeys) },
  { id: 'k-playfair', name: 'Playfair', category: 'key', needsKey: true, run: playfairWithKeys },
  { id: 'k-columnar', name: '전치 암호 (Columnar)', category: 'key', needsKey: true, run: columnarWithKeys },
];
