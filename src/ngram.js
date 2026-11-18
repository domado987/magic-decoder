// quadgram 기반 "영어다움" 점수 (치환 암호 솔버용).
// 26^4 크기의 Float32Array 로 펼쳐서 O(1) 조회한다.

// 데이터 파일(~200KB)은 솔버가 처음 필요할 때만 불러온다 (첫 화면 로딩을 가볍게)

const SIZE = 26 ** 4;
let table = null;
let words = null;
let loading = null;

export function loadNgrams() {
  if (table) return Promise.resolve();
  loading ??= import('./data/quadgrams.js').then(build);
  return loading;
}

/** 영어 단어 집합 (대문자) */
export function wordSet() {
  if (!words) throw new Error('loadNgrams() 를 먼저 호출하세요');
  return words;
}

function build({ MIN, MAX, QUADS, SCORES, WORDS }) {
  words = new Set(WORDS.split(' '));
  // 표에 없는 quadgram 은 거의 안 나오는 조합으로 본다
  const missing = MIN - 0.7;
  table = new Float32Array(SIZE).fill(missing);
  const bin = atob(SCORES);
  for (let i = 0; i < bin.length; i++) {
    const q = QUADS.substr(i * 4, 4);
    const idx = (((q.charCodeAt(0) - 65) * 26 + (q.charCodeAt(1) - 65)) * 26 + (q.charCodeAt(2) - 65)) * 26 + (q.charCodeAt(3) - 65);
    table[idx] = MIN + (bin.charCodeAt(i) / 255) * (MAX - MIN);
  }
}

export function quadgramTable() {
  if (!table) throw new Error('loadNgrams() 를 먼저 호출하세요');
  return table;
}

/** 0~25 로 된 글자 배열의 quadgram 로그 확률 합 */
export function quadScore(letters) {
  const t = quadgramTable();
  let s = 0;
  for (let i = 0; i + 3 < letters.length; i++) {
    s += t[((letters[i] * 26 + letters[i + 1]) * 26 + letters[i + 2]) * 26 + letters[i + 3]];
  }
  return s;
}

/** 글자당 평균 점수 (영어 ≈ -2.4 ~ -2.9, 무작위 ≈ -5.5 이하) */
export function quadFitness(text) {
  const letters = [];
  for (const ch of text.toUpperCase()) {
    const c = ch.charCodeAt(0) - 65;
    if (c >= 0 && c < 26) letters.push(c);
  }
  if (letters.length < 4) return -Infinity;
  return quadScore(letters) / (letters.length - 3);
}

/**
 * 단어 경계를 반영한 가중 점수. weights[i] 는 i 번째 글자에서 시작하는 quadgram 의 가중치.
 * (단어 안의 quadgram 은 1, 단어 경계를 넘는 것은 낮게 → 띄어쓰기가 있는 글에서 엉뚱한 해석 방지)
 */
export function quadScoreWeighted(letters, weights) {
  const t = quadgramTable();
  let s = 0;
  for (let i = 0; i + 3 < letters.length; i++) {
    s += weights[i] * t[((letters[i] * 26 + letters[i + 1]) * 26 + letters[i + 2]) * 26 + letters[i + 3]];
  }
  return s;
}
