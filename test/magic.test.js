import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { magic } from '../src/magic.js';

// ---- 테스트 벡터를 만드는 헬퍼 ----
const b64 = (s) => Buffer.from(s).toString('base64');
const hex = (s) => Buffer.from(s).toString('hex');
const rot = (s, k) =>
  s.replace(/[a-z]/gi, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + k) % 26) + base);
  });
const rot47 = (s) => [...s].map((ch) => { const x = ch.charCodeAt(0); return x >= 33 && x <= 126 ? String.fromCharCode(33 + ((x - 33 + 47) % 94)) : ch; }).join('');
const vigenere = (s, key) => {
  let i = 0;
  return s.replace(/[a-z]/gi, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    const k = key.charCodeAt(i++ % key.length) - 65;
    return String.fromCharCode(((ch.charCodeAt(0) - base + k) % 26) + base);
  });
};
const xorHex = (s, key) => { const k = Buffer.from(key); return Buffer.from(s).map((b, i) => b ^ k[i % k.length]).toString('hex'); };

const PANGRAM = 'the quick brown fox jumps over the lazy dog';
const AUSTEN = 'It is a truth universally acknowledged that a single man in possession of a good fortune must be in want of a wife';

const cases = [
  ['Base64', b64('flag{hello_world}'), 'flag{hello_world}', ['base64']],
  ['Base64 두 번', b64(b64('This is a secret message')), 'This is a secret message', ['base64', 'base64']],
  ['URL-safe Base64', 'd2hhdCBhYm91dCB0aGVzZSA_Pz8gY2hhcmFjdGVycyA-Pj4', 'what about these ??? characters >>>', ['base64']],
  ['Base32', 'MZWGCZ33MJQXGZJTGJ6Q====', 'flag{base32}', ['base32']],
  ['Base58', '2NEpo7TZRRrLZSi2U', 'Hello World!', ['base58']],
  ['Ascii85', '<~87cURD]i,"Ebo7~>', 'Hello World', ['ascii85']],
  ['Hex', hex('Hello, World! how are you'), 'Hello, World! how are you', ['hex']],
  ['Hex (\\x 형식)', '\\x66\\x6c\\x61\\x67\\x7b\\x78\\x7d', 'flag{x}'],
  ['Binary', 'hi there'.split('').map((c) => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' '), 'hi there', ['binary']],
  ['Decimal', '102 108 97 103 123 100 101 99 125', 'flag{dec}', ['decimal']],
  ['Octal', '146 154 141 147 173 157 143 164 175', 'flag{oct}', ['octal']],
  ['A1Z26', '8 5 12 12 15 / 23 15 18 12 4', 'HELLO WORLD', ['a1z26']],
  ['URL', encodeURIComponent('안녕하세요 flag{url}'), '안녕하세요 flag{url}', ['url']],
  ['HTML 엔티티', '&#102;&#108;&#97;&#103;&#123;&#104;&#116;&#109;&#108;&#125;', 'flag{html}', ['html']],
  ['이스케이프', '\\x48\\x65\\x6c\\x6c\\x6f \\uc548\\ub155', 'Hello 안녕', ['escape']],
  ['모스 부호', '.... . .-.. .-.. --- / .-- --- .-. .-.. -..', 'HELLO WORLD', ['morse']],
  ['Bacon', 'AABBB AABAA ABABB ABABB ABBBA', 'HELLO', ['bacon']],
  ['ROT13', rot('flag{rot_thirteen_is_easy}', 13), 'flag{rot_thirteen_is_easy}', ['caesar']],
  ['시저 (키 3)', rot('meet me at the park after school', 3), 'meet me at the park after school', ['caesar']],
  ['ROT47', rot47('flag{rot47_works}'), 'flag{rot47_works}', ['rot47']],
  ['Atbash', 'uozt{zgyzhs_rh_xllo}', 'flag{atbash_is_cool}', ['atbash']],
  ['뒤집기', '}gnihtyna_esrever{galf', 'flag{reverse_anything}', ['reverse']],
  ['Rail Fence', 'WECRLTEERDSOEEFEAOCAIVDEN', 'WEAREDISCOVEREDFLEEATONCE', ['railfence']],
  ['Vigenère (키 자동 추정)', vigenere(AUSTEN, 'LEMON'), AUSTEN, ['vigenere']],
  ['Base64 → ROT13', rot(b64(PANGRAM), 13), PANGRAM, ['caesar', 'base64']],
  ['ROT13 → Base64', b64(rot(PANGRAM, 13)), PANGRAM, ['base64', 'caesar']],
  ['gzip + Base64', zlib.gzipSync('compressed secret text here').toString('base64'), 'compressed secret text here', ['base64', 'gunzip']],
  ['zlib + Hex', zlib.deflateSync('zlib inside hex encoded').toString('hex'), 'zlib inside hex encoded', ['hex', 'zlib']],
  ['1바이트 XOR + Hex', xorHex('this is xor encrypted text, can you find the key?', [0x5a]), 'this is xor encrypted text, can you find the key?', ['hex', 'xor1']],
  ['Brainfuck', '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.', 'Hello World!\n', ['brainfuck']],
  ['한글 Base64', b64('안녕하세요, 반갑습니다'), '안녕하세요, 반갑습니다', ['base64']],
];

for (const [name, input, expected, recipe] of cases) {
  test(name, async () => {
    const res = await magic(input);
    assert.ok(res.results.length, '결과가 없음');
    const top = res.results[0];
    assert.equal(top.text, expected, `1위 결과: ${top.recipe.map((s) => s.name).join(' → ')}`);
    if (recipe) assert.deepEqual(top.recipe.map((s) => s.id), recipe);
  });
}

test('crib 으로 반복 키 XOR 키 역산', async () => {
  const res = await magic(xorHex('flag{repeating_key_xor}', 'key'), { crib: 'flag{' });
  assert.equal(res.results[0].text, 'flag{repeating_key_xor}');
  assert.match(res.results[0].recipe.at(-1).note, /"key"/);
});

test('JWT 디코드', async () => {
  const jwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const res = await magic(jwt);
  const top = res.results[0];
  assert.equal(top.recipe[0].id, 'jwt');
  assert.equal(JSON.parse(top.text).payload.name, 'John Doe');
  assert.ok(res.hints.some((h) => h.title.includes('JWT')));
});

test('해시는 디코딩 대신 힌트로 알려준다', async () => {
  const res = await magic('5f4dcc3b5aa765d61d8327deb882cf99');
  assert.ok(res.hints.some((h) => h.title.includes('MD5')));
  assert.ok(res.results.every((r) => r.score < 45), '해시에서 그럴듯한 결과가 나오면 안 됨');
});

test('평문은 그대로 두고 엉뚱한 결과를 높게 매기지 않는다', async () => {
  const res = await magic('just a normal english sentence');
  assert.ok(res.input.analysis.score > 60);
  assert.ok(res.results.every((r) => r.score < res.input.analysis.score));
});

test('취소(AbortSignal) 시 null 반환', async () => {
  const ac = new AbortController();
  ac.abort();
  assert.equal(await magic('ZmxhZ3t4fQ==', { signal: ac.signal }), null);
});

test('무작위 바이트로만 풀리는 입력은 Hex/암호문 힌트를 준다', async () => {
  const res = await magic('72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf');
  const titles = res.hints.map((h) => h.title).join(' | ');
  assert.match(titles, /Hex\(16진수\)/);
  assert.match(titles, /암호화된 데이터/);
  assert.ok(res.results.some((r) => r.depth === 1 && r.recipe[0].id === 'base64'), 'Base64 한 단계 결과는 있어야 함');
});
