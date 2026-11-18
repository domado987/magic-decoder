import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
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
  const res = await magic('9f3a71c2e04b88d1576aa3fe2c19b04d7e6158c3a9f20b7d44e1');
  const titles = res.hints.map((h) => h.title).join(' | ');
  assert.match(titles, /Hex\(16진수\)/);
  assert.match(titles, /암호화된 데이터/);
  assert.ok(res.results.some((r) => r.depth === 1 && r.recipe[0].id === 'base64'), 'Base64 한 단계 결과는 있어야 함');
});

// ---- 재인코딩 / 키 기반 복호화 ----

test('Hex → 바이트 → To Base64 (디코딩 후 다시 인코딩)', async () => {
  const target = 'Magic+Decoder+turns+hex+into+Base64/';
  const res = await magic(Buffer.from(target, 'base64').toString('hex'));
  assert.equal(res.results[0].text, target);
  assert.deepEqual(res.results[0].recipe.map((s) => s.id), ['hex', 'tobase64']);
});

test('To Base64 는 무작위 바이너리에 쓰레기 결과를 만들지 않는다', async () => {
  const res = await magic(crypto.randomBytes(40).toString('hex'));
  assert.ok(!res.results.some((r) => r.recipe.some((s) => s.id === 'tobase64')));
});

const aesEnc = (mode, key, iv, pt) => {
  const c = crypto.createCipheriv(mode, key, iv);
  return Buffer.concat([c.update(pt), c.final()]);
};
const SECRET = 'flag{keyed_ciphers_are_fun}';

const keyed = [
  ['AES-128-ECB (텍스트 키) + Base64', aesEnc('aes-128-ecb', 'YELLOW SUBMARINE', null, SECRET).toString('base64'), ['YELLOW SUBMARINE'], 'k-aes', /ECB/],
  ['AES-256-CBC (SHA-256 키, IV 앞붙임) + Hex', (() => {
    const iv = crypto.randomBytes(16);
    return Buffer.concat([iv, aesEnc('aes-256-cbc', crypto.createHash('sha256').update('password').digest(), iv, SECRET)]).toString('hex');
  })(), ['password'], 'k-aes', /SHA-256/],
  ['AES-128-CBC (MD5 키, IV 따로 입력)', (() => {
    const iv = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    return aesEnc('aes-128-cbc', crypto.createHash('md5').update('hunter2').digest(), iv, SECRET).toString('base64');
  })(), ['hunter2', '000102030405060708090a0b0c0d0e0f'], 'k-aes', /MD5/],
  ['AES-128-CTR (hex 키, 카운터 0)', aesEnc('aes-128-ctr', Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'), Buffer.alloc(16), SECRET).toString('hex'), ['2b7e151628aed2a6abf7158809cf4f3c'], 'k-aes', /CTR/],
  ['RC4', (() => {
    const S = [...Array(256).keys()]; const k = Buffer.from('Secret');
    for (let i = 0, j = 0; i < 256; i++) { j = (j + S[i] + k[i % k.length]) & 255; [S[i], S[j]] = [S[j], S[i]]; }
    let i = 0, j = 0;
    return Buffer.from(SECRET).map((b) => { i = (i + 1) & 255; j = (j + S[i]) & 255; [S[i], S[j]] = [S[j], S[i]]; return b ^ S[(S[i] + S[j]) & 255]; }).toString('hex');
  })(), ['Secret'], 'k-rc4'],
  ['반복 키 XOR (키 입력)', xorHex(SECRET, 'xorkey'), ['xorkey'], 'k-xor'],
  ['Vigenère (키 입력, 짧은 문장)', vigenere('meet me at noon', 'LEMON'), ['lemon'], 'k-poly', /Vigen/],
  ['Playfair', 'BMODZBXDNABEKUDMUIXMMOUVIF', ['playfair example'], 'k-playfair'],
];

for (const [name, input, keys, opId, noteRe] of keyed) {
  test(`키: ${name}`, async () => {
    const res = await magic(input, { keys });
    const top = res.results[0];
    assert.ok(top, '결과 없음');
    assert.ok(top.recipe.some((s) => s.id === opId), `1위 레시피: ${top.recipe.map((s) => s.name + ' ' + s.note).join(' → ')}`);
    if (noteRe) assert.match(top.recipe.find((s) => s.id === opId).note, noteRe);
    const expected = { 'k-playfair': 'HIDETHEGOLDINTHETREXESTUMP', 'k-poly': 'meet me at noon' }[opId] ?? SECRET;
    assert.equal(top.text, expected);
  });
}

test('키: Columnar 전치 (글자 키)', async () => {
  // ZEBRAS 키로 직접 암호화
  const pt = 'WEAREDISCOVEREDFLEEATONCE';
  const key = 'ZEBRAS';
  const order = [...key].map((c, i) => [c, i]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] - b[1])).map((x) => x[1]);
  const ct = order.map((c) => [...pt].filter((_, i) => i % key.length === c).join('')).join('');
  const res = await magic(ct, { keys: [key] });
  assert.equal(res.results[0].text, pt);
});

test('틀린 키로는 엉뚱한 결과를 높게 매기지 않는다', async () => {
  const ct = aesEnc('aes-128-ecb', 'YELLOW SUBMARINE', null, SECRET).toString('base64');
  const res = await magic(ct, { keys: ['WRONG KEY HERE!!', 'nope'] });
  assert.ok(res.results.every((r) => r.score < 45));
});
