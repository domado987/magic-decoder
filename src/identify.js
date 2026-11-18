// 디코딩은 못 하지만 "이게 뭔지"는 알려줄 수 있는 것들 (해시, 키, RSA 파라미터 등)

const HEX_HASHES = {
  8: 'CRC32',
  16: 'MySQL323 / 64비트 해시',
  32: 'MD5 / NTLM / MD4',
  40: 'SHA-1 / RIPEMD-160',
  56: 'SHA-224 / SHA3-224',
  64: 'SHA-256 / SHA3-256 / BLAKE2s',
  96: 'SHA-384 / SHA3-384',
  128: 'SHA-512 / SHA3-512 / BLAKE2b / Whirlpool',
};

export function identify(text) {
  const s = text.trim();
  const hints = [];
  if (!s) return hints;

  if (/^[a-fA-F0-9]+$/.test(s) && HEX_HASHES[s.length]) {
    hints.push({
      title: `${HEX_HASHES[s.length]} 해시일 수 있음`,
      detail: '해시는 단방향이라 "복호화"가 아니라 크래킹(사전 대입/레인보우 테이블) 대상입니다. CrackStation, hashcat, john 등을 써 보세요.',
    });
  }
  const crypt = [
    [/^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/, 'bcrypt'],
    [/^\$1\$/, 'md5crypt'],
    [/^\$5\$/, 'sha256crypt'],
    [/^\$6\$/, 'sha512crypt (리눅스 /etc/shadow)'],
    [/^\$argon2(id|i|d)\$/, 'Argon2'],
    [/^\$apr1\$/, 'Apache MD5 (htpasswd)'],
    [/^\$y\$/, 'yescrypt'],
  ];
  for (const [re, name] of crypt) {
    if (re.test(s)) hints.push({ title: `${name} 비밀번호 해시`, detail: 'hashcat / john 으로 크래킹하는 대상입니다.' });
  }
  if (/^-----BEGIN [A-Z0-9 ]+-----/.test(s)) {
    const kind = s.match(/^-----BEGIN ([A-Z0-9 ]+)-----/)[1];
    hints.push({ title: `PEM 형식 (${kind})`, detail: '본문은 Base64 로 인코딩된 DER 입니다. openssl 로 내용을 볼 수 있어요.' });
  }
  if (/\bn\s*[=:]\s*\d{20,}/i.test(s) && /\be\s*[=:]\s*\d+/i.test(s)) {
    hints.push({
      title: 'RSA 파라미터처럼 보임',
      detail: 'n, e, (c) 가 보입니다. 작은 e, 작은 n 인수분해(factordb), 공통 인수 등을 확인해 보세요. RsaCtfTool / SageMath 가 유용합니다.',
    });
  }
  if (/^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*$/.test(s) && s.startsWith('eyJ')) {
    hints.push({ title: 'JWT 토큰', detail: '헤더와 페이로드는 아래 결과에서 해독됩니다. alg=none, 약한 HS256 키 등을 점검해 보세요.' });
  }
  if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(s)) {
    hints.push({ title: 'UUID', detail: '버전 1 UUID 라면 생성 시각과 MAC 주소 정보가 들어 있습니다.' });
  }
  return hints;
}
