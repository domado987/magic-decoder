// 바이트 <-> 문자열 변환 유틸리티.
// 엔진 내부에서는 모든 데이터를 Uint8Array 로 다룬다 (CyberChef 와 같은 방식).

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const utf8Encoder = new TextEncoder();

export function utf8Encode(str) {
  return utf8Encoder.encode(str);
}

/** 올바른 UTF-8 이면 문자열, 아니면 null */
export function utf8Decode(bytes) {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    return null;
  }
}

export function latin1Decode(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return s;
}

export function latin1Encode(str) {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

/** 사람이 읽을 텍스트로: UTF-8 로 읽히면 UTF-8, 아니면 latin1 */
export function bytesToText(bytes) {
  const u = utf8Decode(bytes);
  return u ?? latin1Decode(bytes);
}

export function bytesToHex(bytes, sep = ' ') {
  const parts = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) parts[i] = bytes[i].toString(16).padStart(2, '0');
  return parts.join(sep);
}

export function isPrintableByte(b) {
  return (b >= 0x20 && b < 0x7f) || b === 0x09 || b === 0x0a || b === 0x0d;
}

/** 중복 제거용 키 */
export function bytesKey(bytes) {
  return latin1Decode(bytes);
}

const SIGNATURES = [
  { name: 'PNG 이미지', ext: 'png', mime: 'image/png', sig: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { name: 'JPEG 이미지', ext: 'jpg', mime: 'image/jpeg', sig: [0xff, 0xd8, 0xff] },
  { name: 'GIF 이미지', ext: 'gif', mime: 'image/gif', sig: [0x47, 0x49, 0x46, 0x38] },
  { name: 'PDF 문서', ext: 'pdf', mime: 'application/pdf', sig: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { name: 'ZIP 압축 파일', ext: 'zip', mime: 'application/zip', sig: [0x50, 0x4b, 0x03, 0x04] },
  { name: 'GZIP 압축 데이터', ext: 'gz', mime: 'application/gzip', sig: [0x1f, 0x8b] },
  { name: '7-Zip 압축 파일', ext: '7z', mime: 'application/x-7z-compressed', sig: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { name: 'RAR 압축 파일', ext: 'rar', mime: 'application/vnd.rar', sig: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] },
  { name: 'BZIP2 압축 데이터', ext: 'bz2', mime: 'application/x-bzip2', sig: [0x42, 0x5a, 0x68] },
  { name: 'ELF 실행 파일', ext: 'elf', mime: 'application/octet-stream', sig: [0x7f, 0x45, 0x4c, 0x46] },
  { name: 'Windows 실행 파일(PE)', ext: 'exe', mime: 'application/octet-stream', sig: [0x4d, 0x5a] },
  { name: 'Java class 파일', ext: 'class', mime: 'application/octet-stream', sig: [0xca, 0xfe, 0xba, 0xbe] },
];

/** 매직 바이트로 파일 형식 추정 */
export function detectFileType(bytes) {
  for (const t of SIGNATURES) {
    if (bytes.length < t.sig.length) continue;
    if (t.sig.every((b, i) => bytes[i] === b)) return { name: t.name, ext: t.ext, mime: t.mime };
  }
  // zlib 헤더: 0x78 로 시작하고 (CMF*256+FLG) % 31 == 0
  if (bytes.length > 2 && bytes[0] === 0x78 && ((bytes[0] << 8) | bytes[1]) % 31 === 0) {
    return { name: 'zlib 압축 데이터', ext: 'zlib', mime: 'application/octet-stream' };
  }
  return null;
}
