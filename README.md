# 🔮 Magic Decoder

문자열을 붙여넣기만 하면 **각종 인코딩과 고전 암호를 자동으로 연쇄 해석**해서, 가장 그럴듯한 결과부터 보여주는 도구입니다.
[CyberChef](https://gchq.github.io/CyberChef/)의 *Magic* 기능처럼 동작하고, CTF에서 자주 나오는 패턴에 맞춰 조정했습니다.

```
입력:  Hx9HZGZtqTuyovOPLKAyAwD/VR5iVUOlo2WfMJ0h

#1  62  Caesar / ROT-N (ROT13) → From Base64
        ROT13 then Base64? No problem.
```

- **서버 없음**: 모든 처리가 브라우저 안에서 이루어지고, 입력은 어디로도 전송되지 않습니다.
- **연쇄 해석**: `Base64 → Hex → XOR`처럼 여러 단계가 겹쳐 있어도 최대 6단계까지 자동으로 따라갑니다.
- **재인코딩**: `Hex → 바이트 → Base64`처럼 "풀었다가 다른 형식으로 다시 표현"해야 하는 경우도 찾습니다.
- **🔑 키 후보 입력**: 키로 짐작되는 값을 넣으면 AES·RC4·XOR·Vigenère·Playfair 등 키가 필요한 암호까지 함께 시도합니다.
- **점수 매기기**: 결과마다 0~100점의 "그럴듯함" 점수를 매겨 정렬합니다.
- **한글 지원**: UTF-8 한글/일본어/한자 결과도 자연어로 인식합니다.
- **공유 링크**: 입력이 URL `#q=...`에 저장되어 링크로 공유할 수 있습니다.
- **CLI**: 터미널에서도 똑같이 쓸 수 있습니다.

## 지원 목록

| 분류 | 항목 |
| --- | --- |
| 인코딩 | Base64 (표준/URL-safe), Base32, Base58, Ascii85, Hex (`0x`, `\x`, 구분자 포함), Binary (7/8비트), Octal, Decimal(문자 코드), 모스 부호 |
| 웹/텍스트 | URL 인코딩, HTML 엔티티, `\x` `\u` `\u{}` 이스케이프, JWT |
| 고전 암호 | Caesar/ROT-N (전수조사), ROT47, Atbash, A1Z26, Bacon, Rail Fence, **Vigenère (키 자동 추정)** |
| XOR | 1바이트 키 전수조사, **crib(예: `flag{`)로 반복 키 역산** |
| 재인코딩 | To Base64 (바이너리를 다시 Base64로. 결과가 문장/플래그일 때만 채택) |
| 압축 | gzip, zlib |
| 🔑 키 필요 | 반복 키 XOR, AES-128/192/256 (ECB · CBC · CTR), RC4, Vigenère · Beaufort · Autokey, Playfair, Columnar 전치 |
| 기타 | 문자열 뒤집기, Brainfuck 실행 |
| 식별만 | MD5/SHA 계열 해시, bcrypt/sha512crypt 등, PEM, RSA 파라미터, UUID |

해시처럼 원리상 "복호화"가 안 되는 것은 결과 대신 **💡 힌트**로 무엇인지 알려줍니다.

## 사용법

### 웹

GitHub Pages에 배포된 페이지를 쓰거나, 로컬에서 실행합니다.

```bash
npm start          # http://localhost:8080
```

> ES 모듈을 쓰기 때문에 `index.html`을 더블클릭(file://)으로 열면 동작하지 않습니다. 위처럼 로컬 서버로 열어 주세요.

- **플래그 형식 / 알려진 평문 (crib)**: `flag{`, `DH{`처럼 평문에 들어 있을 문자열을 넣으면, 그 문자열이 포함된 결과의 점수가 크게 올라갑니다. 반복 키 XOR은 이 값으로 키를 역산합니다.
- **🔑 키 / IV 후보**: 키로 짐작되는 값을 한 줄에 하나씩 넣습니다. 아래 [키 후보는 어떻게 쓰이나요?](#키-후보는-어떻게-쓰이나요)를 참고하세요.
- **최대 단계**: 몇 단계까지 연쇄 디코딩할지 정합니다 (기본 4).
- **이 결과를 입력으로 ↺**: 자동 탐색이 놓친 경우, 중간 결과에서부터 다시 분석할 수 있습니다.

### CLI

```bash
node cli.js "ZmxhZ3t0ZXN0fQ=="
echo "312b2c25..." | node cli.js --crib "flag{"
node cli.js -k "YELLOW SUBMARINE" -k "password" "LMtwCUDJ..."   # 키 후보 지정
node cli.js --json "..."          # JSON 출력
npm link && magic-decoder "..."    # 전역 명령으로 설치
```

| 옵션 | 설명 |
| --- | --- |
| `-c, --crib <s>` | 플래그 형식 / 알려진 평문 |
| `-k, --key <s>` | 키/IV 후보 (여러 번 지정 가능) |
| `-d, --depth <n>` | 최대 연쇄 단계 (기본 4) |
| `-n, --top <n>` | 출력할 결과 수 (기본 5) |
| `-a, --all` | 점수가 낮은 결과도 출력 |
| `--json` | JSON 출력 |

## 어떻게 동작하나요?

### 1. 탐색 (빔 서치)

입력에서 시작해 모든 디코더를 시도하고, 나온 결과에 다시 모든 디코더를 시도합니다. 단계마다 점수가 높은 후보 14개만 남겨서 다음 단계로 넘어가는 **빔 서치**라서, 단계가 깊어져도 탐색량이 폭발하지 않습니다.

디코더는 두 종류로 나뉩니다.

- **강한 디코더** (Base64, Hex, 모스 부호 등): 입력 형식이 엄격하게 맞을 때만 동작합니다. 형식이 맞으면 결과가 아직 읽을 수 없는 바이너리여도 다음 단계 후보로 남깁니다. (예: Base64를 풀었더니 gzip 바이너리 → 다음 단계에서 압축 해제)
- **약한 변환** (ROT-N, 뒤집기, XOR, Rail Fence 등): 어떤 문자열에든 적용할 수 있어서, 아무 결과나 남기면 쓰레기 후보가 넘쳐납니다. 그래서 **점수를 확실히 올린 경우**에만 남깁니다.
  예외로 ROT-N/ROT47/Atbash/뒤집기는 **한 수 앞을 내다봅니다**. 결과 자체의 점수는 그대로여도, 그 결과에 강한 디코더를 걸었을 때 점수가 크게 오르면 남깁니다. `Base64를 ROT13한 문자열`을 푸는 원리가 이것입니다.

### 2. 점수 (`src/score.js`)

| 요소 | 내용 |
| --- | --- |
| 출력 가능 문자 비율 | 제어 문자/깨진 바이트가 많으면 감점. 올바른 UTF-8이 아니면 추가 감점 |
| 영어 유사도 | 알파벳 빈도(코사인 유사도) + 흔한 바이그램 비율 + 사전 단어 비율 |
| 한중일 문자 비율 | 한글/가나/한자 비율 |
| 보너스 | 플래그 형식 `xxx{...}`, crib 포함, 올바른 JSON, 알려진 파일 시그니처(PNG, ZIP, ELF 등) |

마지막으로 점수가 같으면 단계가 짧은 레시피를 앞에 둡니다.

### 3. 키 자동 추정

- **Vigenère**: 키 길이마다 열을 나눠 일치 지수(IoC)를 계산하고, 영어 IoC(≈0.066)에 가까운 가장 짧은 길이를 고릅니다. 그다음 열마다 카이제곱 검정으로 시프트를 정해 키를 복원합니다.
- **반복 키 XOR**: crib이 평문 맨 앞에 있다고 가정하고 `암호문 ⊕ crib`으로 키스트림을 구한 뒤, 일관된 가장 짧은 주기를 키로 씁니다.

## 키 후보는 어떻게 쓰이나요?

키 문자열 하나를 여러 방식으로 해석해서 모두 시도합니다.

| 키 해석 | 쓰이는 곳 |
| --- | --- |
| 텍스트 그대로 (`secret`) | XOR, RC4, 고전 암호 |
| hex (`0x2b7e15…`, `2b7e15…`) | XOR, RC4, AES |
| base64 | XOR, RC4, AES |
| 길이가 16/24/32바이트인 값 | AES-128/192/256 키 |
| 짧은 텍스트 + 0 패딩 | AES 키 (`key.ljust(16, b"\0")` 같은 코드 대응) |
| `MD5(키)`, `SHA-256(키)`, `SHA-256(키)[:16]` | AES 키 (비밀번호에서 키를 만드는 흔한 방식) |
| 16바이트 값 | AES-CBC/CTR의 IV 후보 |

AES는 모드마다 이렇게 시도합니다.

- **ECB**
- **CBC**: IV=0, IV=암호문 앞 16바이트, 입력한 16바이트 값
- **CTR**: 카운터 0, nonce=암호문 앞 16바이트, 입력한 16바이트 값

PKCS#7 패딩이 올바르면 자동으로 떼어냅니다. 키 후보 × 해석 × 모드 조합이 많기 때문에, 앞 32바이트만 먼저 풀어 보고 읽을 만할 때만 전체를 풉니다.

키로 풀린 결과도 다른 디코더와 똑같이 연쇄됩니다. 예를 들어 `Base64 → AES → Hex → 평문`처럼요.

## 디코더 추가하기

`src/operations.js`의 `OPERATIONS` 배열에 객체 하나만 추가하면 됩니다.

```js
{
  id: 'rot5',
  name: 'ROT5 (숫자)',
  category: 'cipher',      // 칩 색깔: encoding | cipher | xor | compression | format | esoteric | transform | key
  strong: false,           // 형식이 엄격한 디코더면 true
  noRepeat: true,          // 같은 연산을 연달아 적용하지 않음
  // needsKey: true,       // 키 후보가 있을 때만 실행 (ctx.keyMaterial 사용, src/keyed.js 참고)
  run(bytes, text, ctx) {  // async 가능
    if (!/\d/.test(text)) return null;
    const out = text.replace(/\d/g, (d) => String((+d + 5) % 10));
    return [{ out: new TextEncoder().encode(out), note: '' }];
  },
},
```

그리고 `test/magic.test.js`에 테스트 한 줄을 추가하세요.

```bash
npm test
```

## 배포 (GitHub Pages)

이 레포에는 GitHub Actions 워크플로가 들어 있습니다.

1. 레포의 **Settings → Pages → Build and deployment → Source**를 **GitHub Actions**로 바꿉니다.
2. `main` 브랜치에 push하면 테스트를 통과한 뒤 자동으로 배포됩니다.
3. 주소: `https://<사용자명>.github.io/<레포 이름>/`

## 한계

- 단일 치환 암호(임의 알파벳 치환), Enigma, RSA 등은 지원하지 않습니다. AES 같은 현대 대칭 암호는 키를 알 때만 풀 수 있습니다.
- AES-GCM, DES/3DES, ChaCha20 등은 아직 없습니다. 필요하면 `src/keyed.js`에 추가할 수 있습니다.
- 점수는 통계적인 추정이라, 아주 짧은 문자열(몇 글자)에서는 순위가 틀릴 수 있습니다. 이럴 때는 "낮은 점수도 보기"를 켜거나 crib을 넣어 보세요.

## 라이선스

MIT
