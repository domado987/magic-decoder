#!/usr/bin/env node
// 터미널에서 쓰는 Magic Decoder
//   node cli.js "ZmxhZ3t0ZXN0fQ=="
//   echo "..." | node cli.js --crib "flag{"

import { magic } from './src/magic.js';
import { bytesToHex } from './src/bytes.js';

const args = process.argv.slice(2);
const opts = { maxDepth: 4, crib: '', keys: [], top: 5, json: false, all: false };
const positional = [];

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '-d' || a === '--depth') opts.maxDepth = Number(args[++i]);
  else if (a === '-c' || a === '--crib') opts.crib = args[++i];
  else if (a === '-k' || a === '--key') opts.keys.push(args[++i]);
  else if (a === '-n' || a === '--top') opts.top = Number(args[++i]);
  else if (a === '--json') opts.json = true;
  else if (a === '-a' || a === '--all') opts.all = true;
  else if (a === '-h' || a === '--help') {
    console.log(`사용법: magic-decoder [옵션] [입력]   (입력이 없으면 stdin)

  -c, --crib <문자열>  플래그 형식 / 알려진 평문 (예: "flag{")
  -k, --key <문자열>   키/IV 후보 (여러 번 지정 가능)
  -d, --depth <n>      최대 연쇄 단계 (기본 4)
  -n, --top <n>        출력할 결과 수 (기본 5)
  -a, --all            점수가 낮은 결과도 출력
      --json           JSON 으로 출력`);
    process.exit(0);
  } else positional.push(a);
}

async function readStdin() {
  if (process.stdin.isTTY) return '';
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
}

const input = positional.length ? positional.join(' ') : await readStdin();
if (!input) {
  console.error('입력이 없습니다. --help 를 참고하세요.');
  process.exit(1);
}

const res = await magic(input, { maxDepth: opts.maxDepth, crib: opts.crib, keys: opts.keys, timeLimit: 10000 });
let list = res.results.filter((r) => opts.all || r.score >= 45).slice(0, opts.top);
// 읽을 수 있는 결과가 없으면, 형식상 디코딩된 한 단계 결과라도 보여준다
if (!list.length && res.input.analysis.lang < 0.4) list = res.results.filter((r) => r.depth === 1).slice(0, opts.top);

if (opts.json) {
  console.log(
    JSON.stringify(
      {
        hints: res.hints,
        results: list.map((r) => ({
          score: r.score,
          recipe: r.recipe.map((s) => (s.note ? `${s.name} (${s.note})` : s.name)),
          output: r.isText ? r.text : null,
          hex: r.isText ? null : bytesToHex(r.bytes, ''),
          fileType: r.fileType?.name ?? null,
        })),
        stats: res.stats,
      },
      null,
      2
    )
  );
  process.exit(0);
}

const tty = process.stdout.isTTY;
const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);

for (const hnt of res.hints) console.log(c('33', `💡 ${hnt.title}`) + c('2', ` — ${hnt.detail}`));
if (res.hints.length) console.log();

if (!list.length) {
  console.log('그럴듯한 결과를 찾지 못했습니다. (--all 로 낮은 점수 결과 보기)');
  process.exit(0);
}

list.forEach((r, i) => {
  const recipe = r.recipe.map((s) => (s.note ? `${s.name} ${c('2', `(${s.note})`)}` : s.name)).join(c('2', ' → '));
  console.log(`${c('2', `#${i + 1}`)} ${c(r.score >= 70 ? '32' : '33', r.score.toFixed(0).padStart(3))}  ${recipe}`);
  let out;
  if (r.isText) out = r.text.length > 500 ? r.text.slice(0, 500) + ' …' : r.text;
  else out = `[${r.fileType?.name ?? '바이너리'} ${r.bytes.length}B] ${bytesToHex(r.bytes.subarray(0, 48))}${r.bytes.length > 48 ? ' …' : ''}`;
  console.log('     ' + out.split('\n').join('\n     '));
  console.log();
});
console.log(c('2', `후보 ${res.stats.candidates}개 · ${res.stats.ms}ms`));
