import { magic } from './magic.js';
import { OPERATIONS } from './operations.js';
import { bytesToHex, utf8Encode, latin1Decode } from './bytes.js';

const $ = (sel) => document.querySelector(sel);
const els = {
  input: $('#input'),
  crib: $('#crib'),
  depth: $('#depth'),
  results: $('#results'),
  hints: $('#hints'),
  stats: $('#stats'),
  banner: $('#banner'),
  showAll: $('#showAll'),
  examples: $('#examples'),
  opList: $('#opList'),
  clear: $('#clearBtn'),
};

const MIN_SCORE = 45; // 기본으로 보여줄 최소 점수
const PREVIEW_CHARS = 4000;

const EXAMPLES = [
  { label: 'Base64', value: 'ZmxhZ3t3ZWxjb21lX3RvX21hZ2ljX2RlY29kZXJ9' },
  { label: 'Base64 → ROT13', value: 'Hx9HZGZtqTuyovOPLKAyAwD/VR5iVUOlo2WfMJ0h' },
  { label: '모스 부호', value: '-- .- --. .. -.-. / -.. . -.-. --- -.. . .-.' },
  { label: 'Hex + XOR', value: '312b2c252e2762203b3627623a2d30622b31622c2d3662272c21303b32362b2d2c6e622b36622b31622362212d3136372f27' },
  {
    label: 'Vigenère',
    value: 'Tx ug n evghu frujrcwmzyj eoyazaxsqrip hulx m gvykxs zlr ub czwesfdmab bq e scbo jafgfrq ahdx ns vy ambg zj m kvqi',
  },
  { label: 'gzip + Base64', value: 'H4sIAAAAAAAAA0uvyixQyMwrzkxJVUhKLE41M9FRSMsvzUtRyCwBABied+ccAAAA' },
  { label: '한글 (Hex → Base64)', value: 'ZWM5NTg4ZWI4NTk1ZWQ5NTk4ZWM4NGI4ZWM5YTk0MjEyMGVkOTU5Y2VhYjg4MGViOGY4NDIwZWM5ZTk4MjBlZDkyODBlYmEwYTRlYzlhOTQ=' },
  {
    label: 'JWT',
    value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  },
  { label: 'Brainfuck', value: '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.' },
];

// ---------------------------------------------------------------------------
// 작은 DOM 헬퍼

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') el.style.cssText = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const FLAG_HIGHLIGHT = /[A-Za-z][A-Za-z0-9_\-]{1,19}\{[^{}\n]{1,300}\}/g;

function highlighted(text, crib, withFlags) {
  const frag = document.createDocumentFragment();
  const ranges = [];
  if (withFlags) for (const m of text.matchAll(FLAG_HIGHLIGHT)) ranges.push([m.index, m.index + m[0].length]);
  if (crib) {
    const lower = text.toLowerCase();
    const c = crib.toLowerCase();
    let i = lower.indexOf(c);
    while (i !== -1 && ranges.length < 50) {
      if (!ranges.some(([a, b]) => i >= a && i < b)) ranges.push([i, i + c.length]);
      i = lower.indexOf(c, i + c.length);
    }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  let pos = 0;
  for (const [a, b] of ranges) {
    if (a < pos) continue;
    frag.append(text.slice(pos, a), h('mark', {}, text.slice(a, b)));
    pos = b;
  }
  frag.append(text.slice(pos));
  return frag;
}

function scoreColor(score) {
  const hue = Math.round(Math.max(0, Math.min(1, (score - 20) / 70)) * 140); // 빨강 → 초록
  return `hsl(${hue} 75% 55%)`;
}

function visibleText(text) {
  // 제어 문자는 보이도록 치환
  return text.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g, '·');
}

async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h('textarea', { style: 'position:fixed;opacity:0' }, text);
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  const old = btn.textContent;
  btn.textContent = '복사됨 ✓';
  setTimeout(() => (btn.textContent = old), 1200);
}

function download(bytes, fileType) {
  const blob = new Blob([bytes], { type: fileType?.mime || 'application/octet-stream' });
  const a = h('a', { href: URL.createObjectURL(blob), download: `decoded.${fileType?.ext || 'bin'}` });
  document.body.append(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(a.href);
    a.remove();
  }, 1000);
}

// ---------------------------------------------------------------------------
// 렌더링

function renderResult(r, i, crib) {
  const recipe = h('div', { class: 'recipe' });
  r.recipe.forEach((step, idx) => {
    if (idx) recipe.append(h('span', { class: 'arrow' }, '→'));
    recipe.append(h('span', { class: `chip cat-${step.category}`, title: step.note || step.name }, step.name, step.note ? h('small', {}, step.note) : null));
  });

  const badges = [];
  if (r.flag) badges.push(h('span', { class: 'badge flag' }, '🚩 플래그 형식 발견'));
  if (r.crib) badges.push(h('span', { class: 'badge flag' }, '✓ crib 포함'));
  if (r.fileType) badges.push(h('span', { class: 'badge file' }, `📦 ${r.fileType.name}`));
  if (!r.isText && !r.fileType) badges.push(h('span', { class: 'badge' }, `바이너리 ${r.bytes.length} 바이트`));

  let showHex = !r.isText;
  const pre = h('pre', { class: 'output' });
  const fill = (full = false) => {
    pre.textContent = '';
    pre.classList.toggle('binary', showHex);
    if (showHex) {
      const slice = full ? r.bytes : r.bytes.subarray(0, 1024);
      pre.textContent = hexdump(slice) + (slice.length < r.bytes.length ? `\n… (${r.bytes.length} 바이트 중 ${slice.length} 바이트 표시)` : '');
    } else {
      const t = visibleText(r.text);
      const shown = full ? t : t.slice(0, PREVIEW_CHARS);
      pre.append(highlighted(shown, els.crib.value.trim(), r.flag));
      if (shown.length < t.length) {
        pre.append(h('span', { class: 'arrow' }, `\n… (${t.length}자 중 ${shown.length}자) `), h('button', { class: 'ghost small', onclick: () => fill(true) }, '전체 보기'));
      }
    }
  };
  fill();

  const actions = h(
    'div',
    { class: 'actions' },
    h('button', { class: 'ghost small', onclick: (e) => copy(r.isText ? r.text : bytesToHex(r.bytes, ''), e.currentTarget) }, r.isText ? '복사' : 'Hex 복사'),
    h('button', { class: 'ghost small', onclick: (e) => { showHex = !showHex; e.currentTarget.textContent = showHex ? '텍스트 보기' : 'Hex 보기'; fill(); } }, showHex ? '텍스트 보기' : 'Hex 보기'),
    !r.isText || r.fileType ? h('button', { class: 'ghost small', onclick: () => download(r.bytes, r.fileType) }, '다운로드') : null,
    h('button', { class: 'ghost small', title: '이 결과에서부터 다시 분석', onclick: () => setInput(r.isText ? r.text : bytesToHex(r.bytes, '')) }, '이 결과를 입력으로 ↺')
  );

  return h(
    'article',
    { class: `result${i === 0 ? ' top' : ''}` },
    h(
      'div',
      { class: 'result-head' },
      h('span', { class: 'rank' }, `#${i + 1}`),
      recipe,
      h('div', { class: 'score', title: '그럴듯함 점수 (0~100)' }, h('div', { class: 'bar' }, h('i', { style: `width:${r.score}%;background:${scoreColor(r.score)}` })), h('b', {}, r.score.toFixed(0)))
    ),
    badges.length ? h('div', { class: 'badges' }, badges) : null,
    pre,
    actions
  );
}

function hexdump(bytes) {
  const lines = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const row = bytes.subarray(off, off + 16);
    const hex = bytesToHex(row, ' ').padEnd(47, ' ');
    const ascii = latin1Decode(row).replace(/[^\x20-\x7e]/g, '.');
    lines.push(`${off.toString(16).padStart(8, '0')}  ${hex}  ${ascii}`);
  }
  return lines.join('\n');
}

function render(res) {
  const crib = els.crib.value.trim();
  const { results, hints, stats, input } = res;

  els.hints.replaceChildren(...hints.map((x) => h('div', { class: 'hint' }, h('b', {}, `💡 ${x.title}`), h('span', {}, x.detail))));

  const visible = els.showAll.checked ? results : results.filter((r) => r.score >= MIN_SCORE);
  const hiddenCount = results.length - visible.length;

  els.stats.textContent = `후보 ${stats.candidates}개 · ${stats.ms}ms${stats.truncated ? ' · 시간 제한으로 일부만 탐색' : ''}`;

  const banners = [];
  const top = visible[0];
  if (input.analysis.isText && input.analysis.score >= 60 && (!top || top.score <= input.analysis.score + 3)) {
    banners.push(h('div', { class: 'banner' }, '입력이 이미 평문처럼 보입니다. 다른 해석이 필요하면 "낮은 점수도 보기"를 켜 보세요.'));
  }
  els.banner.replaceChildren(...banners);

  // 읽을 수 있는 결과는 없지만 형식상 디코딩은 된 경우: 한 단계 결과를 그대로 보여준다
  const rawDecodes = results.filter((r) => r.depth === 1).slice(0, 4);
  if (!visible.length && rawDecodes.length) {
    els.banner.replaceChildren(
      ...banners,
      h('div', { class: 'banner' }, '읽을 수 있는 평문은 찾지 못했어요. 형식상 디코딩은 되므로 그 결과(바이너리)를 아래에 보여 드립니다. 왼쪽 💡 힌트도 확인해 보세요.')
    );
    els.results.replaceChildren(...rawDecodes.map((r, i) => renderResult(r, i, crib)));
    return;
  }

  if (!visible.length) {
    els.results.replaceChildren(
      h(
        'p',
        { class: 'empty' },
        results.length
          ? `그럴듯한 결과를 찾지 못했어요. 점수가 낮은 후보 ${hiddenCount}개가 있습니다 — "낮은 점수도 보기"를 켜 보세요.`
          : '적용할 수 있는 디코더를 찾지 못했어요. 플래그 형식(crib)을 넣거나 최대 단계를 늘려 보세요.'
      )
    );
    return;
  }
  const cards = visible.map((r, i) => renderResult(r, i, crib));
  if (hiddenCount && !els.showAll.checked) {
    cards.push(h('p', { class: 'empty', style: 'padding:12px' }, `점수가 낮은 후보 ${hiddenCount}개는 숨겨져 있습니다.`));
  }
  els.results.replaceChildren(...cards);
}

// ---------------------------------------------------------------------------
// 실행 / 상태

let controller = null;
let timer = null;
let lastResult = null;

async function run() {
  controller?.abort();
  const value = els.input.value;
  syncHash();
  if (!value.trim()) {
    lastResult = null;
    els.hints.replaceChildren();
    els.banner.replaceChildren();
    els.stats.textContent = '';
    els.results.replaceChildren(h('p', { class: 'empty' }, '왼쪽에 문자열을 입력하면 바로 분석을 시작합니다.'));
    return;
  }
  controller = new AbortController();
  els.stats.replaceChildren(h('span', { class: 'spinner' }), '분석 중…');
  const res = await magic(value, {
    maxDepth: Number(els.depth.value),
    crib: els.crib.value,
    signal: controller.signal,
  });
  if (!res) return; // 새 입력으로 취소됨
  lastResult = res;
  render(res);
}

function schedule(delay = 220) {
  clearTimeout(timer);
  timer = setTimeout(run, delay);
}

function setInput(value) {
  els.input.value = value;
  window.scrollTo({ top: 0, behavior: 'smooth' });
  schedule(0);
}

// URL 해시로 입력 공유: #q=<base64url>&crib=...
function toB64Url(str) {
  let bin = '';
  for (const b of utf8Encode(str)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64Url(s) {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}
function syncHash() {
  const p = new URLSearchParams();
  if (els.input.value && els.input.value.length < 6000) p.set('q', toB64Url(els.input.value));
  if (els.crib.value) p.set('crib', els.crib.value);
  if (els.depth.value !== '4') p.set('depth', els.depth.value);
  const hash = p.toString();
  history.replaceState(null, '', hash ? `#${hash}` : location.pathname + location.search);
}
function loadHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  try {
    if (p.get('q')) els.input.value = fromB64Url(p.get('q'));
  } catch {
    /* 잘못된 해시는 무시 */
  }
  if (p.get('crib')) els.crib.value = p.get('crib');
  if (p.get('depth')) els.depth.value = p.get('depth');
}

// ---------------------------------------------------------------------------
// 초기화

for (const ex of EXAMPLES) {
  els.examples.append(h('button', { class: 'chip-btn', type: 'button', onclick: () => setInput(ex.value) }, ex.label));
}
for (const op of OPERATIONS) {
  els.opList.append(h('li', {}, h('span', { class: `chip cat-${op.category}` }, op.name)));
}

els.input.addEventListener('input', () => schedule());
els.crib.addEventListener('input', () => schedule());
els.depth.addEventListener('change', () => schedule(0));
els.showAll.addEventListener('change', () => lastResult && render(lastResult));
els.clear.addEventListener('click', () => {
  els.input.value = '';
  els.input.focus();
  schedule(0);
});

loadHash();
if (els.input.value) schedule(0);
els.input.focus();
