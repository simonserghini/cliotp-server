// cliotp web UI — vanilla JS, no dependencies.
const LS_KEY = 'cliotp_key';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

let key = localStorage.getItem(LS_KEY) || '';
let codesTimer = null;

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async function api(method, path, body) {
  const headers = { Accept: 'application/json' };
  if (key) headers.Authorization = 'Bearer ' + key;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) { logout(true); throw new Error('unauthorized'); }
  let data = null;
  try { data = await res.json(); } catch { /* no body */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 4000);
}

// ---------------------------------------------------------------------------
// Auth / view switching
// ---------------------------------------------------------------------------

function showLogin() {
  $('#login').hidden = false;
  $('#app').hidden = true;
  if (codesTimer) { clearInterval(codesTimer); codesTimer = null; }
}

function showApp() {
  $('#login').hidden = true;
  $('#app').hidden = false;
  switchTab('codes');
  refreshAll();
  if (!codesTimer) codesTimer = setInterval(loadCodes, 1000);
}

function login() {
  key = $('#key-input').value.trim();
  if (!key) return;
  localStorage.setItem(LS_KEY, key);
  $('#login-error').hidden = true;
  showApp();
}

function logout(silent) {
  key = '';
  localStorage.removeItem(LS_KEY);
  if (!silent) showLogin();
  showLogin();
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

function switchTab(name) {
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  $('#tab-codes').hidden = name !== 'codes';
  $('#tab-entries').hidden = name !== 'entries';
  $('#tab-keys').hidden = name !== 'keys';
  if (name === 'entries') loadEntries();
  if (name === 'keys') loadKeys();
}

// ---------------------------------------------------------------------------
// Codes
// ---------------------------------------------------------------------------

async function loadCodes() {
  if (!key) return;
  let codes;
  try { codes = await api('GET', '/api/codes'); }
  catch (e) { toast(e.message); return; }

  const grid = $('#codes-grid');
  grid.innerHTML = '';
  $('#codes-empty').hidden = codes.length > 0;

  for (const c of codes) {
    const card = document.createElement('div');
    card.className = 'code-card';

    const label = (c.issuer ? c.issuer + ': ' : '') + c.name;
    const isHotp = c.kind === 'hotp';
    const pct = isHotp ? 100 : Math.min(100, Math.max(0, ((c.secondsRemaining || 0) / c.period) * 100));
    const barClass = pct <= 20 ? ' crit' : pct <= 45 ? ' warn' : '';

    card.innerHTML = `
      <div class="label"></div>
      <div class="issuer"></div>
      <div class="code"></div>
      <div class="meta">
        <span class="kind-badge">${esc(c.kind)}</span>
        <span class="countdown"></span>
      </div>
      ${isHotp ? `<div class="meta"><button class="btn btn-ghost" data-consume="${c.id}">Next code</button></div>` : `<div class="progress ${barClass}"><div style="width:${pct}%"></div></div>`}
    `;

    card.querySelector('.label').textContent = label;
    card.querySelector('.issuer').textContent = c.issuer || c.kind;
    card.querySelector('.code').textContent = formatCode(c.code);
    card.querySelector('.countdown').textContent = isHotp ? `counter ${c.counter ?? 0}` : `${c.secondsRemaining ?? 0}s`;

    grid.appendChild(card);
  }
}

function formatCode(code) {
  // group digits for readability: 6 -> "123 456", 8 -> "1234 5678"
  const s = String(code);
  if (s.length === 6) return `${s.slice(0, 3)} ${s.slice(3)}`;
  if (s.length === 8) return `${s.slice(0, 4)} ${s.slice(4)}`;
  return s;
}

async function consumeHotp(id) {
  try { await api('GET', `/api/entries/${id}/code`); await loadCodes(); }
  catch (e) { toast(e.message); }
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

function resetEntryForm() {
  $('#entry-id').value = '';
  $('#entry-form').reset();
  $('#f-period').value = '30';
  $('#f-digits').value = '6';
  $('#f-algorithm').value = 'SHA1';
  $('#entry-submit').textContent = 'Add';
  $('#entry-cancel').hidden = true;
}

async function loadEntries() {
  if (!key) return;
  let entries;
  try { entries = await api('GET', '/api/entries'); }
  catch (e) { toast(e.message); return; }

  const list = $('#entries-list');
  list.innerHTML = '';
  for (const e of entries) {
    const item = document.createElement('div');
    item.className = 'list-item';
    const sub = `${e.kind} · ${e.algorithm} · ${e.digits} digits${e.kind === 'hotp' ? ' · counter ' + e.counter : ' · ' + e.period + 's'}`;
    item.innerHTML = `
      <div class="info">
        <div class="name">${esc(e.name)}</div>
        <div class="sub">${esc(e.issuer || '')}${e.issuer ? ' · ' : ''}${esc(sub)}</div>
      </div>
      <div class="actions">
        <button class="btn btn-ghost" data-edit="${e.id}">Edit</button>
        <button class="btn btn-danger" data-del="${e.id}">Delete</button>
      </div>
    `;
    list.appendChild(item);
  }
}

async function fillEditForm(id) {
  let e;
  try { e = await api('GET', `/api/entries/${id}`); }
  catch (err) { toast(err.message); return; }
  $('#entry-id').value = e.id;
  $('#f-name').value = e.name;
  $('#f-issuer').value = e.issuer || '';
  $('#f-secret').value = '';
  $('#f-kind').value = e.kind;
  $('#f-digits').value = String(e.digits);
  $('#f-period').value = String(e.period);
  $('#f-algorithm').value = e.algorithm;
  $('#entry-submit').textContent = 'Save';
  $('#entry-cancel').hidden = false;
  $('#f-secret').placeholder = '(unchanged)';
  $('#f-name').focus();
}

async function submitEntry(ev) {
  ev.preventDefault();
  const id = $('#entry-id').value;
  const name = $('#f-name').value.trim();
  const secret = $('#f-secret').value.trim();

  try {
    if (/^otpauth(-migration)?:\/\//i.test(name)) {
      await api('POST', '/api/entries', { uri: name });
    } else if (id) {
      const patch = {
        name,
        issuer: $('#f-issuer').value.trim(),
        kind: $('#f-kind').value,
        digits: Number($('#f-digits').value),
        period: Number($('#f-period').value),
        algorithm: $('#f-algorithm').value,
      };
      if (secret) patch.secret = secret;
      await api('PATCH', `/api/entries/${id}`, patch);
    } else {
      await api('POST', '/api/entries', {
        name,
        secret,
        issuer: $('#f-issuer').value.trim(),
        kind: $('#f-kind').value,
        digits: Number($('#f-digits').value),
        period: Number($('#f-period').value),
        algorithm: $('#f-algorithm').value,
      });
    }
    resetEntryForm();
    await loadEntries();
    await loadCodes();
  } catch (e) { toast(e.message); }
}

async function deleteEntry(id) {
  if (!confirm('Delete this entry?')) return;
  try { await api('DELETE', `/api/entries/${id}`); await loadEntries(); await loadCodes(); }
  catch (e) { toast(e.message); }
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

async function loadKeys() {
  if (!key) return;
  let keys;
  try { keys = await api('GET', '/api/keys'); }
  catch (e) { toast(e.message); return; }

  const list = $('#keys-list');
  list.innerHTML = '';
  for (const k of keys) {
    const item = document.createElement('div');
    item.className = 'list-item';
    const created = new Date(k.createdAt * 1000).toLocaleString();
    item.innerHTML = `
      <div class="info">
        <div class="name">${esc(k.name)}</div>
        <div class="sub">created ${esc(created)}</div>
      </div>
      <div class="actions">
        <button class="btn btn-danger" data-revoke="${esc(k.id)}">Revoke</button>
      </div>
    `;
    list.appendChild(item);
  }
}

async function createKey(ev) {
  ev.preventDefault();
  const name = $('#key-name').value.trim();
  try {
    const created = await api('POST', '/api/keys', name ? { name } : {});
    $('#new-key-value').textContent = created.key;
    $('#key-modal').hidden = false;
    $('#key-name').value = '';
    await loadKeys();
  } catch (e) { toast(e.message); }
}

async function revokeKey(id) {
  if (!confirm('Revoke this key? Any client using it will lose access.')) return;
  try { await api('DELETE', `/api/keys/${id}`); await loadKeys(); }
  catch (e) { toast(e.message); }
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------------------------------------------------------------------------
// Wire up events
// ---------------------------------------------------------------------------

$('#login-form').addEventListener('submit', (e) => { e.preventDefault(); login(); });
$('#logout').addEventListener('click', () => logout(false));
$('#key-input').addEventListener('input', () => { $('#login-error').hidden = true; });

$$('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));

$('#codes-grid').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-consume]');
  if (btn) consumeHotp(btn.dataset.consume);
});

$('#entry-form').addEventListener('submit', submitEntry);
$('#entry-cancel').addEventListener('click', resetEntryForm);

$('#entries-list').addEventListener('click', (e) => {
  const edit = e.target.closest('[data-edit]');
  const del = e.target.closest('[data-del]');
  if (edit) fillEditForm(edit.dataset.edit);
  if (del) deleteEntry(del.dataset.del);
});

$('#key-form').addEventListener('submit', createKey);
$('#keys-list').addEventListener('click', (e) => {
  const revoke = e.target.closest('[data-revoke]');
  if (revoke) revokeKey(revoke.dataset.revoke);
});

$('#copy-key').addEventListener('click', async () => {
  const val = $('#new-key-value').textContent;
  try { await navigator.clipboard.writeText(val); }
  catch { /* fallback below */ }
  $('#copy-key').textContent = 'Copied';
  setTimeout(() => { $('#copy-key').textContent = 'Copy'; }, 1500);
});

$('#close-key-modal').addEventListener('click', () => { $('#key-modal').hidden = true; });

function refreshAll() {
  loadCodes();
  loadEntries();
  loadKeys();
}

// boot
if (key) showApp(); else showLogin();
