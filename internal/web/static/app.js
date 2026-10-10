// ECS 出口代理 WebUI（原生 JS，无构建步骤）。
'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// esc 转义用户数据，所有插入 innerHTML 的动态内容都必须经过它。
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const ui = { state: null, status: null, pollTimer: null, confirmTimer: null, editingId: null };

// api 统一处理请求、登录过期与错误信息。
async function api(method, path, body) {
  const opt = { method, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  let data = null;
  try { data = await res.json(); } catch (_) { /* 非 JSON 响应 */ }
  if (res.status === 401 && path !== '/api/login') {
    showLogin();
    throw new Error((data && data.error) || '请先登录');
  }
  if (!res.ok) {
    const err = new Error((data && data.error) || `请求失败（HTTP ${res.status}）`);
    err.data = data;
    throw err;
  }
  return data;
}

function toast(msg, bad = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('bad', bad);
  t.classList.remove('hidden');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add('hidden'), bad ? 8000 : 3500);
}

function fmtTime(s) {
  if (!s || s.startsWith('0001')) return '-';
  const d = new Date(s);
  return d.toLocaleString('zh-CN', { hour12: false });
}

function fmtBytes(n) {
  if (n == null) return '-';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function since(s) {
  if (!s || s.startsWith('0001')) return '';
  const sec = Math.max(0, Math.floor((Date.now() - new Date(s)) / 1000));
  if (sec < 60) return `${sec} 秒`;
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时`;
  return `${Math.floor(sec / 86400)} 天`;
}

const modeText = { failover: '主备（自动切换）', fixed: '固定代理' };
const udpText = { proxy: '经代理', direct: '直连', block: '阻断' };

// ---------------- 登录 ----------------
function showLogin() {
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  clearInterval(ui.pollTimer);
}

async function showApp() {
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  await refreshAll();
  clearInterval(ui.pollTimer);
  ui.pollTimer = setInterval(refreshStatus, 5000);
  route();
}

$('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  $('#login-error').textContent = '';
  try {
    await api('POST', '/api/login', { username: f.username.value, password: f.password.value });
    f.password.value = '';
    await showApp();
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

$('#btn-logout').addEventListener('click', async () => {
  await api('POST', '/api/logout', {}).catch(() => {});
  showLogin();
});

// ---------------- 路由 ----------------
function route() {
  const tab = (location.hash || '#dashboard').slice(1);
  $$('.tab').forEach(s => s.classList.toggle('hidden', s.id !== `tab-${tab}`));
  $$('#tabs a').forEach(a => a.classList.toggle('active', a.dataset.tab === tab));
  if (tab === 'logs') loadLogs();
  if (tab === 'settings' || tab === 'bypass') loadPreview();
}
window.addEventListener('hashchange', route);

// ---------------- 数据刷新 ----------------
async function refreshAll() {
  await Promise.all([refreshState(), refreshStatus()]);
}

async function refreshState() {
  ui.state = await api('GET', '/api/state');
  renderProxies();
  fillPolicy();
  fillBypass();
  fillSettings();
}

async function refreshStatus() {
  try {
    ui.status = await api('GET', '/api/status');
  } catch (_) { return; }
  renderStatus();
}

function proxyName(id) {
  const p = ui.state && ui.state.proxies.find(x => x.id === id);
  return p ? p.name : id;
}

function renderStatus() {
  const s = ui.status;
  const top = $('#top-status');
  let cls = '', text = '';
  if (!s.enabled) { text = '未启用（直连）'; }
  else if (s.blackholed) { cls = 'bad'; text = '已阻断出网（代理全部不可用）'; }
  else if (s.degraded) { cls = 'warn'; text = '已降级直连（代理全部不可用）'; }
  else if (!s.engine.running && !s.dryRun) { cls = 'bad'; text = 'gost 未运行'; }
  else { cls = 'ok'; text = `出口代理运行中：${s.currentName || '-'}`; }
  if (s.dryRun) text += '（演示模式）';
  top.className = `pill ${cls}`;
  top.textContent = text;
  $('#dirty-hint').classList.toggle('hidden', !s.dirty);

  // 横幅：待确认、降级、错误。
  const banner = $('#banner');
  const msgs = [];
  if (s.pending) msgs.push(['warn', '有一次应用正在等待确认。']);
  if (s.firewall.error) msgs.push(['bad', `防火墙不可用：${s.firewall.error}`]);
  if (s.engine.error && s.enabled) msgs.push(['bad', `gost：${s.engine.error}`]);
  if (s.degraded) msgs.push(['warn', '全部代理不可用，kill switch 已关闭，当前暂时使用 ECS 自身 IP 直连。代理恢复后会自动切回。']);
  if (s.blackholed) msgs.push(['bad', '全部代理不可用，kill switch 生效，出网流量已被阻断（不会泄露 ECS 自身 IP）。']);
  if (s.dryRun) msgs.push(['info', '演示模式：不会启动 gost，也不会修改防火墙，命令只记录在“设置 → 配置预览”中。']);
  banner.innerHTML = msgs.map(([c, m]) => `<div class="banner ${c}">${esc(m)}</div>`).join('');
  if (s.pending && !$('#dlg-confirm').open) openConfirm(s.pending, null);

  $('#d-enabled').textContent = s.enabled ? '已启用' : '未启用';
  $('#d-current').textContent = s.enabled ? (s.currentName || (s.blackholed ? '无（已阻断）' : '-')) : '-';
  $('#d-mode').textContent = s.enabled ? (modeText[s.mode] || '-') : '-';
  $('#d-ks').textContent = s.enabled ? (s.killSwitch ? '开启' : '关闭') : '-';
  $('#d-udp').textContent = s.enabled ? (udpText[s.udpMode] || '-') : '-';
  $('#d-applied').textContent = fmtTime(s.appliedAt);
  $('#btn-enable').classList.toggle('hidden', s.enabled);
  $('#btn-disable').classList.toggle('hidden', !s.enabled);

  $('#d-ecsip').textContent = (s.ecs && s.ecs.publicIp) || '-';
  if (s.lastVerify && !$('#d-realip').dataset.manual) {
    $('#d-realip').textContent = s.lastVerify.realIp || '-';
    $('#d-verify').textContent = `${s.lastVerify.message}（${fmtTime(s.lastVerify.at)}）`;
  }
  const e = s.engine;
  $('#d-engine').textContent = s.dryRun ? '演示模式' : e.running ? `运行中 v${e.version} · PID ${e.pid} · 已运行 ${since(e.since)}` : `未运行${e.version ? ' · v' + e.version : ''}`;
  $('#d-fw').textContent = s.firewall.error ? '不可用' : `iptables (${s.firewall.backend || '-'})${s.active ? ' · 规则已生效' : ''}`;
  const [ct, ctMax] = s.conntrack;
  $('#d-ct').textContent = ctMax ? `${ct} / ${ctMax}（${Math.round(ct * 100 / ctMax)}%）` : '-';
  $('#d-traffic').textContent = s.traffic ? `上行 ${fmtBytes(s.traffic.inputBytes)} · 下行 ${fmtBytes(s.traffic.outputBytes)}` : '-';
  $('#d-inflight').textContent = s.traffic ? String(s.traffic.inFlight) : '-';
  $('#d-ecs').textContent = s.ecs ? `${s.ecs.instanceId || ''} ${s.ecs.regionId || ''} ${s.ecs.privateIp || ''}` : (s.ecsError || '-');

  const rows = (ui.state ? ui.state.proxies : []).filter(p => p.enabled).map(p => {
    const h = s.health[p.id];
    let st = '<span class="pill">未检查</span>';
    if (h && h.known) st = h.healthy ? '<span class="pill ok">健康</span>' : '<span class="pill bad">故障</span>';
    if (s.currentId === p.id) st += ' <span class="pill ok">当前出口</span>';
    return `<tr><td>${esc(p.name)}</td><td>${st}</td><td>${h && h.latencyMs ? h.latencyMs + ' ms' : '-'}</td><td>${h ? fmtTime(h.lastCheck) : '-'}</td><td class="small">${esc(h ? h.lastError : '')}</td></tr>`;
  });
  $('#health-table tbody').innerHTML = rows.join('') || '<tr><td colspan="5" class="muted">没有已启用的代理</td></tr>';
}

// ---------------- 应用 / 确认 ----------------
async function doApply() {
  const btn = $('#btn-apply');
  btn.disabled = true;
  btn.textContent = '应用中…';
  try {
    const res = await api('POST', '/api/apply', { skipVerify: false });
    if (res.nonce) openConfirm({ nonce: res.nonce, deadline: res.deadline }, res);
    else toast(res.message);
  } catch (err) {
    let msg = err.message;
    if (err.data && err.data.result && err.data.result.verify) msg += `\n${err.data.result.verify.message}`;
    toast(msg, true);
  } finally {
    btn.disabled = false;
    btn.textContent = '应用更改';
    await refreshAll();
  }
}
$('#btn-apply').addEventListener('click', doApply);

async function setEnabled(on) {
  try {
    await api('PUT', '/api/enabled', { enabled: on });
    await doApply();
  } catch (err) { toast(err.message, true); }
}
$('#btn-enable').addEventListener('click', () => setEnabled(true));
$('#btn-disable').addEventListener('click', () => {
  if (confirm('停用后本机将恢复使用 ECS 自身 IP 访问互联网，确定吗？')) setEnabled(false);
});

function openConfirm(pending, res) {
  const dlg = $('#dlg-confirm');
  ui.pending = pending;
  $('#confirm-msg').textContent = res && res.verify ? res.verify.message : '新的出口配置已生效。';
  const tick = () => {
    const left = Math.max(0, Math.round((new Date(pending.deadline) - Date.now()) / 1000));
    $('#confirm-left').textContent = left;
    if (left <= 0) {
      clearInterval(ui.confirmTimer);
      dlg.close();
      toast('未在规定时间内确认，已自动回滚', true);
      setTimeout(refreshAll, 1500);
    }
  };
  clearInterval(ui.confirmTimer);
  tick();
  ui.confirmTimer = setInterval(tick, 500);
  if (!dlg.open) dlg.showModal();
}

$('#btn-confirm').addEventListener('click', async () => {
  clearInterval(ui.confirmTimer);
  $('#dlg-confirm').close();
  try {
    await api('POST', '/api/apply/confirm', { nonce: ui.pending.nonce });
    toast('已确认，新配置已保存');
  } catch (err) { toast(err.message, true); }
  refreshAll();
});

$('#btn-revert').addEventListener('click', async () => {
  clearInterval(ui.confirmTimer);
  $('#dlg-confirm').close();
  try {
    await api('POST', '/api/apply/revert', { nonce: ui.pending.nonce });
    toast('已回滚到上一次的配置');
  } catch (err) { toast(err.message, true); }
  refreshAll();
});

$('#btn-check').addEventListener('click', async () => {
  const btn = $('#btn-check');
  btn.disabled = true;
  btn.textContent = '检测中…';
  try {
    const r = await api('POST', '/api/egress-check', {});
    const real = r.real.consensus || (r.real.ips || [])[0] || '-';
    $('#d-realip').textContent = real;
    $('#d-realip').dataset.manual = '1';
    const direct = r.direct.consensus || '-';
    let msg = `回显服务结果：${(r.real.ips || []).join('、') || '无'}；ECS 直连出口：${direct}`;
    if (r.real.error) msg += `；错误：${r.real.error}`;
    $('#d-verify').textContent = msg + `（${fmtTime(r.at)}）`;
  } catch (err) { toast(err.message, true); }
  btn.disabled = false;
  btn.textContent = '立即检测出口';
});

// ---------------- 代理 ----------------
function udpBadge(p) {
  if (p.udp === 'yes') return '<span class="pill ok">支持</span>';
  if (p.udp === 'no') return '<span class="pill warn">不支持</span>';
  return '<span class="pill">未知</span>';
}

function renderProxies() {
  const tb = $('#proxy-table tbody');
  const ps = ui.state.proxies;
  $('#proxy-empty').classList.toggle('hidden', ps.length > 0);
  tb.innerHTML = ps.map((p, i) => {
    const t = p.lastTest;
    let test = '<span class="muted">未测试</span>';
    if (t) {
      test = t.ok
        ? `<span class="mono">${esc(t.exitIp)}</span> ${esc([t.country, t.region, t.city].filter(Boolean).join(' '))}<br><span class="muted small">${t.connectMs + t.handshakeMs} ms 握手 · ${t.requestMs} ms 请求 · ${fmtTime(t.at)}</span>`
        : `<span class="error small">${esc(t.error)}</span>`;
    }
    return `<tr data-id="${esc(p.id)}">
      <td><div class="ops"><button class="btn sm" data-act="up" ${i === 0 ? 'disabled' : ''} title="上移">↑</button><button class="btn sm" data-act="down" ${i === ps.length - 1 ? 'disabled' : ''} title="下移">↓</button><span class="muted">${i + 1}</span></div></td>
      <td>${esc(p.name)}</td>
      <td class="mono">${esc(p.host)}:${p.port}</td>
      <td>${p.username ? esc(p.username) + (p.hasPassword ? ' / ******' : '') : '<span class="muted">无</span>'}</td>
      <td>${udpBadge(p)}</td>
      <td>${test}</td>
      <td><label class="switch"><input type="checkbox" data-act="toggle" ${p.enabled ? 'checked' : ''}><span></span></label></td>
      <td><div class="ops"><button class="btn sm" data-act="test">测试</button><button class="btn sm" data-act="edit">编辑</button><button class="btn sm danger" data-act="del">删除</button></div></td>
    </tr>`;
  }).join('');
  const sel = $('#policy-form select[name=activeProxyId]');
  sel.innerHTML = '<option value="">（请选择）</option>' + ps.filter(p => p.enabled).map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
  sel.value = ui.state.policy.activeProxyId || '';
}

function proxyPatch(p, overrides = {}) {
  return Object.assign({ name: p.name, host: p.host, port: p.port, username: p.username || '', password: null, enabled: p.enabled }, overrides);
}

$('#proxy-table').addEventListener('click', async e => {
  const btn = e.target.closest('[data-act]');
  if (!btn || btn.dataset.act === 'toggle') return;
  const id = btn.closest('tr').dataset.id;
  const ps = ui.state.proxies;
  const idx = ps.findIndex(p => p.id === id);
  const p = ps[idx];
  try {
    switch (btn.dataset.act) {
      case 'up':
      case 'down': {
        const ids = ps.map(x => x.id);
        const j = btn.dataset.act === 'up' ? idx - 1 : idx + 1;
        [ids[idx], ids[j]] = [ids[j], ids[idx]];
        await api('POST', '/api/proxies/reorder', { ids });
        break;
      }
      case 'test': {
        btn.disabled = true;
        btn.textContent = '测试中…';
        const r = await api('POST', `/api/proxies/${encodeURIComponent(id)}/test`, {});
        showTest(p, r);
        break;
      }
      case 'edit':
        openProxyDialog(p);
        return;
      case 'del':
        if (!confirm(`删除代理“${p.name}”？`)) return;
        await api('DELETE', `/api/proxies/${encodeURIComponent(id)}`);
        break;
    }
    await refreshAll();
  } catch (err) {
    toast(err.message, true);
    await refreshAll();
  }
});

$('#proxy-table').addEventListener('change', async e => {
  if (e.target.dataset.act !== 'toggle') return;
  const id = e.target.closest('tr').dataset.id;
  const p = ui.state.proxies.find(x => x.id === id);
  try {
    await api('PUT', `/api/proxies/${encodeURIComponent(id)}`, proxyPatch(p, { enabled: e.target.checked }));
  } catch (err) { toast(err.message, true); }
  await refreshAll();
});

function showTest(p, r) {
  const rows = [
    ['代理', p.name],
    ['结果', r.ok ? '可用' : '失败'],
    ['错误', r.error || ''],
    ['TCP 连接', `${r.connectMs} ms`],
    ['SOCKS5 握手', `${r.handshakeMs} ms`],
    ['HTTP 请求', `${r.requestMs} ms`],
    ['出口 IP', r.exitIp || '-'],
    ['位置', [r.country, r.region, r.city].filter(Boolean).join(' ') || '-'],
    ['运营商', r.isp || '-'],
    ['UDP', ({ yes: '支持', no: '不支持', unknown: '未知' })[r.udp] || r.udp],
    ['UDP 出口 IP', r.udpMappedIp || '-'],
    ['UDP 中继地址', r.relayAddress || '-'],
    ['说明', r.udpDetail || ''],
  ].filter(([, v]) => v !== '');
  $('#test-result').innerHTML = rows.map(([k, v]) => `<span>${esc(k)}</span><span>${esc(v)}</span>`).join('');
  $('#dlg-test').showModal();
}
$('#btn-test-close').addEventListener('click', () => $('#dlg-test').close());

function openProxyDialog(p) {
  const f = $('#proxy-form');
  ui.editingId = p ? p.id : null;
  $('#proxy-dlg-title').textContent = p ? '编辑代理' : '添加代理';
  f.name.value = p ? p.name : '';
  f.host.value = p ? p.host : '';
  f.port.value = p ? p.port : 1080;
  f.username.value = p ? (p.username || '') : '';
  f.password.value = '';
  f.password.placeholder = p && p.hasPassword ? '留空表示不修改' : '';
  f.enabled.checked = p ? p.enabled : true;
  $('[data-error]', f).textContent = '';
  $('#dlg-proxy').showModal();
}
$('#btn-add-proxy').addEventListener('click', () => openProxyDialog(null));

$('#proxy-form').addEventListener('submit', async e => {
  if (e.submitter && e.submitter.value === 'cancel') return;
  e.preventDefault();
  const f = e.target;
  const body = {
    name: f.name.value.trim(), host: f.host.value.trim(), port: Number(f.port.value),
    username: f.username.value, password: f.password.value === '' && ui.editingId ? null : f.password.value,
    enabled: f.enabled.checked,
  };
  try {
    if (ui.editingId) await api('PUT', `/api/proxies/${encodeURIComponent(ui.editingId)}`, body);
    else await api('POST', '/api/proxies', body);
    $('#dlg-proxy').close();
    await refreshAll();
  } catch (err) { $('[data-error]', f).textContent = err.message; }
});

$('#btn-import').addEventListener('click', () => {
  $('#import-form').text.value = '';
  $('[data-error]', $('#import-form')).textContent = '';
  $('#dlg-import').showModal();
});

$('#import-form').addEventListener('submit', async e => {
  if (e.submitter && e.submitter.value === 'cancel') return;
  e.preventDefault();
  const f = e.target;
  try {
    const r = await api('POST', '/api/proxies/import', { text: f.text.value });
    const errs = (r.errors || []).map(x => `${x.line ? '第 ' + x.line + ' 行' : x.text}：${x.error}`);
    if (errs.length) {
      $('[data-error]', f).textContent = `已导入 ${r.added} 个。\n` + errs.join('\n');
    } else {
      $('#dlg-import').close();
      toast(`已导入 ${r.added} 个代理`);
    }
    await refreshAll();
  } catch (err) { $('[data-error]', f).textContent = err.message; }
});

// ---------------- 出口策略 ----------------
function fillPolicy() {
  const f = $('#policy-form');
  const p = ui.state.policy;
  $$('input[name=mode]', f).forEach(r => { r.checked = r.value === p.mode; });
  f.killSwitch.checked = p.killSwitch;
  f.blockIpv6.checked = p.blockIpv6;
  f.failback.checked = p.failback;
  f.udpMode.value = p.udpMode;
  f.healthIntervalSec.value = p.healthIntervalSec;
  f.failThreshold.value = p.failThreshold;
  f.recoverThreshold.value = p.recoverThreshold;
  syncModeFields();
}
function syncModeFields() {
  const fixed = $('#policy-form input[name=mode][value=fixed]').checked;
  $('#active-wrap').classList.toggle('hidden', !fixed);
}
$$('#policy-form input[name=mode]').forEach(r => r.addEventListener('change', syncModeFields));

$('#policy-form').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  const body = {
    mode: $('input[name=mode]:checked', f).value,
    activeProxyId: f.activeProxyId.value,
    killSwitch: f.killSwitch.checked,
    udpMode: f.udpMode.value,
    blockIpv6: f.blockIpv6.checked,
    healthIntervalSec: Number(f.healthIntervalSec.value),
    failThreshold: Number(f.failThreshold.value),
    recoverThreshold: Number(f.recoverThreshold.value),
    failback: f.failback.checked,
  };
  if (!body.killSwitch && !confirm('关闭 kill switch 后，代理全部不可用时会回落到 ECS 自身 IP 出网，确定吗？')) return;
  try {
    await api('PUT', '/api/policy', body);
    $('[data-error]', f).textContent = '';
    toast('已保存，点击“应用更改”生效');
    await refreshAll();
  } catch (err) { $('[data-error]', f).textContent = err.message; }
});

// ---------------- 绕过规则 ----------------
const lines = s => s.split(/[\n,]/).map(x => x.trim()).filter(Boolean);
const ports = s => lines(s).map(Number);

function fillBypass() {
  const f = $('#bypass-form');
  const b = ui.state.bypass;
  f.cidrs.value = b.cidrs.join('\n');
  f.domains.value = b.domains.join('\n');
  f.tcpPorts.value = b.tcpPorts.join(',');
  f.udpPorts.value = b.udpPorts.join(',');
  f.mgmtPorts.value = b.mgmtPorts.join(',');
  f.directGroup.value = b.directGroup;
}

$('#bypass-form').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  const body = {
    cidrs: lines(f.cidrs.value), domains: lines(f.domains.value),
    tcpPorts: ports(f.tcpPorts.value), udpPorts: ports(f.udpPorts.value), mgmtPorts: ports(f.mgmtPorts.value),
    directGroup: f.directGroup.value.trim(),
  };
  if (body.tcpPorts.concat(body.udpPorts, body.mgmtPorts).some(isNaN)) {
    $('[data-error]', f).textContent = '端口必须是数字';
    return;
  }
  try {
    await api('PUT', '/api/bypass', body);
    $('[data-error]', f).textContent = '';
    toast('已保存，点击“应用更改”生效');
    await refreshAll();
    loadPreview();
  } catch (err) { $('[data-error]', f).textContent = err.message; }
});

// ---------------- 设置 ----------------
function fillSettings() {
  const f = $('#settings-form');
  const s = ui.state.settings;
  for (const k of ['listen', 'gostBin', 'redirPort', 'tproxyPort', 'apiPort', 'metricsPort', 'healthUrl', 'stunServer']) f[k].value = s[k];
  f.echoUrls.value = (s.echoUrls || []).join('\n');
}

$('#settings-form').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  const body = {
    listen: f.listen.value, gostBin: f.gostBin.value,
    redirPort: Number(f.redirPort.value), tproxyPort: Number(f.tproxyPort.value),
    apiPort: Number(f.apiPort.value), metricsPort: Number(f.metricsPort.value),
    healthUrl: f.healthUrl.value, echoUrls: lines(f.echoUrls.value), stunServer: f.stunServer.value,
  };
  try {
    await api('PUT', '/api/settings', body);
    $('[data-error]', f).textContent = '';
    toast('已保存。端口类设置需“应用更改”，监听地址需重启服务后生效');
    await refreshAll();
  } catch (err) { $('[data-error]', f).textContent = err.message; }
});

$('#password-form').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  try {
    await api('POST', '/api/password', { old: f.old.value, new: f.new.value });
    f.reset();
    toast('密码已修改，请重新登录');
    showLogin();
  } catch (err) { $('[data-error]', f).textContent = err.message; }
});

async function loadPreview() {
  try {
    const p = await api('GET', '/api/preview');
    $('#pv-backend').textContent = p.backend || '-';
    $('#pv-rules').textContent = p.rules;
    $('#pv-gost').textContent = JSON.stringify(p.gostConfig, null, 2);
    $('#builtin-bypass').innerHTML = (p.bypass || []).map(c => `<span>${esc(c)}</span>`).join('');
    $('#pv-dry').classList.toggle('hidden', !(p.dryRunLog && p.dryRunLog.length));
    $('#pv-drylog').textContent = (p.dryRunLog || []).join('\n');
  } catch (err) { toast(err.message, true); }
}
$('#btn-preview').addEventListener('click', loadPreview);

// ---------------- 日志 ----------------
async function loadLogs() {
  try {
    const r = await api('GET', '/api/logs');
    $('#audit-table tbody').innerHTML = (r.audit || []).map(e => `<tr>
      <td class="small">${fmtTime(e.time)}</td><td>${esc({ admin: '管理员', system: '系统', health: '健康检查' }[e.actor] || e.actor)}</td>
      <td>${e.success ? '' : '<span class="pill bad">失败</span> '}${esc(e.action)}</td><td class="small">${esc(e.detail)}</td></tr>`).join('')
      || '<tr><td colspan="4" class="muted">暂无记录</td></tr>';
    $('#engine-log').textContent = (r.engine || []).join('\n') || '（gost 未运行或暂无日志）';
  } catch (err) { toast(err.message, true); }
}
$('#btn-refresh-logs').addEventListener('click', loadLogs);

// ---------------- 启动 ----------------
(async () => {
  try {
    await api('GET', '/api/session');
    await showApp();
  } catch (_) {
    showLogin();
  }
})();
