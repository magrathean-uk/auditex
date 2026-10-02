/* Auditex run explorer. Vanilla JavaScript, no network access, no HTML parsing of
   data: every string from the run is set with textContent or setAttribute.
   Icons are path data from Lucide. Licence notices follow.

   Lucide: ISC License. Copyright (c) 2026 Lucide Icons and Contributors.
   Permission to use, copy, modify, and/or distribute this software for any purpose with or
   without fee is hereby granted, provided that the above copyright notice and this permission
   notice appear in all copies. THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
   WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
   FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
   CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
   WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
   CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

   Icons derived from Feather (check, chevron-down, arrow-right, clock, key, lock, log-in, moon,
   search, x and others): The MIT License. Copyright (c) 2013-present Cole Bemis.
   Permission is hereby granted, free of charge, to any person obtaining a copy of this software
   and associated documentation files (the "Software"), to deal in the Software without
   restriction, including without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions: The above copyright
   notice and this permission notice shall be included in all copies or substantial portions of
   the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
   PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
   LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.

   Full texts ship with Auditex: explorer_assets/LICENSE-lucide.txt, explorer_assets/fonts/OFL.txt. */
(function () {
  'use strict';

  var RAW = JSON.parse(document.getElementById('data').textContent);
  var SVGNS = document.getElementById('ax-svgns').namespaceURI;
  var DOC = document.documentElement;
  var ROOT = document.getElementById('ax-root');
  var MAIN = document.getElementById('ax-main');
  var RUNS = RAW.runs || [];
  var SEVS = ['critical', 'high', 'medium', 'low', 'info'];
  var SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', clean: 'Clean' };
  var SEV_LEVEL = { critical: 4, high: 3, medium: 2, low: 1, info: 0, clean: 0 };
  var VIEWS = ['overview', 'findings', 'paths', 'detection', 'baselines', 'access', 'compare'];
  var FW_ORDER = ['cis_m365_v7', 'cisa_scuba', 'ms_secure_score', 'ms_zero_trust', 'mcsb', 'nist_800_53', 'iso_27001', 'mitre_attack', 'soc2', 'nis2', 'dora', 'google_workspace_baseline', 'cis_m365_v3'];
  var FW_LABEL = { cis_m365_v7: 'CIS M365 v7', cisa_scuba: 'CISA SCuBA', ms_secure_score: 'Secure Score', ms_zero_trust: 'Zero Trust', mcsb: 'MCSB', nist_800_53: 'NIST 800-53', iso_27001: 'ISO 27001', mitre_attack: 'MITRE ATT&CK', soc2: 'SOC 2', nis2: 'NIS2', dora: 'DORA', google_workspace_baseline: 'Google Workspace', cis_m365_v3: 'CIS M365 v3 (legacy)' };
  var NODE_LABEL = { user: 'User', guest: 'Guest', group: 'Group', service_principal: 'Enterprise app', application: 'Application', directory_role: 'Directory role', graph_permission: 'Graph permission', entry: 'Entry', principal: 'Principal' };
  var NODE_ICON = { user: 'user', guest: 'guest', group: 'users', service_principal: 'app-window', application: 'app-window', directory_role: 'shield', graph_permission: 'key-round', entry: 'log-in', principal: 'users' };
  var GRAPH_COLLECTORS = ['identity', 'app_consent', 'app_credentials', 'auth_methods'];

  var ICONS = {
    'shield-check': [['path', { d: 'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z' }], ['path', { d: 'm9 12 2 2 4-4' }]],
    'eye-off': [['path', { d: 'M10.7 5.1A10.7 10.7 0 0 1 22 12a10.8 10.8 0 0 1-1.4 2.5' }], ['path', { d: 'M14.1 14.2a3 3 0 0 1-4.2-4.2' }], ['path', { d: 'M17.5 17.5A10.8 10.8 0 0 1 2 12a10.8 10.8 0 0 1 4.5-5.2' }], ['path', { d: 'm2 2 20 20' }]],
    'file-check': [['path', { d: 'M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z' }], ['path', { d: 'M14 2v4a2 2 0 0 0 2 2h4' }], ['path', { d: 'm9 15 2 2 4-4' }]],
    'file': [['path', { d: 'M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z' }], ['path', { d: 'M14 2v4a2 2 0 0 0 2 2h4' }]],
    check: [['path', { d: 'M20 6 9 17l-5-5' }]],
    x: [['path', { d: 'M18 6 6 18M6 6l12 12' }]],
    lock: [['rect', { width: '18', height: '11', x: '3', y: '11' }], ['path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }]],
    sun: [['circle', { cx: '12', cy: '12', r: '4' }], ['path', { d: 'M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4' }]],
    moon: [['path', { d: 'M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z' }]],
    printer: [['path', { d: 'M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2' }], ['path', { d: 'M6 9V3h12v6' }], ['rect', { x: '6', y: '14', width: '12', height: '8' }]],
    search: [['circle', { cx: '11', cy: '11', r: '8' }], ['path', { d: 'm21 21-4.3-4.3' }]],
    'chevron-down': [['path', { d: 'm6 9 6 6 6-6' }]],
    'arrow-right': [['path', { d: 'M5 12h14M12 5l7 7-7 7' }]],
    copy: [['rect', { width: '14', height: '14', x: '8', y: '8' }], ['path', { d: 'M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2' }]],
    user: [['path', { d: 'M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2' }], ['circle', { cx: '12', cy: '7', r: '4' }]],
    guest: [['path', { d: 'M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2' }], ['circle', { cx: '12', cy: '7', r: '4', 'stroke-dasharray': '3 2' }]],
    users: [['path', { d: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2' }], ['circle', { cx: '9', cy: '7', r: '4' }], ['path', { d: 'M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75' }]],
    'app-window': [['rect', { x: '2', y: '4', width: '20', height: '16' }], ['path', { d: 'M2 8h20M6 4v4M10 4v4' }]],
    shield: [['path', { d: 'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z' }]],
    'key-round': [['path', { d: 'M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z' }], ['circle', { cx: '16.5', cy: '7.5', r: '.5' }]],
    'log-in': [['path', { d: 'M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4' }], ['path', { d: 'm10 17 5-5-5-5M15 12H3' }]],
    scissors: [['circle', { cx: '6', cy: '6', r: '3' }], ['path', { d: 'M8.12 8.12 12 12M20 4 8.12 15.88' }], ['circle', { cx: '6', cy: '18', r: '3' }], ['path', { d: 'M14.8 14.8 20 20' }]],
    'circle-help': [['circle', { cx: '12', cy: '12', r: '9' }], ['path', { d: 'M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3' }], ['path', { d: 'M12 17h.01' }]],
    'flask-conical': [['path', { d: 'M10 2v7.5a2 2 0 0 1-.2.9L4.7 20.6a1 1 0 0 0 .9 1.4h12.8a1 1 0 0 0 .9-1.4l-5.1-10.2a2 2 0 0 1-.2-.9V2' }], ['path', { d: 'M8.5 2h7M7 16h10' }]],
    clock: [['circle', { cx: '12', cy: '12', r: '9', 'stroke-dasharray': '4 2' }], ['path', { d: 'M12 7v5l3 2' }]],
    half: [['circle', { cx: '12', cy: '12', r: '8' }], ['path', { d: 'M12 4a8 8 0 0 0 0 16z', fill: 'currentColor' }]],
    dash: [['path', { d: 'M5 12h14' }]],
    ne: [['path', { d: 'M5 9h14M5 15h14M18 4 6 20' }]],
    arrowhead: [['path', { d: 'M1 1l5 4-5 4' }]]
  };

  var STATUS = {
    pass: ['check', 'ok', 'Pass'], on: ['check', 'ok', 'On'], verified: ['check', 'ok', 'Verified'], agree: ['check', 'ok', 'Agrees'], supported: ['check', 'ok', 'Evidence'], no: ['check', 'ok', 'No'],
    fail: ['x', 'bad', 'Fail'], off: ['x', 'bad', 'Off'], yes: ['x', 'bad', 'Yes'], added: ['x', 'bad', 'New'],
    accepted: ['half', 'warn', 'Accepted risk'], partial: ['half', 'warn', 'Partial proof'],
    disagree: ['ne', 'warn', 'Disagrees'],
    not_assessed: ['circle-help', 'muted', 'Not assessed', true], not_verified: ['circle-help', 'muted', 'Not verified', true], unknown: ['circle-help', 'muted', 'Not verified', true],
    not_selected: ['dash', 'muted', 'Not selected', true], open: ['dash', 'ink', 'Open']
  };

  var media = function (q) { try { return window.matchMedia && window.matchMedia(q).matches; } catch (e) { return false; } };
  var params = (function () { try { return new URLSearchParams(window.location.search); } catch (e) { return null; } })();
  var param = function (k) { return params ? params.get(k) : null; };

  var startRun = Number(param('run'));
  var S = {
    run: Number.isInteger(startRun) && startRun >= 0 && startRun < RUNS.length && param('run') !== null ? startRun : (RAW.default_run || 0),
    view: VIEWS.indexOf(param('view')) >= 0 ? param('view') : 'overview',
    theme: param('theme') === 'dark' || param('theme') === 'light' ? param('theme') : (media('(prefers-color-scheme: dark)') ? 'dark' : 'light'),
    q: '', sev: [], area: '', fw: '', status: '', limit: 20, expanded: {}, openPaths: {}, hop: {}, foot: '', fwOpen: {},
    printing: false, narrow: false, tableWide: false, compact: false, justOpened: null
  };

  // ------------------------------------------------------------------ DOM helpers
  function add(el, kids) {
    for (var i = 0; i < kids.length; i++) {
      var c = kids[i];
      if (c === null || c === undefined || c === false) continue;
      if (Array.isArray(c)) { add(el, c); continue; }
      el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  function setProps(el, p) {
    if (!p) return el;
    Object.keys(p).forEach(function (k) {
      var v = p[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') el.setAttribute('class', v);
      else if (k === 'text') el.textContent = String(v);
      else if (k === 'style') el.style.cssText = v;
      else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    return el;
  }
  function h(tag, p) { return add(setProps(document.createElement(tag), p), Array.prototype.slice.call(arguments, 2)); }
  function s(tag, p) { return add(setProps(document.createElementNS(SVGNS, tag), p), Array.prototype.slice.call(arguments, 2)); }
  function icon(name, size, extra) {
    var o = extra || {};
    var el = s('svg', { 'aria-hidden': 'true', focusable: 'false', width: String(size || 16), height: String(size || 16), viewBox: name === 'arrowhead' ? '0 0 10 10' : '0 0 24 24', fill: 'none', stroke: o.stroke || 'currentColor', 'stroke-width': String(o.sw || 1.5), 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'class': o.cls || null, style: o.style || null });
    (ICONS[name] || []).forEach(function (part) { el.appendChild(s(part[0], part[1])); });
    return el;
  }
  function corners() { return ['tl', 'tr', 'bl', 'br'].map(function (c) { return h('i', { 'class': 'corner ' + c, 'aria-hidden': 'true' }); }); }
  function bp(tag, cls, p) {
    var el = h(tag, Object.assign({}, p || {}, { 'class': 'blueprint' + (cls ? ' ' + cls : '') }));
    add(el, corners());
    return add(el, Array.prototype.slice.call(arguments, 3));
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function fmtNum(v) { return v === null || v === undefined || v === '' ? '—' : String(v); }
  function pct(n, d) { return d ? (100 * n / d).toFixed(2) + '%' : '0%'; }
  function upper(sv) { return String(sv || '').toUpperCase(); }

  // ------------------------------------------------------------------ components
  function sevBadge(sev, lg) {
    var key = SEV_LABEL[sev] ? sev : 'info';
    var lvl = SEV_LEVEL[key];
    var unit = lg ? 3 : 2;
    var bars = h('span', { 'class': 'bars', 'aria-hidden': 'true' });
    for (var i = 0; i < 4; i++) bars.appendChild(h('i', { 'class': i < lvl ? 'on' : null, style: 'height:' + ((i + 2) * unit) + 'px' }));
    return h('span', { 'class': 'ax-sev sev-' + key + (key === 'critical' ? ' filled' : '') + (lg ? ' lg' : '') }, bars, h('span', { text: SEV_LABEL[key] }));
  }
  function pill(status, label) {
    var m = STATUS[status] || STATUS.not_assessed;
    return h('span', { 'class': 'ax-pill pc-' + m[1] + (m[3] ? ' dashed' : '') }, icon(m[0], 13, { sw: 2 }), h('span', { text: label || m[2] }));
  }
  function fwTag(label, code) { return h('span', { 'class': 'ax-fwtag' }, h('span', { 'class': 'k', text: label }), h('span', { 'class': 'v', text: code })); }
  function statTile(label, value, sub, tone, unit) {
    return bp('div', 'ax-tile', null,
      h('span', { 'class': 'lab', text: label }),
      h('span', { 'class': 'val' }, h('span', { 'class': 'v' + (tone ? ' ' + tone : ''), text: value }), unit ? h('span', { 'class': 'u', text: unit }) : null),
      sub ? h('span', { 'class': 'sub', text: sub }) : null);
  }
  function meter(verified, total, okLabel, gapLabel) {
    var gap = Math.max(0, total - verified);
    var bar = h('div', { 'class': 'ax-meter-bar', role: 'img', 'aria-label': verified + ' of ' + total + ' ' + okLabel });
    if (!total) bar.appendChild(h('span', { 'class': 'gap', style: 'flex:1' }));
    else if (total <= 40) for (var i = 0; i < total; i++) bar.appendChild(h('span', { 'class': i < verified ? null : 'gap', style: 'flex:1' }));
    else { if (verified) bar.appendChild(h('span', { style: 'flex:' + verified })); if (gap) bar.appendChild(h('span', { 'class': 'gap', style: 'flex:' + gap })); }
    return h('div', { 'class': 'ax-meter' }, bar,
      h('div', { 'class': 'ax-meter-legend' },
        h('span', null, h('span', { 'class': 'ax-sw', 'aria-hidden': 'true' }), h('strong', { text: String(verified) }), ' ' + okLabel),
        gap ? h('span', null, h('span', { 'class': 'ax-sw gap', 'aria-hidden': 'true' }), h('strong', { text: String(gap) }), ' ' + gapLabel) : null));
  }
  function vhead(id, kicker, title, sub) {
    return h('div', { 'class': 'ax-vhead' }, h('span', { 'class': 'ax-kicker', text: kicker }), h('h1', { id: id, 'class': 'ax-h1', text: title }), sub ? h('p', { 'class': 'ax-sub', text: sub }) : null);
  }
  function emptyFrame(pillStatus, pillLabel, title, text, extra) {
    return bp('div', 'dashed ax-empty', null, pillStatus ? pill(pillStatus, pillLabel) : null, h('strong', { text: title }), text ? h('p', { text: text }) : null, extra || null);
  }
  function fmtValue(v) { return v === null ? 'null' : typeof v === 'object' ? JSON.stringify(v) : String(v); }
  function copyText(text, done) {
    var fallback = function () {
      var ta = h('textarea', { 'aria-hidden': 'true', style: 'position:fixed;left:-9999px;top:0' });
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (e) { /* clipboard unavailable */ }
      document.body.removeChild(ta); done();
    };
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback);
      else fallback();
    } catch (e) { fallback(); }
  }
  function evidenceBlock(artifact, key, collector, heading) {
    var record = (R().evidence || {})[artifact + '#' + key];
    var label = h('span', { 'aria-live': 'polite', text: 'Copy record' });
    var timer = null;
    var btn = h('button', { type: 'button', 'class': 'btn btn-secondary ax-copy', 'data-noprint': '', 'aria-label': 'Copy evidence record JSON for ' + key, disabled: record ? null : true }, icon('copy', 14), label);
    btn.addEventListener('click', function () {
      copyText(JSON.stringify({ source_file: artifact, record_key: key, record: record }, null, 2), function () {
        label.textContent = 'Copied';
        clearTimeout(timer); timer = setTimeout(function () { label.textContent = 'Copy record'; }, 1600);
      });
    });
    var table = h('div', { role: 'table', 'aria-label': 'Evidence record ' + key, 'class': 'ax-col' });
    if (record && typeof record === 'object') {
      Object.keys(record).forEach(function (k) {
        table.appendChild(h('div', { role: 'row', 'class': 'ax-ev-row' }, h('span', { role: 'rowheader', text: k }), h('span', { role: 'cell', text: fmtValue(record[k]) })));
      });
    } else {
      table.appendChild(h('div', { role: 'row', 'class': 'ax-ev-row' }, h('span', { role: 'rowheader', text: 'record' }), h('span', { role: 'cell', text: 'Not embedded in this page. Open ' + artifact + ' in the run folder.' })));
    }
    return bp('figure', 'ax-ev', { 'data-avoid-break': '' },
      h('figcaption', null,
        h('span', { 'class': 'ax-col', style: 'gap:3px;min-width:0;flex:1 1 220px' },
          h('span', { 'class': 'ax-ev-k' }, icon('file-check', 13), h('span', { text: heading || ('Evidence record · ' + (collector || '')) })),
          h('span', { 'class': 'ax-mono ax-break', style: 'font-size:12px', text: artifact }),
          h('span', { 'class': 'ax-mono ax-break ax-muted', style: 'font-size:11px', text: 'record key · ' + key })),
        btn),
      table);
  }

  // ------------------------------------------------------------------ run model
  function fwRank(k) { var i = FW_ORDER.indexOf(k); return i < 0 ? 999 : i; }
  var cache = {};
  function R() { return RUNS[S.run] || {}; }
  function M() {
    if (cache[S.run]) return cache[S.run];
    var r = R();
    var findings = r.findings || [];
    var fwKeys = {};
    findings.forEach(function (f) {
      var tags = [];
      var fm = f.framework_mappings || {};
      Object.keys(fm).forEach(function (k) { (fm[k] || []).forEach(function (id) { tags.push({ fw: k, label: FW_LABEL[k] || k, id: String(id) }); fwKeys[k] = true; }); });
      tags.sort(function (a, b) { return fwRank(a.fw) - fwRank(b.fw) || (a.fw < b.fw ? -1 : a.fw > b.fw ? 1 : 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0); });
      f._tags = tags;
      f._hay = [f.title, f.object, f.rule_id, f.area_label, f.n, (f.affected_objects || []).join(' '), tags.map(function (t) { return t.id; }).join(' ')].join(' ').toLowerCase();
    });
    var areaCounts = {};
    findings.forEach(function (f) { areaCounts[f.area] = (areaCounts[f.area] || 0) + 1; });
    var areaOrder = Object.keys(areaCounts).sort(function (a, b) { return areaCounts[b] - areaCounts[a] || (a < b ? -1 : 1); });
    var labelOf = {}; findings.forEach(function (f) { labelOf[f.area] = f.area_label; });
    var fws = FW_ORDER.filter(function (k) { return fwKeys[k]; }).concat(Object.keys(fwKeys).filter(function (k) { return FW_ORDER.indexOf(k) < 0; }).sort());
    var m = {
      findings: findings,
      areas: areaOrder.map(function (k) { return { key: k, label: labelOf[k], count: areaCounts[k] }; }),
      fwOptions: fws.map(function (k) { return { value: k, label: FW_LABEL[k] || k }; }),
      fwKeys: fwKeys,
      supported: findings.filter(function (f) { return f.proof === 'supported'; }).length,
      paths: r.attack_paths || []
    };
    cache[S.run] = m;
    return m;
  }

  // ------------------------------------------------------------------ chrome
  function renderChrome() {
    var r = R(), m = M(), meta = r.meta || {}, cov = r.coverage || { verified: 0, all: 0 };
    document.getElementById('ax-tenant-name').textContent = meta.display_name || r.tenant || 'Run';
    var sub = [meta.domain, meta.users !== null && meta.users !== undefined ? plural(meta.users, 'user') : null].filter(Boolean).join(' · ');
    document.getElementById('ax-tenant-sub').textContent = sub;

    var sel = clear(document.getElementById('ax-run'));
    RUNS.forEach(function (run, i) {
      var risk = run.risk || {};
      sel.appendChild(h('option', { value: String(i), text: run.collected_label + ' · ' + upper(risk.grade) + ' ' + fmtNum(risk.score) }));
    });
    sel.value = String(S.run);
    sel.disabled = RUNS.length < 2;

    var ro = clear(document.getElementById('ax-ro-chip'));
    var wrote = (r.data_handling || {}).write_actions === true;
    add(ro, [icon(wrote ? 'x' : 'lock', 14), wrote ? 'Writes recorded' : 'Read-only']);

    var tb = clear(document.getElementById('ax-theme'));
    tb.setAttribute('aria-label', S.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    tb.appendChild(icon(S.theme === 'dark' ? 'sun' : 'moon', 16));
    var pb = clear(document.getElementById('ax-print'));
    add(pb, [icon('printer', 15), 'Handoff PDF']);

    var dh = r.data_handling || {}, pa = dh.provider_assertions || {};
    var content = dh.content_reads !== undefined && dh.content_reads !== null ? dh.content_reads : pa.body_or_file_content_reads;
    var g = clear(document.getElementById('ax-guarantees'));
    var item = function (ic, color, text, extra) { return h('li', null, icon(ic, 15, Object.assign({ stroke: color }, extra || {})), text); };
    g.appendChild(dh.write_actions === false ? item('shield-check', 'var(--ok)', 'Wrote nothing to the tenant') : dh.write_actions ? item('x', 'var(--sev-critical)', 'Wrote to the tenant') : item('circle-help', 'var(--color-neutral-700)', 'Write activity not recorded'));
    g.appendChild(content === false ? item('eye-off', 'var(--ok)', 'Read no mail bodies or file contents') : content ? item('x', 'var(--sev-critical)', 'Read mail bodies or file contents') : item('circle-help', 'var(--color-neutral-700)', 'Content reads not recorded'));
    g.appendChild(item('file-check', 'var(--color-accent-700)', m.findings.length ? m.supported + ' of ' + m.findings.length + ' findings cite a full evidence record' : 'No findings to evidence'));
    g.appendChild(r.contract_valid ? item('check', 'var(--ok)', 'Bundle contract valid') : item('x', 'var(--sev-critical)', 'Bundle contract invalid'));
    g.appendChild(item('clock', 'var(--color-accent-700)', cov.verified + ' of ' + cov.all + ' collectors verified'));

    var bw = clear(document.getElementById('ax-banners'));
    (r.banners || []).forEach(function (b) {
      bw.appendChild(h('div', { 'class': 'ax-banner-wrap' },
        bp('div', 'ax-banner', { role: 'status' },
          h('span', { 'class': 'ax-banner-stripe', 'aria-hidden': 'true' }),
          h('div', { 'class': 'ax-banner-body' },
            icon(b.kind === 'synthetic' ? 'flask-conical' : 'circle-help', 20, { stroke: 'var(--color-accent-700)' }),
            h('div', { 'class': 'ax-banner-text' }, h('strong', { 'class': 'ax-banner-title', text: b.title }), h('span', { 'class': 'ax-banner-copy', text: b.text }))))));
    });

    var det = r.detection;
    var counts = {
      overview: '', findings: String(m.findings.length), paths: String(m.paths.length),
      detection: det && scored(det) ? String(det.score) : '—',
      baselines: r.baselines && r.baselines.frameworks && r.baselines.frameworks.length ? String(r.baselines.frameworks.length) : '—',
      access: cov.verified + '/' + cov.all, compare: RAW.compare ? RUNS.length + ' runs' : '—'
    };
    Array.prototype.forEach.call(document.querySelectorAll('#ax-nav button[data-view]'), function (b) {
      var v = b.getAttribute('data-view');
      b.querySelector('.ax-c').textContent = counts[v];
      if (v === S.view) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    var dl = clear(document.getElementById('ax-nav-meta'));
    [['Run', r.run_name, true], ['Collected', r.collected_label], ['Mode', r.mode_label], ['Platform', r.platform_label + ' · ' + (RAW.generator || 'Auditex')]].forEach(function (row) {
      dl.appendChild(h('div', null, h('dt', { text: row[0] }), h('dd', { 'class': row[2] ? 'mono' : null, text: row[1] || '—' })));
    });
    document.getElementById('ax-footer-version').textContent = (RAW.generator || 'Auditex') + ' · self-contained file, no network requests';
  }
  function scored(det) { return det && det.score !== null && det.score !== undefined && det.counts && det.counts.unknown * 2 <= (det.signals || []).length; }

  // ------------------------------------------------------------------ navigation
  function go(view, extra) {
    if (extra) Object.keys(extra).forEach(function (k) { S[k] = extra[k]; });
    S.view = view;
    renderAll(true);
    try { window.scrollTo(0, 0); } catch (e) { /* ignore */ }
    try { MAIN.focus({ preventScroll: true }); } catch (e) { MAIN.focus(); }
  }
  function clearFilters() { S.q = ''; S.sev = []; S.area = ''; S.fw = ''; S.status = ''; S.limit = 20; }

  // ------------------------------------------------------------------ overview
  function viewOverview(sec) {
    var r = R(), m = M(), risk = r.risk || {}, cov = r.coverage || { verified: 0, all: 0 }, counts = r.counts || {};
    var bands = RAW.risk_bands || [];
    var score = Number(risk.score) || 0;
    var scale = h('div', { 'class': 'ax-scale', role: 'img', 'aria-label': 'Score ' + score + ' of 100 on the scale ' + bands.map(function (b) { return b.grade + ' ' + b.from + '–' + b.to; }).join(', ') });
    var bandRow = h('div', { 'class': 'ax-scale-bands' });
    var labRow = h('div', { 'class': 'ax-scale-labels', 'aria-hidden': 'true' });
    bands.forEach(function (b) {
      var w = (b.to - b.from) + '%';
      bandRow.appendChild(h('span', { style: 'width:' + w }));
      labRow.appendChild(h('span', { style: 'width:' + w, text: b.to - b.from >= 8 ? b.grade : '' }));
    });
    bandRow.appendChild(h('span', { 'class': 'mark', style: 'left:' + Math.min(99.5, score) + '%' }));
    add(scale, [bandRow, labRow]);
    var left = h('div', { 'class': 'cell' },
      h('span', { 'class': 'ax-kicker', text: 'Risk grade' }),
      h('div', { 'class': 'ax-row', style: 'gap:12px 18px' }, sevBadge(risk.grade, true),
        h('span', { 'class': 'ax-num' }, h('span', { style: 'font-size:56px', text: String(score) }), h('span', { 'class': 'ax-unit', style: 'font-size:22px', text: ' / 100' }))),
      scale,
      cov.verified < cov.all ? h('span', { 'class': 'ax-row', style: 'gap:8px;font-size:12.5px' }, pill('not_verified', 'Provisional'), 'Based on ' + cov.verified + ' of ' + cov.all + ' collectors') : null);
    var right = h('div', { 'class': 'cell', style: 'justify-content:center;gap:12px' },
      h('span', { 'class': 'ax-kicker', text: 'Verdict' }),
      h('p', { 'class': 'verdict', text: r.verdict || '' }),
      h('p', { style: 'font-size:15px', text: r.action || '' }),
      h('div', { 'class': 'ax-row', style: 'gap:8px' },
        h('button', { type: 'button', 'class': 'btn btn-primary', onclick: function () { go('findings'); } }, 'Review findings'),
        h('button', { type: 'button', 'class': 'btn btn-secondary', onclick: function () { go('paths'); } }, 'See attack paths')));
    var plate = bp('div', 'ax-plate', null, left, right);

    var total = m.findings.length;
    var segs = h('div', { 'class': 'ax-stack', role: 'img', 'aria-label': SEVS.filter(function (k) { return counts[k]; }).map(function (k) { return counts[k] + ' ' + SEV_LABEL[k]; }).join(', ') || 'No findings', style: 'height:12px' });
    SEVS.forEach(function (k) {
      if (!counts[k]) return;
      segs.appendChild(h('span', { style: 'width:' + pct(counts[k], total) + ';border-color:var(--sev-' + k + ');background:' + (k === 'info' ? 'transparent' : 'var(--sev-' + k + ')') }));
    });
    if (!total) segs.appendChild(h('span', { style: 'flex:1;border:1px dashed var(--color-divider)' }));
    var legend = h('ul', { 'class': 'ax-row', style: 'gap:4px 12px;font-size:12.5px' });
    SEVS.forEach(function (k) { legend.appendChild(h('li', null, h('strong', { style: 'font-weight:600', text: String(counts[k] || 0) }), ' ', h('span', { 'class': 'ax-muted', text: SEV_LABEL[k] }))); });
    var stats = h('div', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 240px), 1fr))' },
      bp('div', 'ax-stat', null, h('span', { 'class': 'ax-kicker', text: 'Open findings' }),
        h('span', { 'class': 'big' }, String(r.open_count || 0), r.accepted_count ? h('span', { 'class': 'u body', text: ' + ' + r.accepted_count + ' accepted' }) : null), segs, legend),
      bp('div', 'ax-stat', null, h('span', { 'class': 'ax-kicker', text: 'Findings with proof' }),
        h('span', { 'class': 'big' }, String(m.supported), h('span', { 'class': 'u', text: ' / ' + total })), meter(m.supported, total, 'cite a full record', 'partial proof')),
      bp('div', 'ax-stat', null, h('span', { 'class': 'ax-kicker', text: 'Collector coverage' }),
        h('span', { 'class': 'big' }, String(cov.verified), h('span', { 'class': 'u', text: ' / ' + cov.all })), meter(cov.verified, cov.all, 'verified', 'not verified or not selected')),
      bp('div', 'ax-stat', null, h('span', { 'class': 'ax-kicker', text: 'Bundle contract' }),
        h('span', { 'class': 'ax-row', style: 'gap:10px' }, h('span', { 'class': 'ax-num', style: 'font-size:34px;color:' + (r.contract_valid ? 'var(--ok)' : 'var(--sev-critical)'), text: r.contract_valid ? 'Valid' : 'Invalid' }), r.contract_valid ? pill('pass', 'Schema checks pass') : pill('fail', 'Schema checks fail')),
        h('span', { 'class': 'note', text: 'validation.json · every artifact checksummed in checksums.sha256' })));

    var open = m.findings.filter(function (f) { return f.status === 'open'; });
    var fix = open.slice().sort(function (a, b) { return SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity) || (a.proof === 'supported' ? 0 : 1) - (b.proof === 'supported' ? 0 : 1) || (a.n < b.n ? -1 : 1); }).slice(0, 5);
    var caveat = cov.verified < cov.all ? 'Only ' + cov.verified + ' of ' + cov.all + ' collectors ran.' : 'All ' + cov.all + ' collectors ran.';
    var fixSec = bp('section', '', { 'aria-labelledby': 'h-fixfirst', style: 'display:flex;flex-direction:column' },
      h('div', { style: 'padding:14px 16px 8px' }, h('h2', { id: 'h-fixfirst', 'class': 'ax-h2', text: 'Fix first' }), h('p', { 'class': 'ax-muted', style: 'font-size:13px', text: 'Highest severity, strongest evidence, open.' })));
    if (fix.length) {
      var ol = h('ol');
      fix.forEach(function (f, i) {
        ol.appendChild(h('li', { style: 'border-top:1px solid var(--color-divider)' },
          h('button', { type: 'button', 'class': 'ax-fix-row', onclick: function () { openFinding(f); } },
            h('span', { 'class': 'ax-mono ax-muted', style: 'font-size:12px;width:20px', text: String(i + 1).padStart(2, '0') }),
            h('span', { style: 'width:92px;display:flex' }, sevBadge(f.severity)),
            h('span', { 'class': 'ax-col', style: 'flex:1 1 220px;min-width:0' }, h('span', { style: 'font-weight:600;font-size:14.5px;line-height:1.3', text: f.title }), h('span', { 'class': 'ax-mono ax-muted ax-break', style: 'font-size:11.5px', text: f.object })),
            icon('arrow-right', 16, { style: 'color:var(--color-accent-700)' }))));
      });
      fixSec.appendChild(ol);
    } else {
      fixSec.appendChild(h('p', { style: 'padding:14px 16px;border-top:1px solid var(--color-divider);font-size:14px', text: 'Nothing to fix in what was checked. ' + caveat }));
    }
    var maxArea = Math.max.apply(null, [1].concat(m.areas.map(function (a) { return a.count; })));
    var areaSec = bp('section', '', { 'aria-labelledby': 'h-areas', style: 'display:flex;flex-direction:column;gap:4px;padding:14px 16px' },
      h('h2', { id: 'h-areas', 'class': 'ax-h2', style: 'margin:0 0 8px', text: 'Findings by area' }));
    m.areas.forEach(function (a) {
      areaSec.appendChild(h('div', { 'class': 'ax-area-row' }, h('span', { text: a.label }), h('span', { 'class': 'bar', 'aria-hidden': 'true', style: 'width:' + (100 * a.count / maxArea).toFixed(1) + '%' }), h('span', { 'class': 'ax-mono', style: 'font-size:12.5px;text-align:right', text: String(a.count) })));
    });
    (r.nv_areas || []).forEach(function (a) {
      areaSec.appendChild(h('div', { 'class': 'ax-area-row nv' }, h('span', { text: a.label }), h('span', { 'class': 'ax-row ax-muted', style: 'gap:8px;font-size:12px' }, pill('not_verified'), a.reason)));
    });
    if (!total) areaSec.appendChild(h('p', { 'class': 'ax-muted', style: 'font-size:14px', text: 'No findings in any checked area.' }));

    var meta = r.meta || {};
    var rows = [['Tenant', meta.display_name], ['Tenant ID', meta.tenant_id, 1], ['Run ID', r.run_name, 1], ['Collected', r.collected_label], ['Mode', r.mode_label], ['Platform', r.platform_label], ['Preset', r.preset || (r.plane ? 'none · ' + r.plane + ' plane' : ''), 1], ['Tool', RAW.generator]];
    var dl = h('dl', { 'class': 'ax-meta-grid' });
    rows.forEach(function (row) { dl.appendChild(h('div', null, h('dt', { text: row[0] }), h('dd', { 'class': row[2] ? 'ax-mono' : null, text: row[1] || '—' }))); });

    add(sec, [
      vhead('h-overview', 'Overview', 'Risk overview'),
      plate, stats,
      h('div', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 420px), 1fr))' }, fixSec, areaSec),
      h('section', { 'aria-labelledby': 'h-meta' }, h('h2', { id: 'h-meta', 'class': 'ax-h2', style: 'margin:0 0 10px', text: 'Run metadata' }), dl)
    ]);
    sec.className = 'ax-view gap-26';
  }

  function openFinding(f) {
    var idx = M().findings.indexOf(f);
    var ex = {}; ex[f.id] = true;
    clearFilters();
    go('findings', { expanded: ex, limit: Math.max(20, Math.ceil((idx + 1) / 20) * 20), justOpened: f.id });
  }

  // ------------------------------------------------------------------ findings
  function filtered() {
    var q = S.q.trim().toLowerCase();
    return M().findings.filter(function (f) {
      return (!S.sev.length || S.sev.indexOf(f.severity) >= 0) && (!S.area || f.area === S.area) &&
        (!S.fw || f._tags.some(function (t) { return t.fw === S.fw; })) && (!S.status || f.status === S.status) && (!q || f._hay.indexOf(q) >= 0);
    });
  }
  function findingCard(f) {
    var open = S.printing ? (f.severity === 'critical' || f.severity === 'high' || !!S.expanded[f.id]) : !!S.expanded[f.id];
    var safe = f.n.replace(/[^A-Za-z0-9]/g, '-');
    var titleId = 'ft-' + safe, panelId = 'fp-' + safe;
    var btn = h('button', { type: 'button', 'class': 'ax-card-btn', 'aria-expanded': open ? 'true' : 'false', 'aria-controls': panelId },
      h('span', { style: 'flex:none;width:96px;display:flex' }, sevBadge(f.severity)),
      h('span', { 'class': 'ax-col', style: 'gap:3px;flex:1 1 260px;min-width:0' },
        h('span', { id: titleId, 'class': 'ax-card-title', text: f.title }),
        h('span', { 'class': 'ax-card-meta' }, h('span', { 'class': 'ax-mono', style: 'font-size:11.5px', text: f.n }), h('span', { text: f.area_label }), f.object ? h('span', { 'class': 'ax-mono ax-break', style: 'font-size:11.5px;color:var(--color-text)', text: f.object }) : null)),
      h('span', { 'class': 'ax-row', style: 'gap:8px;flex:none;margin-left:auto' },
        f.status === 'accepted' ? pill('accepted') : null, pill(f.proof === 'supported' ? 'supported' : 'partial'),
        icon('chevron-down', 18, { cls: 'ax-chev' + (open ? ' open' : '') })));
    var card = h('article', { 'class': 'ax-card' + (f.severity === 'critical' ? ' critical' : '') + (open ? ' open' : ''), 'data-avoid-break': '', 'aria-labelledby': titleId, 'data-fid': f.id },
      h('h3', null, btn));
    btn.addEventListener('click', function () {
      S.expanded[f.id] = !open;
      S.justOpened = !open ? f.id : null;
      var next = findingCard(f);
      card.parentNode.replaceChild(next, card);
      next.querySelector('.ax-card-btn').focus();
    });
    if (open) {
      var objs = f.affected_objects || [];
      var objList = h('ul', { 'class': 'ax-objs' });
      objs.slice(0, 60).forEach(function (o) { objList.appendChild(h('li', { text: o })); });
      if (objs.length > 60) objList.appendChild(h('li', { text: '+ ' + (objs.length - 60) + ' more in findings.json' }));
      var waiver = f.waiver || {};
      var acceptedNote = f.status === 'accepted' ? 'Accepted risk recorded' + (waiver.owner || waiver.approved_by ? ' by ' + (waiver.owner || waiver.approved_by) : '') + (waiver.expires_on ? ', expires ' + waiver.expires_on : '') + (waiver.comment ? ': ' + waiver.comment : '.') + ' Still listed so the decision stays visible.' : null;
      var left = h('div', { 'class': 'ax-col', style: 'gap:14px;min-width:0' },
        f.description ? h('section', null, h('h4', { 'class': 'ax-h4', text: 'What we found' }), h('p', { style: 'font-size:14px;text-wrap:pretty', text: f.description })) : null,
        f.impact ? h('section', null, h('h4', { 'class': 'ax-h4', text: 'Why it matters' }), h('p', { style: 'font-size:14px;text-wrap:pretty', text: f.impact })) : null,
        f.remediation ? bp('section', '', { style: 'padding:12px 14px' }, h('h4', { 'class': 'ax-h4', text: 'How to fix' }), h('p', { style: 'font-size:14px;font-weight:500;text-wrap:pretty', text: f.remediation })) : null,
        h('section', null, h('h4', { 'class': 'ax-h4', style: 'margin-bottom:6px', text: 'Affected objects · ' + objs.length }), objs.length ? objList : h('p', { 'class': 'ax-muted', style: 'font-size:13px', text: 'No object recorded; the finding applies to the tenant setting.' })),
        acceptedNote ? h('p', { 'class': 'ax-muted', style: 'font-size:13px', text: acceptedNote }) : null);
      var refs = f.evidence_refs || [];
      var tags = h('ul', { 'class': 'ax-objs' });
      f._tags.forEach(function (t) { tags.appendChild(h('li', { style: 'border:0;padding:0' }, fwTag(t.label, t.id))); });
      var right = h('div', { 'class': 'ax-col', style: 'gap:14px;min-width:0' },
        refs.length ? refs.slice(0, 3).map(function (ref) { return evidenceBlock(ref.artifact_path, ref.record_key, ref.collector || f.collector); }) : bp('div', 'dashed', { style: 'padding:12px 14px;font-size:13.5px' }, pill('partial'), ' No evidence record is linked to this finding.'),
        refs.length > 3 ? h('p', { 'class': 'ax-muted', style: 'font-size:12.5px', text: (refs.length - 3) + ' more evidence references in findings.json.' }) : null,
        f._tags.length ? h('section', null, h('h4', { 'class': 'ax-h4', style: 'margin-bottom:6px', text: 'Framework mapping' }), tags) : null,
        h('p', { 'class': 'ax-mono ax-muted ax-break', style: 'font-size:12px', text: 'rule ' + (f.rule_id || '—') }));
      card.appendChild(h('div', { id: panelId, role: 'region', 'aria-labelledby': titleId, 'class': 'ax-card-panel' + (S.justOpened === f.id ? ' ax-reveal' : '') }, left, right));
    }
    return card;
  }
  function viewFindings(sec) {
    var r = R(), m = M(), total = m.findings.length, cov = r.coverage || { verified: 0, all: 0 };
    sec.className = 'ax-view gap-18';
    add(sec, [vhead('h-findings', 'Findings', plural(total, 'finding'), 'Sorted by severity. Every finding links to the record that proves it.')]);
    var nv = r.nv_areas || [];
    if (nv.length) {
      sec.appendChild(bp('div', 'dashed ax-row', { style: 'gap:8px 14px;padding:10px 14px' }, pill('not_verified'),
        h('span', { style: 'font-size:13.5px', text: nv.map(function (a) { return a.label + ' (' + a.reason.charAt(0).toLowerCase() + a.reason.slice(1) + ')'; }).join(' and ') + (nv.length === 1 ? ' was' : ' were') + ' not checked. No findings there is not a pass.' })));
    }
    if (!total) {
      var caveat = cov.verified < cov.all ? 'Only ' + cov.verified + ' of ' + cov.all + ' collectors ran.' : 'All ' + cov.all + ' collectors ran.';
      sec.appendChild(bp('div', 'dashed ax-empty', { style: 'max-width:720px' }, h('strong', { text: 'No findings in what was checked' }),
        h('p', { text: caveat + ' An empty list is not a clean bill of health for areas that were never collected.' }),
        h('span', null, h('button', { type: 'button', 'class': 'btn btn-secondary', onclick: function () { go('access'); } }, 'See which collectors ran'))));
      return;
    }
    var counts = r.counts || {};
    var search = h('input', { 'class': 'input', type: 'search', placeholder: 'Title, object, rule or control id', 'aria-label': 'Search findings' });
    search.value = S.q;
    search.addEventListener('input', function () { S.q = search.value; S.limit = 20; refresh(); });
    var mkSelect = function (label, value, options, onchange, flex) {
      var sel = h('select', { 'class': 'input', 'aria-label': label });
      options.forEach(function (o) { sel.appendChild(h('option', { value: o.value, text: o.label })); });
      sel.value = value;
      sel.addEventListener('change', function () { onchange(sel.value); S.limit = 20; refresh(); });
      return { el: h('label', { 'class': 'ax-field', style: 'flex:' + flex }, label, sel), sel: sel };
    };
    var areaSel = mkSelect('Area', S.area, [{ value: '', label: 'All areas' }].concat(m.areas.map(function (a) { return { value: a.key, label: a.label }; })), function (v) { S.area = v; }, '1 1 150px');
    var fwSel = mkSelect('Framework', S.fw, [{ value: '', label: 'All frameworks' }].concat(m.fwOptions), function (v) { S.fw = v; }, '1 1 150px');
    var stSel = mkSelect('Status', S.status, [{ value: '', label: 'Any status' }, { value: 'open', label: 'Open' }, { value: 'accepted', label: 'Accepted risk' }], function (v) { S.status = v; }, '1 1 130px');
    var chips = h('div', { role: 'group', 'aria-label': 'Filter by severity', 'class': 'ax-row', style: 'gap:6px' });
    var chipEls = {};
    SEVS.forEach(function (sv) {
      var bars = h('span', { 'class': 'bars', 'aria-hidden': 'true' });
      for (var i = 0; i < 4; i++) bars.appendChild(h('i', { 'class': i < SEV_LEVEL[sv] ? 'on' : null, style: 'height:' + (3 + i * 2) + 'px' }));
      var c = h('button', { type: 'button', 'class': 'ax-chip sevchip sev-' + sv, 'aria-pressed': 'false', disabled: counts[sv] ? null : true }, bars, SEV_LABEL[sv], h('span', { 'class': 'cnt', text: String(counts[sv] || 0) }));
      c.addEventListener('click', function () {
        var at = S.sev.indexOf(sv);
        if (at >= 0) S.sev.splice(at, 1); else S.sev.push(sv);
        S.limit = 20; refresh();
      });
      chipEls[sv] = c; chips.appendChild(c);
    });
    add(chips, [h('span', { style: 'flex:1' }),
      h('button', { type: 'button', 'class': 'btn btn-ghost', onclick: function () { filtered().slice(0, S.limit).forEach(function (f) { S.expanded[f.id] = true; }); S.justOpened = null; refresh(); } }, 'Expand all'),
      h('button', { type: 'button', 'class': 'btn btn-ghost', onclick: function () { S.expanded = {}; refresh(); } }, 'Collapse all')]);
    var live = h('span', { 'aria-live': 'polite', style: 'white-space:nowrap' });
    var clearBtn = h('button', { type: 'button', 'class': 'btn btn-ghost', style: 'font-size:13px', onclick: function () { clearFilters(); search.value = ''; areaSel.sel.value = ''; fwSel.sel.value = ''; stSel.sel.value = ''; refresh(); } }, 'Clear filters');
    var filters = h('div', { 'class': 'ax-filters', 'data-noprint': '' },
      h('div', { 'class': 'ax-filter-row' },
        h('label', { 'class': 'ax-field', style: 'flex:1 1 280px' }, 'Search', h('span', { 'class': 'ax-search' }, icon('search', 16), search)),
        areaSel.el, fwSel.el, stSel.el),
      chips,
      h('div', { 'class': 'ax-row', style: 'gap:10px;font-size:13px' }, live, clearBtn));
    var list = h('div', { 'class': 'ax-col', style: 'gap:18px' });
    sec.appendChild(filters);
    sec.appendChild(list);
    function refresh() {
      SEVS.forEach(function (sv) { chipEls[sv].setAttribute('aria-pressed', S.sev.indexOf(sv) >= 0 ? 'true' : 'false'); });
      var rows = filtered();
      var limited = S.printing ? rows : rows.slice(0, S.limit);
      clear(live);
      add(live, ['Showing ', h('strong', { text: String(limited.length) }), ' of ' + total + ' findings' + (rows.length !== total ? ' (' + rows.length + ' match)' : '')]);
      clearBtn.hidden = !(S.q.trim() || S.sev.length || S.area || S.fw || S.status);
      clear(list);
      SEVS.forEach(function (sv) {
        var items = limited.filter(function (f) { return f.severity === sv; });
        if (!items.length) return;
        var n = rows.filter(function (f) { return f.severity === sv; }).length;
        var group = h('section', { 'aria-label': SEV_LABEL[sv] + ' findings', 'class': 'ax-col', style: 'gap:8px' },
          h('h2', { 'class': 'ax-group-h' }, SEV_LABEL[sv], h('span', { 'class': 'cnt', text: String(n) }), h('span', { 'class': 'rule', 'aria-hidden': 'true' })));
        items.forEach(function (f) { group.appendChild(findingCard(f)); });
        list.appendChild(group);
      });
      if (!rows.length) {
        list.appendChild(bp('div', 'dashed', { style: 'padding:24px;display:flex;flex-direction:column;align-items:flex-start;gap:8px' },
          h('strong', { style: 'font-family:var(--font-heading);font-size:20px;font-weight:600', text: 'No findings match these filters' }),
          h('button', { type: 'button', 'class': 'btn btn-secondary', onclick: function () { clearBtn.click(); } }, 'Clear filters')));
      }
      if (!S.printing && rows.length > limited.length) {
        var rest = rows.length - limited.length;
        list.appendChild(h('button', { type: 'button', 'class': 'btn btn-secondary', 'data-noprint': '', style: 'align-self:flex-start', onclick: function () { S.limit += 20; S.justOpened = null; refresh(); } },
          'Show ' + Math.min(20, rest) + ' more · ' + rest + ' remaining'));
      }
      S.justOpened = null;
    }
    refresh();
  }

  // ------------------------------------------------------------------ attack paths
  function pathFlow(p) {
    var hops = p.hops || [];
    var cut = p.break_index;
    var sel = S.hop[p.id] !== undefined ? S.hop[p.id] : (cut !== null && cut !== undefined ? cut : 0);
    var wrap = h('div', { 'class': 'ax-flow-wrap' });
    var need = (hops.length + 1) * 170 + hops.length * 150;
    var flow = h('ol', { 'class': 'ax-flow', 'data-need': String(need), 'aria-label': 'Attack path from ' + p.source + ' to ' + p.target + ', ' + plural(hops.length, 'hop') });
    var node = function (label, type, i, last) {
      var first = i === 0;
      var typeLabel = NODE_LABEL[type] || type;
      var kicker = first ? 'Foothold · ' + (type === 'entry' ? p.foothold_label : typeLabel) : last ? 'Tier-0 control · ' + typeLabel : typeLabel;
      return bp('li', 'ax-node' + (last ? ' tier0' : ''), null,
        h('span', { 'class': 'k', text: kicker }),
        h('span', { 'class': 'lbl' }, icon(NODE_ICON[type] || 'user', 20), h('span', { style: String(label).indexOf('@') >= 0 ? 'font-family:var(--mono)' : null, text: label })));
    };
    hops.forEach(function (hp, i) {
      if (i === 0) flow.appendChild(node(hp.from, hp.from_type, 0, false));
      var isCut = i === cut;
      var line = h('span', { 'class': 'ax-line', 'aria-hidden': 'true' }, h('span', { 'class': 'seg' }));
      if (isCut) add(line, [h('span', { 'class': 'ax-scissors' }, icon('scissors', 14)), h('span', { 'class': 'seg' })]);
      line.appendChild(icon('arrowhead', 10, { cls: 'arrow' }));
      var chip = h('button', { type: 'button', 'class': 'ax-tech', 'aria-pressed': sel === i ? 'true' : 'false', 'aria-label': 'Show evidence for hop ' + (i + 1) + ': ' + hp.from + ' ' + hp.rel + ' ' + hp.to + ', ATT&CK ' + hp.technique }, hp.technique || 'evidence', icon('file', 11));
      chip.addEventListener('click', function () {
        S.hop[p.id] = i;
        var next = pathFlow(p);
        wrap.parentNode.replaceChild(next, wrap);
        updateFlows();
        var target = next.querySelectorAll('.ax-tech')[i];
        if (target) target.focus();
      });
      flow.appendChild(h('li', { 'class': 'ax-edge' + (isCut ? ' cut' : '') },
        h('span', { 'class': 'rel', text: hp.rel + (hp.eligible ? ' (PIM)' : '') }), line, chip,
        isCut ? h('span', { 'class': 'ax-breakhere', text: 'Break here' }) : null));
      flow.appendChild(node(hp.to, hp.to_type, i + 1, i === hops.length - 1));
    });
    var also = p.also || [];
    var breakBox = bp('section', 'ax-breakit' + (p.fix ? '' : ' none'), null,
      h('span', { 'class': 'k' }, icon('scissors', 14), p.fix ? 'Break it · one change closes this path' : 'No single break point'),
      h('span', { 'class': 'fix', text: p.fix || 'No single change closes this path' }),
      h('span', { 'class': 'ax-muted', style: 'font-size:13.5px;text-wrap:pretty', text: p.fix_detail }),
      h('span', { 'class': 'ax-muted', style: 'font-size:12.5px', text: also.length ? 'Also closes the same route from ' + also.join(', ') + '.' : 'Closes the only foothold found for this route.' }));
    var sh = hops[sel] || hops[0];
    var evCol = h('div', { 'class': 'ax-col', style: 'gap:8px;min-width:0' });
    if (sh) {
      add(evCol, [h('span', { 'class': 'ax-muted', style: 'font-size:12.5px' }, 'Hop ' + (sel + 1) + ' of ' + hops.length + ' · ', h('strong', { style: 'color:var(--color-text);font-weight:600', text: sh.technique_name }), ' (' + (sh.technique || '—') + ')'),
        sh.evidence && sh.evidence.key ? evidenceBlock(sh.evidence.artifact, sh.evidence.key, sh.evidence.collector, 'Evidence for hop ' + (sel + 1) + ' · ' + sh.rel) : h('p', { 'class': 'ax-muted', style: 'font-size:13px', text: 'No evidence reference recorded for this hop.' })]);
    }
    add(wrap, [flow, h('div', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 300px), 1fr));gap:18px' }, breakBox, evCol)]);
    return wrap;
  }
  function updateFlows() {
    Array.prototype.forEach.call(document.querySelectorAll('.ax-flow'), function (f) {
      var w = f.parentNode ? f.parentNode.getBoundingClientRect().width : 0;
      f.classList.toggle('vertical', S.narrow || (w > 0 && w < Number(f.getAttribute('data-need'))));
    });
  }
  function viewPaths(sec) {
    var r = R(), m = M(), paths = m.paths;
    sec.className = 'ax-view gap-20';
    var heading = paths.length ? plural(paths.length, 'route') + ' to tier-0 control' : 'No routes to tier-0 control';
    sec.appendChild(vhead('h-paths', 'Attack paths', heading, 'Privilege-escalation routes from a foothold (ordinary user, guest, user without MFA, third-party app) to tier-0 control. Every hop cites its evidence record and ATT&CK technique.'));
    if (!paths.length) {
      var colls = {}; (r.collectors || []).forEach(function (c) { colls[c.collector] = c; });
      var graph = r.attack_graph || {};
      var relevant = GRAPH_COLLECTORS.map(function (n) { return colls[n]; }).filter(Boolean);
      var notSel = !graph.node_count || !relevant.length || relevant.some(function (c) { return c.status === 'not_selected'; });
      var notVer = relevant.filter(function (c) { return c.status === 'not_verified'; });
      if (notSel) sec.appendChild(emptyFrame('not_verified', 'Not evaluated', 'Attack paths could not be evaluated', 'The collectors that feed the privilege graph (users, app ownership, consent and role assignments) did not all run. Re-run with a fuller preset.'));
      else if (notVer.length) sec.appendChild(emptyFrame('not_verified', 'Partially checked', 'No path found in what was collected', notVer.map(function (c) { return c.collector; }).join(', ') + ' could not be verified (' + notVer[0].reason.toLowerCase() + '), so routes through those objects could not be evaluated. This is not the same as no paths.'));
      else sec.appendChild(emptyFrame('pass', 'No path found', 'No route from any foothold reaches tier-0 control', 'Checked ' + plural(graph.node_count || 0, 'object') + ' and ' + plural(graph.edge_count || 0, 'relationship') + ' in the privilege graph. Every collector that feeds it ran.'));
      return;
    }
    var crit = paths.filter(function (p) { return p.severity === 'critical'; }).length, high = paths.filter(function (p) { return p.severity === 'high'; }).length;
    var fixes = {}; paths.forEach(function (p) { if (p.fix) fixes[p.fix] = true; });
    var foot = paths.reduce(function (n, p) { return n + 1 + (p.also || []).length; }, 0);
    sec.appendChild(h('div', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 200px), 1fr))' },
      statTile('Paths to tier-0', String(paths.length), crit + ' critical, ' + high + ' high', 'bad'),
      statTile('Footholds', String(foot), 'accounts or apps that can start a path'),
      statTile('Changes to close all', String(Object.keys(fixes).length), Object.keys(fixes).length === paths.length ? 'one break-it fix per path' : 'paths without a single break point need more')));
    var kinds = [];
    paths.forEach(function (p) { if (kinds.indexOf(p.foothold) < 0) kinds.push(p.foothold); });
    var chips = h('div', { role: 'group', 'aria-label': 'Filter by foothold', 'data-noprint': '', 'class': 'ax-row', style: 'gap:6px' });
    var list = h('ol', { 'class': 'ax-col', style: 'gap:18px' });
    var opts = [{ k: '', label: 'All footholds', count: paths.length }].concat(kinds.map(function (k) {
      var first = paths.filter(function (p) { return p.foothold === k; });
      return { k: k, label: first[0].foothold_label, count: first.length };
    }));
    var chipEls = opts.map(function (o) {
      var c = h('button', { type: 'button', 'class': 'ax-chip foot', 'aria-pressed': S.foot === o.k ? 'true' : 'false' }, o.label, h('span', { 'class': 'cnt', text: String(o.count) }));
      c.addEventListener('click', function () { S.foot = o.k; chipEls.forEach(function (x, i) { x.setAttribute('aria-pressed', opts[i].k === S.foot ? 'true' : 'false'); }); drawList(); });
      chips.appendChild(c);
      return c;
    });
    sec.appendChild(chips);
    sec.appendChild(list);
    function pathItem(p, i) {
      var open = S.printing || (S.openPaths[p.id] !== undefined ? S.openPaths[p.id] : i === 0);
      var bodyId = 'pb-' + i;
      var hopsN = (p.hops || []).length;
      var btn = h('button', { type: 'button', 'class': 'ax-path-btn', 'aria-expanded': open ? 'true' : 'false', 'aria-controls': bodyId },
        h('span', { style: 'width:96px;display:flex' }, sevBadge(p.severity)),
        h('span', { 'class': 'ax-col', style: 'gap:2px;flex:1 1 300px;min-width:0' },
          h('span', { 'class': 'ax-path-sum', text: p.headline || p.summary }),
          h('span', { 'class': 'ax-path-meta' }, h('span', { text: p.foothold_label }), h('span', { 'class': 'm', text: p.source }), h('span', { 'aria-hidden': 'true', text: '→' }), h('span', { 'class': 'm', text: p.target }), h('span', { text: '· ' + plural(hopsN, 'hop') }))),
        icon('chevron-down', 18, { cls: 'ax-chev' + (open ? ' open' : '') }));
      var li = bp('li', '', { 'data-avoid-break': '', style: 'display:flex;flex-direction:column' }, h('h2', { style: 'font:inherit;letter-spacing:normal' }, btn));
      if (open) li.appendChild(h('div', { id: bodyId, 'class': 'ax-path-body' + (S.justOpened === p.id ? ' ax-reveal' : '') }, h('p', { 'class': 'ax-path-detail', text: p.summary }), pathFlow(p)));
      btn.addEventListener('click', function () {
        S.openPaths[p.id] = !open; S.justOpened = !open ? p.id : null;
        var next = pathItem(p, i);
        li.parentNode.replaceChild(next, li);
        S.justOpened = null;
        updateFlows();
        next.querySelector('.ax-path-btn').focus();
      });
      return li;
    }
    function drawList() {
      clear(list);
      paths.forEach(function (p, i) { if (!S.foot || p.foothold === S.foot) list.appendChild(pathItem(p, i)); });
      updateFlows();
    }
    drawList();
  }

  // ------------------------------------------------------------------ detection
  function viewDetection(sec) {
    var det = R().detection;
    sec.className = 'ax-view gap-20';
    sec.appendChild(vhead('h-detection', 'Detection', 'Could this tenant see an attack?', 'Signals an investigator or SOC depends on. "Not verified" means Auditex could not collect the evidence; it is never counted as off.'));
    if (!det) {
      sec.appendChild(emptyFrame('not_selected', 'Not collected', 'Detection signals were not collected in this run', 'This run did not include the collectors that report audit and alerting configuration. Re-run with the full preset to answer this question.'));
      return;
    }
    var sig = det.signals || [], c = det.counts || { on: 0, off: 0, unknown: 0 };
    var ok = scored(det);
    var strip = h('div', { 'class': 'ax-signals', role: 'img', 'aria-label': c.on + ' on, ' + c.off + ' off, ' + c.unknown + ' not verified', style: 'grid-template-columns:repeat(' + Math.max(1, sig.length) + ', 1fr)' });
    sig.forEach(function (x) { strip.appendChild(h('span', { 'class': x.status, title: x.title + ': ' + (x.status === 'unknown' ? 'not verified' : x.status), text: x.status === 'on' ? '✓' : x.status === 'off' ? '✕' : '?' })); });
    sec.appendChild(h('div', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 260px), 1fr))' },
      bp('div', 'ax-stat', null, h('span', { 'class': 'ax-kicker', text: 'Detection score' }),
        h('span', { 'class': 'ax-num', style: 'font-size:44px' }, ok ? String(det.score) : 'Not scored', ok ? h('span', { 'class': 'ax-unit', style: 'font-size:20px', text: ' / 100' }) : null),
        h('span', { 'class': 'note', text: ok ? det.note : c.unknown + ' of ' + sig.length + ' signals not verified' })),
      bp('div', 'ax-stat ax-det-sig', null, h('span', { 'class': 'ax-kicker', text: 'Signals' }), strip,
        h('div', { 'class': 'ax-row ax-det-legend', style: 'gap:8px 18px;font-size:13px' },
          h('span', null, pill('on'), h('strong', { text: String(c.on) })), h('span', null, pill('off'), h('strong', { text: String(c.off) })), h('span', null, pill('unknown'), h('strong', { text: String(c.unknown) }))))));
    var order = { off: 0, unknown: 1, on: 2 };
    var cards = h('ul', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 340px), 1fr))' });
    sig.slice().sort(function (a, b) { return order[a.status] - order[b.status]; }).forEach(function (x) {
      cards.appendChild(bp('li', 'ax-sig' + (x.status === 'unknown' ? ' dashed' : ''), { 'data-avoid-break': '' },
        h('div', { style: 'display:flex;align-items:flex-start;justify-content:space-between;gap:10px' }, h('h2', { text: x.title }), pill(x.status)),
        h('p', { 'class': 'why', text: x.why }),
        h('p', { 'class': 'detail' + (x.status === 'on' ? ' on' : x.status === 'off' ? ' off' : ''), text: x.detail }),
        h('p', { 'class': 'src', text: x.source })));
    });
    sec.appendChild(cards);
  }

  // ------------------------------------------------------------------ baselines
  var SEG = { fail: 'background:var(--sev-critical);border:1px solid var(--sev-critical)', accepted: 'background:repeating-linear-gradient(135deg, var(--sev-high) 0 2px, transparent 2px 5px);border:1px solid var(--sev-high)', pass: 'background:var(--ok);border:1px solid var(--ok)', not_assessed: 'background:transparent;border:1px dashed var(--color-neutral-600)' };
  function viewBaselines(sec) {
    var b = R().baselines, m = M();
    sec.className = 'ax-view';
    sec.appendChild(vhead('h-baselines', 'Baselines', 'Baseline alignment', 'Each control is fail, accepted risk, pass or not assessed. Not assessed means no collector in this run evidences it.'));
    if (!b || (!(b.frameworks || []).length && !b.secure)) {
      sec.appendChild(emptyFrame('not_assessed', null, 'Not enough coverage to assess any framework', 'Showing a percentage here would imply controls were checked that were not.'));
      return;
    }
    (b.frameworks || []).forEach(function (f, fi) {
      var open = S.printing || !!S.fwOpen[f.key];
      var hid = 'fw-h-' + fi, pid = 'fw-p-' + fi;
      var c = f.counts;
      var bar = h('div', { role: 'img', 'aria-label': f.label + ': ' + c.fail + ' fail, ' + c.accepted + ' accepted risk, ' + c.pass + ' pass, ' + c.not_assessed + ' not assessed', 'class': 'ax-stack', style: 'height:14px' });
      ['fail', 'accepted', 'pass', 'not_assessed'].forEach(function (k) { if (c[k]) bar.appendChild(h('span', { style: 'width:' + pct(c[k], f.total) + ';' + SEG[k] })); });
      if (!f.total) bar.appendChild(h('span', { style: 'flex:1;' + SEG.not_assessed }));
      var legend = h('div', { 'class': 'ax-fw-legend' });
      ['fail', 'accepted', 'pass', 'not_assessed'].forEach(function (k) { legend.appendChild(h('span', null, pill(k), h('strong', { text: String(c[k]) }))); });
      var toggle = h('button', { type: 'button', 'class': 'btn btn-secondary', 'data-noprint': '', 'aria-expanded': open ? 'true' : 'false', 'aria-controls': pid }, open ? 'Hide controls' : 'View ' + plural(f.total, 'control'));
      var card = bp('section', '', { 'aria-labelledby': hid, 'data-avoid-break': '', style: 'display:flex;flex-direction:column' },
        h('div', { 'class': 'ax-fw-head' },
          h('div', { 'class': 'ax-col', style: 'gap:2px;flex:1 1 240px' },
            h('h2', { id: hid, 'class': 'ax-h2' }, f.label + ' ', h('span', { 'class': 'ax-mono ax-muted', style: 'font-size:13px;font-weight:400', text: f.version })),
            h('span', { 'class': 'ax-muted', style: 'font-size:13px', text: f.assessed + ' of ' + plural(f.total, 'control') + ' assessed' })),
          h('div', { 'class': 'ax-col', style: 'gap:8px;flex:2 1 320px;min-width:0' }, bar, legend),
          toggle));
      toggle.addEventListener('click', function () {
        S.fwOpen[f.key] = !open;
        var target = clear(document.getElementById('view-baselines'));
        viewBaselines(target);
        var again = document.querySelector('[aria-controls="' + pid + '"]');
        if (again) again.focus();
      });
      if (open) {
        var ul = h('ul');
        f.controls.forEach(function (ct) {
          var link = ct.linked > 0 ? h('button', { type: 'button', 'class': 'btn btn-ghost', style: 'font-size:13px;padding:2px 4px', onclick: function () { clearFilters(); go('findings', { fw: m.fwKeys[f.key] ? f.key : '', q: m.fwKeys[f.key] ? '' : ct.id, limit: 20 }); } }, plural(ct.linked, 'finding') + ' →') : h('span', { 'class': 'ax-muted', text: '—' });
          ul.appendChild(h('li', { 'class': 'ax-ctrl ax-rule' },
            h('span', { 'class': 'ax-mono', style: 'flex:0 0 150px;font-size:12.5px;padding-top:2px;word-break:break-all', text: ct.id }),
            h('span', { 'class': 'ax-col', style: 'flex:1 1 300px;gap:2px;font-size:13.5px' }, h('span', { text: ct.title }), ct.note ? h('span', { 'class': 'ax-muted', style: 'font-size:12px', text: ct.note }) : null),
            h('span', { style: 'flex:0 0 130px' }, pill(ct.status)),
            h('span', { style: 'flex:0 0 150px;font-size:13px' }, link)));
        });
        card.appendChild(h('div', { id: pid, 'class': S.printing ? null : 'ax-reveal', style: 'border-top:1px solid var(--color-divider)' },
          h('div', { 'class': 'ax-thead', 'aria-hidden': 'true', style: 'padding:8px 16px' }, h('span', { style: 'flex:0 0 150px', text: 'Control' }), h('span', { style: 'flex:1 1 300px', text: 'Requirement' }), h('span', { style: 'flex:0 0 130px', text: 'Status' }), h('span', { style: 'flex:0 0 150px', text: 'Evidence' })),
          ul));
      }
      sec.appendChild(card);
    });
    var ss = b.secure;
    var ssSec = h('section', { 'aria-labelledby': 'h-ss', 'class': 'ax-col', style: 'gap:12px' },
      h('div', { 'class': 'ax-col', style: 'gap:2px' }, h('h2', { id: 'h-ss', 'class': 'ax-h2 lg', text: 'Microsoft Secure Score reconciliation' }),
        h('p', { 'class': 'ax-muted', style: 'font-size:13.5px;max-width:76ch', text: 'Microsoft’s own score next to whether Auditex’s evidence agrees. Disagreements are where a dashboard looks better, or worse, than the evidence.' })));
    if (ss) {
      var rows = ss.rows || [];
      ssSec.appendChild(h('div', { 'class': 'ax-row', style: 'gap:10px 28px;align-items:baseline' },
        h('span', { 'class': 'ax-num', style: 'font-size:40px' }, fmtNum(ss.pct) + '%', h('span', { 'class': 'ax-unit', style: 'font-size:17px', text: ' Secure Score · ' + fmtNum(ss.cur) + ' / ' + fmtNum(ss.max) })),
        h('span', { style: 'font-size:13.5px' }, 'Auditex agrees on ', h('strong', { text: String(ss.agree) }), ', disagrees on ', h('strong', { text: String(ss.disagree) }), ', cannot assess ', h('strong', { text: String(ss.na) }), ' of ' + plural(rows.length, 'mapped control'))));
      var ul2 = h('ul');
      rows.forEach(function (row) {
        ul2.appendChild(h('li', { 'class': 'ax-ss-row ax-rule' + (row.highlight ? ' hl' : '') },
          h('span', { 'class': 'ax-col', style: 'flex:1 1 280px;gap:1px' }, h('span', { style: 'font-size:13.5px;font-weight:500', text: row.title }), h('span', { 'class': 'ax-mono ax-muted', style: 'font-size:11px', text: row.id })),
          h('span', { 'class': 'ax-col', style: 'flex:0 0 150px;gap:4px;font-size:12.5px' },
            h('span', null, h('strong', { 'class': 'ax-mono', text: fmtNum(row.score) }), ' / ' + fmtNum(row.max) + ' · ' + row.ms_status),
            h('span', { 'class': 'ax-ss-bar', 'aria-hidden': 'true' }, h('span', { style: 'width:' + Math.max(0, Math.min(100, row.pct)) + '%' }))),
          h('span', { style: 'flex:0 0 110px' }, pill(row.verdict)),
          h('span', { style: 'flex:1 1 260px;font-size:13px;text-wrap:pretty', text: row.note })));
      });
      ssSec.appendChild(h('div', { style: 'border:1px solid var(--color-divider)' },
        h('div', { 'class': 'ax-thead', 'aria-hidden': 'true' }, h('span', { style: 'flex:1 1 280px', text: 'Secure Score control' }), h('span', { style: 'flex:0 0 150px', text: 'Microsoft' }), h('span', { style: 'flex:0 0 110px', text: 'Auditex' }), h('span', { style: 'flex:1 1 260px', text: 'Why' })),
        ul2));
    } else {
      ssSec.appendChild(bp('div', 'dashed ax-row', { style: 'padding:18px 20px;gap:10px' }, pill('not_verified'), h('span', { style: 'font-size:14px', text: b.secure_missing || 'Secure Score was not collected in this run.' })));
    }
    sec.appendChild(ssSec);
  }

  // ------------------------------------------------------------------ access
  function viewAccess(sec) {
    var r = R(), cov = r.coverage || {};
    sec.className = 'ax-view';
    sec.appendChild(vhead('h-access', 'Access & data handling', 'What this run could and could not do', 'Recorded in data-handling.json at run time, not asserted after the fact.'));
    var grid = h('ul', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 220px), 1fr))' });
    (r.assertions || []).forEach(function (a) {
      grid.appendChild(bp('li', 'ax-assert', null, h('span', { style: 'font-size:13.5px', text: a.q }),
        h('span', { 'class': 'ax-row', style: 'gap:10px' }, h('span', { 'class': 'a' + (a.status === 'fail' ? ' bad' : a.status === 'not_verified' ? ' unk' : ''), text: a.a }), pill(a.status, a.pill)),
        h('span', { 'class': 'ax-mono ax-muted ax-break', style: 'font-size:11px', text: a.src })));
    });
    sec.appendChild(grid);
    if ((r.data_handling || {}).write_actions === false) {
      sec.appendChild(h('p', { style: 'font-size:14px;max-width:80ch;text-wrap:pretty', text: 'API methods were read-only (GET and Exchange Get-* cmdlets). Graph metadata and settings only: inbox rules are read as rule definitions and sharing links as link metadata; message bodies and file contents are never requested. Secrets are recorded as expiry dates, never values.' }));
    }
    var nv = cov.not_verified || 0, ns = cov.not_selected || 0;
    var rows = (r.collectors || []).map(function (c, i) { return { c: c, i: i }; }).sort(function (a, b) { return (a.c.status === 'verified') - (b.c.status === 'verified') || a.i - b.i; });
    var ul = h('ul');
    rows.forEach(function (x) {
      var c = x.c;
      var perms = h('span', { 'class': 'ax-row', style: 'flex:1 1 280px;gap:4px;align-items:flex-start' });
      (c.permissions || []).forEach(function (p) { perms.appendChild(h('span', { 'class': 'ax-perm', text: p })); });
      if (!(c.permissions || []).length) perms.appendChild(h('span', { 'class': 'ax-muted', style: 'font-size:12px', text: 'No Graph permission (command-line or offline source)' }));
      ul.appendChild(h('li', { 'class': 'ax-coll ax-rule' },
        h('span', { 'class': 'ax-mono', style: 'flex:0 0 170px;font-size:12.5px;padding-top:2px;word-break:break-all', text: c.collector }),
        h('span', { 'class': 'ax-col', style: 'flex:0 0 200px;gap:3px;align-items:flex-start' }, pill(c.status), c.status !== 'verified' ? h('span', { 'class': 'ax-muted', style: 'font-size:12px', text: c.reason }) : null),
        perms,
        h('span', { 'class': 'ax-muted', style: 'flex:1 1 240px;font-size:13px', text: c.description })));
    });
    sec.appendChild(h('section', { 'aria-labelledby': 'h-coll', 'class': 'ax-col', style: 'gap:10px' },
      h('h2', { id: 'h-coll', 'class': 'ax-h2 lg', text: 'Collectors and their read permissions' }),
      h('p', { 'class': 'ax-muted', style: 'font-size:13.5px', text: (cov.verified || 0) + ' verified' + (nv ? ', ' + nv + ' not verified' : '') + (ns ? ', ' + ns + ' not selected' : '') + '.' + (nv || ns ? ' Not verified collectors are listed first, with the reason.' : '') }),
      h('div', { style: 'border:1px solid var(--color-divider)' },
        h('div', { 'class': 'ax-thead', 'aria-hidden': 'true' }, h('span', { style: 'flex:0 0 170px', text: 'Collector' }), h('span', { style: 'flex:0 0 200px', text: 'Status' }), h('span', { style: 'flex:1 1 280px', text: 'Read permissions' }), h('span', { style: 'flex:1 1 240px', text: 'What it reads' })),
        ul)));
  }

  // ------------------------------------------------------------------ compare
  function viewCompare(sec) {
    var c = RAW.compare;
    sec.className = 'ax-view';
    sec.appendChild(vhead('h-compare', 'Before / after', 'Progress since the last run'));
    if (!c) {
      sec.appendChild(bp('div', 'dashed ax-empty', null, h('strong', { text: 'Only one run of this tenant is loaded' }),
        h('p', null, 'Generate the explorer with a previous run to compare: ', h('span', { 'class': 'ax-cli', text: 'auditex report explorer <run> --compare <previous-run>' }))));
      return;
    }
    var a = c.a, b = c.b;
    var diff = (Number(b.score) || 0) - (Number(a.score) || 0);
    var line = (diff < 0 ? 'Score down ' + plural(-diff, 'point') + '.' : diff > 0 ? 'Score up ' + plural(diff, 'point') + '.' : 'Score unchanged.');
    if (c.paths_before > c.paths_after) line += c.paths_after === 0 ? ' Every attack path is closed.' : ' ' + plural(c.paths_before - c.paths_after, 'attack path') + ' closed.';
    else if (c.paths_after > c.paths_before) line += ' ' + plural(c.paths_after - c.paths_before, 'new attack path') + '.';
    var cell = function (k, run, total) {
      return h('div', { 'class': 'ax-cmp-cell' },
        h('span', { 'class': 'ax-kicker muted', text: k + ' · ' + run.label }),
        h('span', { 'class': 'ax-row', style: 'gap:12px' }, sevBadge(run.grade, true), h('span', { 'class': 'ax-num', style: 'font-size:40px', text: fmtNum(run.score) })),
        h('span', { 'class': 'ax-mono ax-muted', style: 'font-size:11.5px', text: run.run_name + ' · ' + plural(total, 'finding') }));
    };
    var plate = bp('div', 'ax-plate', { style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 260px), 1fr))' },
      cell('Before', a, a.findings), cell('After', b, b.findings),
      h('div', { 'class': 'ax-cmp-cell', style: 'justify-content:center;gap:6px' },
        h('span', { 'class': 'ax-kicker', text: 'Risk grade change' }),
        h('span', { 'class': 'ax-num', style: 'font-size:26px;line-height:1.15', text: upper(a.grade) + ' ' + fmtNum(a.score) + ' → ' + upper(b.grade) + ' ' + fmtNum(b.score) }),
        h('span', { style: 'font-size:13.5px', text: line })));
    Array.prototype.forEach.call(plate.querySelectorAll('.ax-cmp-cell'), function (el, i) { if (i) el.classList.add('cell-sep'); });
    sec.appendChild(plate);
    sec.appendChild(h('div', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 160px), 1fr))' },
      statTile('Resolved', String(c.resolved.length), 'no longer present', c.resolved.length ? 'good' : null),
      statTile('New', String(c.added.length), 'appeared since last run', c.added.length ? 'bad' : null),
      statTile('Changed', String(c.changed.length), 'severity moved'),
      statTile('Findings', a.findings + ' → ' + b.findings, 'before → after'),
      statTile('Attack paths', c.paths_before + ' → ' + c.paths_after, 'routes to tier-0'),
      statTile('Detection', fmtNum(c.det_before) + ' → ' + fmtNum(c.det_after), 'score over verified signals')));
    var maxRow = Math.max.apply(null, [1].concat(c.rows.map(function (r) { return Math.max(r.before, r.after); })));
    var table = h('div', { role: 'table', 'aria-label': 'Findings by severity, before and after', style: 'border:1px solid var(--color-divider)' },
      h('div', { role: 'row', 'class': 'ax-cmp-row head' }, ['Severity', 'Before', 'After', 'Resolved', 'Changed'].map(function (t) { return h('span', { role: 'columnheader', text: t }); }), h('span', { role: 'columnheader', 'class': 'ax-pair-col', text: 'Before / after' })));
    c.rows.forEach(function (r) {
      table.appendChild(h('div', { role: 'row', 'class': 'ax-cmp-row ax-rule' },
        h('span', { role: 'cell' }, sevBadge(r.severity)),
        h('span', { role: 'cell', text: String(r.before) }),
        h('span', { role: 'cell', style: 'font-weight:700', text: String(r.after) }),
        h('span', { role: 'cell', style: 'color:var(--ok)', text: r.resolved ? '−' + r.resolved : '0' }),
        h('span', { role: 'cell', text: r.changed_out ? '−' + r.changed_out : r.changed_in ? '+' + r.changed_in : '0' }),
        h('span', { role: 'cell', 'aria-hidden': 'true', 'class': 'ax-pair ax-pair-col' }, h('span', { 'class': 'b', style: 'width:' + (100 * r.before / maxRow).toFixed(1) + '%' }), h('span', { 'class': 'a', style: 'width:' + (100 * r.after / maxRow).toFixed(1) + '%' }))));
    });
    sec.appendChild(h('section', { 'aria-labelledby': 'h-cmpsev', 'class': 'ax-col', style: 'gap:10px' }, h('h2', { id: 'h-cmpsev', 'class': 'ax-h2', text: 'By severity' }), table));
    var listSec = function (id, title, rows, status, label, strike, dashedEmpty) {
      if (!rows.length) return bp('section', 'dashed', { 'aria-labelledby': id, style: 'display:flex;flex-direction:column' }, h('h2', { id: id, 'class': 'ax-h2', style: 'padding:14px 16px 4px', text: title + ' · 0' }), h('p', { style: 'padding:0 16px 14px;font-size:14px', text: dashedEmpty }));
      var ul = h('ul');
      rows.forEach(function (f) {
        ul.appendChild(h('li', { 'class': 'ax-list-row' },
          h('span', { style: 'width:92px;display:flex' }, sevBadge(f.severity)),
          h('span', { 'class': 'ax-col', style: 'flex:1 1 200px;min-width:0' }, h('span', { 'class': strike ? 'ax-strike' : null, style: strike ? null : 'font-size:14px;font-weight:500', text: f.title }), h('span', { 'class': 'ax-mono ax-muted ax-break', style: 'font-size:11.5px', text: f.object })),
          pill(status, label)));
      });
      return bp('section', '', { 'aria-labelledby': id, style: 'display:flex;flex-direction:column' }, h('h2', { id: id, 'class': 'ax-h2', style: 'padding:14px 16px 8px', text: title + ' · ' + rows.length }), ul);
    };
    var changed = c.changed.length ? (function () {
      var ul = h('ul');
      c.changed.forEach(function (f) {
        ul.appendChild(h('li', { 'class': 'ax-col', style: 'gap:6px;padding:10px 16px;border-top:1px solid var(--color-divider)' },
          h('span', { style: 'font-size:14px;font-weight:500' }, f.title + ' ', h('span', { 'class': 'ax-mono ax-muted', style: 'font-size:11.5px;font-weight:400', text: f.object })),
          h('span', { 'class': 'ax-row', style: 'gap:8px' }, sevBadge(f.severity), h('span', { 'class': 'ax-sr', text: 'changed to' }), icon('arrow-right', 16), sevBadge(f.to_severity))));
      });
      return bp('section', '', { 'aria-labelledby': 'h-chg', style: 'display:flex;flex-direction:column' }, h('h2', { id: 'h-chg', 'class': 'ax-h2', style: 'padding:14px 16px 8px', text: 'Changed · ' + c.changed.length }), ul);
    })() : bp('section', 'dashed', { 'aria-labelledby': 'h-chg', style: 'display:flex;flex-direction:column' }, h('h2', { id: 'h-chg', 'class': 'ax-h2', style: 'padding:14px 16px 4px', text: 'Changed · 0' }), h('p', { style: 'padding:0 16px 14px;font-size:14px', text: 'No finding changed severity.' }));
    sec.appendChild(h('div', { 'class': 'ax-grid', style: 'grid-template-columns:repeat(auto-fit, minmax(min(100%, 380px), 1fr))' },
      listSec('h-res', 'Resolved', c.resolved, 'pass', 'Resolved', true, 'No finding was resolved since the previous run.'),
      h('div', { 'class': 'ax-col', style: 'gap:22px' }, listSec('h-new', 'New', c.added, 'added', 'New', false, 'No new findings since the previous run.'), changed)));
  }

  // ------------------------------------------------------------------ render loop
  var RENDER = { overview: viewOverview, findings: viewFindings, paths: viewPaths, detection: viewDetection, baselines: viewBaselines, access: viewAccess, compare: viewCompare };
  function renderCover() {
    var cover = clear(document.getElementById('ax-cover'));
    cover.hidden = !S.printing;
    if (!S.printing) return;
    var r = R();
    add(cover, [h('span', { 'class': 'ax-kicker', text: 'Customer handoff pack' }),
      h('h1', { text: ((r.meta || {}).display_name || r.tenant || 'Tenant') + ' · security audit evidence' }),
      h('p', { text: 'Run ' + r.run_name + ' · ' + r.collected_label + ' · ' + r.mode_label + ' · ' + (RAW.generator || 'Auditex') + '. ' + ((r.data_handling || {}).write_actions === false ? 'Read-only: nothing was written to the tenant and no mail or file content was read. ' : '') + 'Every finding cites the record that proves it.' })]);
  }
  function renderAll(animate) {
    DOC.setAttribute('data-theme', S.printing ? 'light' : S.theme);
    renderChrome();
    renderCover();
    VIEWS.forEach(function (v) {
      var sec = document.getElementById('view-' + v);
      var show = S.printing || v === S.view;
      sec.hidden = !show;
      clear(sec);
      if (!show) return;
      RENDER[v](sec);
      if (animate && !S.printing) sec.classList.add('ax-anim-in');
    });
    measure();
  }
  function measure() {
    var w = ROOT.getBoundingClientRect().width;
    var mw = MAIN.getBoundingClientRect().width;
    var narrow = w > 0 && w < 760;
    if (narrow !== S.narrow) { S.narrow = narrow; ROOT.classList.toggle('ax-narrow', narrow); }
    ROOT.classList.toggle('ax-table-wide', mw >= 900);
    ROOT.classList.toggle('ax-compact', mw > 0 && mw < 600);
    updateFlows();
  }

  // ------------------------------------------------------------------ wiring
  Array.prototype.forEach.call(document.querySelectorAll('#ax-nav button[data-view]'), function (b) {
    b.addEventListener('click', function () { go(b.getAttribute('data-view')); });
  });
  document.getElementById('ax-run').addEventListener('change', function (e) {
    S.run = Number(e.target.value) || 0;
    S.expanded = {}; S.limit = 20; S.openPaths = {}; S.hop = {}; S.foot = ''; S.fwOpen = {};
    clearFilters();
    renderAll(true);
  });
  document.getElementById('ax-theme').addEventListener('click', function () {
    S.theme = S.theme === 'dark' ? 'light' : 'dark';
    DOC.setAttribute('data-theme', S.theme);
    renderChrome();
  });
  document.getElementById('ax-print').addEventListener('click', function () {
    S.printing = true;
    renderAll(false);
    setTimeout(function () { try { window.print(); } catch (e) { /* print unavailable */ } }, 350);
  });
  window.addEventListener('afterprint', function () { if (!S.printing) return; S.printing = false; renderAll(false); });
  window.addEventListener('resize', measure);
  if (window.ResizeObserver) { var ro = new ResizeObserver(function () { measure(); }); ro.observe(ROOT); ro.observe(MAIN); }

  // Narrow layout is decided before the first paint so the nav does not jump.
  ROOT.classList.toggle('ax-narrow', ROOT.getBoundingClientRect().width < 760);
  S.narrow = ROOT.classList.contains('ax-narrow');
  renderAll(false);
})();
