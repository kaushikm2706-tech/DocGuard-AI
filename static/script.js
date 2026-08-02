// ==========================================================================
// DocGuard AI: Sentinel — frontend logic
// No framework — plain JS is enough for this scope, and it keeps the
// "how does this actually work" story simple to explain to judges.
// ==========================================================================

let scanCount = 0;
let lastFile = null;
let lastBatchId = null;

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const radar = document.getElementById('radar');
const terminalPanel = document.getElementById('terminalPanel');
const terminal = document.getElementById('terminal');
const resultsSection = document.getElementById('results');
const caseFile = document.getElementById('caseFile');

// ---------- drag & drop wiring ----------
['dragenter', 'dragover'].forEach(evt =>
  dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.add('drag-over'); })
);
['dragleave', 'drop'].forEach(evt =>
  dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.remove('drag-over'); })
);
dropzone.addEventListener('drop', e => {
  const files = Array.from(e.dataTransfer.files).filter(f => f.type === 'application/pdf');
  if (files.length) routeFiles(files);
});
fileInput.addEventListener('change', e => {
  const files = Array.from(e.target.files);
  if (files.length) routeFiles(files);
});

function routeFiles(files) {
  if (files.length === 1) {
    handleFile(files[0]);
  } else {
    handleBatch(files);
  }
}

// ---------- main flow ----------
async function handleFile(file) {
  lastFile = file;
  lastBatchId = null;
  scanCount += 1;
  caseFile.textContent = `CASE FILE #${String(scanCount).padStart(3, '0')} — ${file.name.toUpperCase()}`;

  document.getElementById('batchPanel').classList.add('hidden');
  radar.classList.remove('threat', 'clear');
  radar.classList.add('scanning');
  terminalPanel.classList.remove('hidden');
  resultsSection.classList.add('hidden');
  terminal.textContent = '';

  await typeLine(`> Ingesting ${file.name} into memory buffer...`);
  await typeLine('> Bypassing flattened text extraction. Reading raw character objects...');
  await typeLine('> Scout Agent: scanning font size, color channel, and hyperlink structure...');

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/scan', { method: 'POST', body: formData });
    const data = await res.json();
    if (data.error) {
      await typeLine(`> ERROR: ${data.error}`, 'danger');
      radar.classList.remove('scanning');
      return;
    }
    await renderScanLog(data);
    radar.classList.remove('scanning');
    radar.classList.add(data.threat_score > 0 ? 'threat' : 'clear');
    renderResults(data);
  } catch (err) {
    await typeLine(`> CONNECTION ERROR: ${err}`, 'danger');
    radar.classList.remove('scanning');
  }
}

function typeLine(text, cls) {
  return new Promise(resolve => {
    const span = document.createElement('div');
    if (cls === 'danger') span.className = 'line-danger';
    if (cls === 'ok') span.className = 'line-ok';
    terminal.appendChild(span);
    let i = 0;
    const interval = setInterval(() => {
      span.textContent += text[i];
      i++;
      terminal.scrollTop = terminal.scrollHeight;
      if (i >= text.length) {
        clearInterval(interval);
        setTimeout(resolve, 120);
      }
    }, 8);
  });
}

async function renderScanLog(data) {
  await typeLine(`> Pages inspected: ${data.stats.page_count}`);
  await typeLine(`> Character nodes scanned: ${data.stats.total_chars}`);
  if (data.anomalies.length === 0) {
    await typeLine('> SCAN COMPLETE. No anomalies detected.', 'ok');
  } else {
    await typeLine(`> SCAN COMPLETE. ${data.anomalies.length} anomaly(ies) flagged.`, 'danger');
  }
}

// ---------- batch scan flow ----------
let batchResults = [];

async function handleBatch(files) {
  scanCount += 1;
  caseFile.textContent = `CASE FILE #${String(scanCount).padStart(3, '0')} — BATCH OF ${files.length} DOCUMENTS`;

  resultsSection.classList.add('hidden');
  radar.classList.remove('threat', 'clear');
  radar.classList.add('scanning');
  terminalPanel.classList.remove('hidden');
  terminal.textContent = '';

  await typeLine(`> Ingesting batch of ${files.length} documents...`);
  await typeLine('> Scout Agent: processing each file through the forensic pipeline...');

  const formData = new FormData();
  files.forEach(f => formData.append('files', f));

  try {
    const res = await fetch('/api/scan/batch', { method: 'POST', body: formData });
    const data = await res.json();
    if (data.error) {
      await typeLine(`> ERROR: ${data.error}`, 'danger');
      radar.classList.remove('scanning');
      return;
    }
    batchResults = data.results;
    const threatCount = batchResults.filter(r => !r.error && r.threat_score > 0).length;
    await typeLine(`> BATCH COMPLETE. ${threatCount} of ${batchResults.length} document(s) flagged.`, threatCount ? 'danger' : 'ok');
    radar.classList.remove('scanning');
    radar.classList.add(threatCount ? 'threat' : 'clear');
    renderBatchTable(batchResults);
  } catch (err) {
    await typeLine(`> CONNECTION ERROR: ${err}`, 'danger');
    radar.classList.remove('scanning');
  }
}

function renderBatchTable(results) {
  const panel = document.getElementById('batchPanel');
  const table = document.getElementById('batchTable');
  panel.classList.remove('hidden');

  let html = `<div class="batch-head-row"><span>FILE</span><span>THREAT SCORE</span><span>VERDICT</span><span style="text-align:right">ANOMALIES</span></div>`;
  results.forEach((r, idx) => {
    if (r.error) {
      html += `<div class="batch-row error-row" data-idx="${idx}">
        <span class="batch-file">${escapeHtml(r.filename)}</span>
        <span class="batch-score">—</span>
        <span class="batch-verdict">PARSE ERROR</span>
        <span class="batch-anomalies">—</span>
      </div>`;
    } else {
      const isClean = r.threat_score === 0;
      html += `<div class="batch-row" data-idx="${idx}">
        <span class="batch-file">${escapeHtml(r.filename)}</span>
        <span class="batch-score ${isClean ? 'clean' : 'threat'}">${r.threat_score}</span>
        <span class="batch-verdict">${isClean ? 'CLEAN' : 'THREAT'}</span>
        <span class="batch-anomalies">${r.anomalies.length}</span>
      </div>`;
    }
  });
  table.innerHTML = html;

  table.querySelectorAll('.batch-row').forEach(row => {
    row.addEventListener('click', () => {
      const idx = parseInt(row.dataset.idx, 10);
      const result = results[idx];
      if (result.error) return;
      table.querySelectorAll('.batch-row').forEach(r => r.classList.remove('active-row'));
      row.classList.add('active-row');
      lastFile = null; // batch items: no local File object, but the server cached the bytes by id
      lastBatchId = result.id;
      renderResults(result);
      document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}

// ---------- results rendering ----------
function renderResults(data) {
  resultsSection.classList.remove('hidden');

  // gauge
  const score = data.threat_score;
  const gaugeFill = document.getElementById('gaugeFill');
  const circumference = 251;
  const offset = circumference - (circumference * score / 100);
  gaugeFill.style.strokeDashoffset = offset;
  gaugeFill.style.stroke = score === 0 ? 'var(--cyan)' : score < 40 ? 'var(--amber)' : 'var(--red)';
  document.getElementById('scoreNumber').textContent = score;

  // stats
  document.getElementById('statChars').textContent = data.stats.total_chars.toLocaleString();
  document.getElementById('statPages').textContent = data.stats.page_count;
  document.getElementById('statLinks').textContent = data.stats.total_links;
  document.getElementById('statFont').textContent = `${data.stats.avg_font_size.toFixed(1)}pt`;

  // verdict
  const badge = document.getElementById('verdictBadge');
  if (score === 0) {
    badge.textContent = 'CLEAN — NO THREATS';
    badge.className = 'verdict-badge clean';
  } else {
    badge.textContent = `THREAT DETECTED — ${data.anomalies.length} VECTOR(S)`;
    badge.className = 'verdict-badge threat';
  }

  renderEvidence(data.anomalies);
  renderGraph(data.stats, data.anomalies);
  renderAction(data, score);
}

function renderEvidence(anomalies) {
  const list = document.getElementById('evidenceList');
  list.innerHTML = '';
  if (anomalies.length === 0) {
    list.innerHTML = '<div class="evidence-empty">No hidden threats found. Document structure matches its visible presentation.</div>';
    return;
  }
  anomalies.forEach((a, idx) => {
    const card = document.createElement('div');
    card.className = 'evidence-card';
    card.innerHTML = `
      <div class="evidence-top">
        <div class="evidence-reason">Threat Vector #${idx + 1} — ${a.reason}</div>
        <div class="evidence-weight">+${a.weight} pts</div>
      </div>
      <div class="evidence-meta">PAGE ${a.page} · KIND: ${a.kind.toUpperCase()}</div>
      <div class="evidence-snippet">${escapeHtml(a.text)}</div>
      <div class="evidence-narrative"><span class="narrative-tag">${a.narrative_mode === 'live' ? 'AI ANALYSIS' : 'PATTERN MATCH'}</span>${escapeHtml(a.narrative)}</div>
      <button class="btn-replay" data-idx="${idx}">▶ RUN ATTACK REPLAY</button>
    `;
    list.appendChild(card);
    card.querySelector('.btn-replay').addEventListener('click', () => openReplay(a));
  });
}

function renderAction(data, score) {
  const el = document.getElementById('actionContent');
  if (score === 0) {
    el.innerHTML = `<div class="action-clean">✓ NO REMEDIATION NEEDED — document is clean as-is.</div>`;
  } else if (!lastFile && lastBatchId) {
    // Batch-selected item: the server cached these bytes during the
    // batch scan, so we can offer a direct one-click download.
    el.innerHTML = `
      <div class="action-threat">
        <div class="action-threat-copy">Sentinel can discard this file's entire structure and synthesize a brand-new, standard-compliant PDF from only the legitimate text.</div>
        <button class="btn-download" id="downloadBtn">⬇ DOWNLOAD SANITIZED PDF</button>
      </div>`;
    document.getElementById('downloadBtn').addEventListener('click', downloadSanitized);
  } else if (!lastFile) {
    el.innerHTML = `<div class="action-threat-copy">To download a sanitized copy of <strong>${escapeHtml(data.filename)}</strong>, re-upload it individually using "Select Document" above.</div>`;
  } else {
    el.innerHTML = `
      <div class="action-threat">
        <div class="action-threat-copy">Sentinel can discard this file's entire structure and synthesize a brand-new, standard-compliant PDF from only the legitimate text.</div>
        <button class="btn-download" id="downloadBtn">⬇ DOWNLOAD SANITIZED PDF</button>
      </div>`;
    document.getElementById('downloadBtn').addEventListener('click', downloadSanitized);
  }
}

async function downloadSanitized() {
  if (lastFile) {
    const formData = new FormData();
    formData.append('file', lastFile);
    const res = await fetch('/api/sanitize', { method: 'POST', body: formData });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sanitized_${lastFile.name}`;
    a.click();
    URL.revokeObjectURL(url);
  } else if (lastBatchId) {
    const a = document.createElement('a');
    a.href = `/api/sanitize/${lastBatchId}`;
    a.click();
  }
}

// ---------- attack replay modal ----------
const replayModal = document.getElementById('replayModal');
document.getElementById('replayClose').addEventListener('click', () => replayModal.classList.add('hidden'));
replayModal.addEventListener('click', e => { if (e.target === replayModal) replayModal.classList.add('hidden'); });

function openReplay(anomaly) {
  document.getElementById('replayAiLine').textContent = anomaly.replay.ai_response;
  document.getElementById('replayConsequence').textContent = anomaly.replay.consequence;
  replayModal.classList.remove('hidden');
}

// ---------- threat graph (D3 force layout) ----------
function renderGraph(stats, anomalies) {
  const container = document.getElementById('graphContainer');
  container.innerHTML = '';
  const width = container.clientWidth;
  const height = 340;

  const svg = d3.select(container).append('svg')
    .attr('width', width).attr('height', height);

  // Build a representative node sample: we don't render every single
  // character (could be thousands) — we render a proportional sample
  // plus every real anomaly, so the graph stays readable but honest.
  const sampleSize = Math.min(70, Math.max(20, Math.floor(stats.total_chars / 40)));
  const nodes = [{ id: 'core', type: 'core' }];
  for (let i = 0; i < sampleSize; i++) {
    nodes.push({ id: `clean-${i}`, type: 'clean' });
  }
  anomalies.forEach((a, i) => nodes.push({ id: `threat-${i}`, type: 'threat', reason: a.reason }));

  const links = nodes
    .filter(n => n.id !== 'core')
    .map(n => ({ source: 'core', target: n.id, threat: n.type === 'threat' }));

  const simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(d => d.threat ? 120 : 70).strength(0.6))
    .force('charge', d3.forceManyBody().strength(-18))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collide', d3.forceCollide(10));

  const link = svg.append('g').selectAll('line')
    .data(links).enter().append('line')
    .attr('class', d => d.threat ? 'graph-link-threat' : 'graph-link');

  const node = svg.append('g').selectAll('circle')
    .data(nodes).enter().append('circle')
    .attr('r', d => d.type === 'core' ? 12 : d.type === 'threat' ? 7 : 3.5)
    .attr('class', d => `node-${d.type}`)
    .append('title');

  const nodeSel = svg.selectAll('circle')
    .data(nodes)
    .join('circle')
    .attr('r', d => d.type === 'core' ? 12 : d.type === 'threat' ? 7 : 3.5)
    .attr('class', d => `node-${d.type}`);
  nodeSel.append('title').text(d => d.reason || d.type);

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    nodeSel
      .attr('cx', d => d.x).attr('cy', d => d.y);
  });
}

// ---------- warden agent controls ----------
const wardenToggle = document.getElementById('wardenToggle');
const wardenStatusText = document.getElementById('wardenStatusText');
const wardenDot = document.getElementById('wardenDot');
const wardenFeed = document.getElementById('wardenFeed');
let wardenPoll = null;

wardenToggle.addEventListener('click', async () => {
  const running = wardenToggle.classList.contains('active');
  const endpoint = running ? '/api/warden/stop' : '/api/warden/start';
  const res = await fetch(endpoint, { method: 'POST' });
  const data = await res.json();
  setWardenUI(data.running);
});

function setWardenUI(running) {
  wardenToggle.classList.toggle('active', running);
  wardenToggle.textContent = running ? 'DEACTIVATE WARDEN' : 'ACTIVATE WARDEN';
  wardenStatusText.textContent = running ? 'PATROLLING' : 'STANDBY';
  wardenDot.classList.toggle('live', running);
  if (running && !wardenPoll) {
    wardenPoll = setInterval(pollWardenLog, 2000);
  } else if (!running && wardenPoll) {
    clearInterval(wardenPoll);
    wardenPoll = null;
  }
}

async function pollWardenLog() {
  const res = await fetch('/api/warden/log');
  const data = await res.json();
  if (data.entries.length === 0) return;
  wardenFeed.innerHTML = '';
  data.entries.slice().reverse().forEach(e => {
    const div = document.createElement('div');
    div.className = `feed-item ${e.verdict === 'THREAT' ? 'threat' : 'clean'}`;
    div.innerHTML = `<span>${e.file}</span><span>${e.verdict} (${e.threat_score})</span>`;
    wardenFeed.appendChild(div);
  });
}

// ---------- utils ----------
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// check warden status on load in case it's already running server-side
fetch('/api/warden/status').then(r => r.json()).then(d => setWardenUI(d.running));

// ---------- simulate-drop control ----------
const simulateDropInput = document.getElementById('simulateDropInput');
simulateDropInput.addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/warden/simulate-drop', { method: 'POST', body: formData });
    const data = await res.json();
    if (data.error) {
      alert(data.error);
    }
    // On success, the Warden's own watcher picks this up within a couple
    // seconds — the existing pollWardenLog() interval will show it in
    // the Incident Feed automatically, no extra handling needed here.
  } catch (err) {
    alert('Upload failed: ' + err);
  } finally {
    simulateDropInput.value = ''; // allow re-selecting the same file again
  }
});

// ---------- clear log control ----------
document.getElementById('clearLogBtn').addEventListener('click', async () => {
  if (!confirm('Clear the incident log and all cleared/quarantined files? This cannot be undone.')) {
    return;
  }
  await fetch('/api/warden/clear', { method: 'POST' });
  wardenFeed.innerHTML = '<div class="feed-empty">No incidents yet. Activate the Warden and drop a PDF into the watch folder.</div>';
});