// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

const INDENT = 20;                 // pixels per indentation level

const listEl = document.getElementById('connections-list');
let pendingSelectionRecovery = null;
let rootNodeStatistics = null;

/* ----------------------------------------------------
   State
   ---------------------------------------------------- */
function getSelectedConnectionRowId() {
  if (!window.app || typeof window.app.getSelectedConnectionRowId !== 'function') {
    return null;
  }
  return window.app.getSelectedConnectionRowId();
}

function setSelectedConnectionRowId(rowID) {
  if (!window.app || typeof window.app.setSelectedConnectionRowId !== 'function') {
    return;
  }
  window.app.setSelectedConnectionRowId(rowID);
}


/* ----------------------------------------------------
   Helpers
   ---------------------------------------------------- */

// SI units (1 kB = 1000 bytes), 3 significant figures
function byteCountString(bytes) {
  if (bytes < 1) return '';
  const units = ['kB', 'MB', 'GB', 'TB'];
  const divisors = [1e3, 1e6, 1e9, 1e12];
  let i = units.length - 1;
  while (i > 0 && bytes < divisors[i]) i--;
  return (bytes / divisors[i]).toPrecision(3) + ' ' + units[i];
}

// Human-readable "time ago" string in 10-second resolution
function ageString(epochSeconds) {
  if (!epochSeconds || epochSeconds <= 0) return '';
  const age = Math.floor(Date.now() / 1000) - epochSeconds;
  if (age < 10) return 'now';
  if (age < 100) return `${Math.floor(age / 10) * 10} s ago`;
  if (age < 5400) return `${Math.max(2, Math.floor(age / 60))} min ago`;
  if (age < 172800) return `${Math.max(2, Math.floor(age / 3600))} hr ago`;
  if (age < 5184000) return `${Math.max(3, Math.floor(age / 86400))} d ago`;
  return `${Math.max(3, Math.floor(age / 2592000))} mo ago`;
}

// Absolute event time, format depends on how long ago the event was:
//   < 24 h  → HH:MM:SS
//   < 7 d   → Weekday HH:MM  (e.g. "Tue 12:30")
//   ≥ 7 d   → ISO date       (e.g. "2025-11-23")
function absoluteTimeString(epochSeconds) {
  if (!epochSeconds || epochSeconds <= 0) return '';
  const age = Date.now() / 1000 - epochSeconds;
  const d = new Date(epochSeconds * 1000);
  if (age < 86400) {
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  if (age < 604800) {
    const day = d.toLocaleDateString(undefined, { weekday: 'short' });
    const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
    return `${day} ${time}`;
  }
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  return `${y}-${m}-${String(d.getDate()).padStart(2, '0')}`;
}

// Fixed "YYYY-MM-DD HH:MM:SS" in local time — used in the inspector panel.
function fullDateTimeString(epochSeconds) {
  if (!epochSeconds || epochSeconds <= 0) return '';
  const d = new Date(epochSeconds * 1000);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}


function htmlID(id) {
  return 'row-' + id;
}

/* Create the DOM node for a single line */
function createRow(row) {
  const el = document.createElement('div');
  el.className = 'row';
  el.id = htmlID(row.id);
  el.dataset.isExpanded = row.isExpanded ? 'true' : 'false';
  el.dataset.isLeaf = row.isLeaf ? 'true' : 'false';
  el.dataset.isMoreItems = row.isMoreItems ? 'true' : 'false';
  if (row.id === getSelectedConnectionRowId()) {
    el.classList.add('selected');
  }

  // Disclosure triangle
  if (!row.isLeaf) {
    const d = document.createElement('span');
    d.className = 'disclosure';
    if (row.isExpanded) {
      d.classList.add('expanded');
    }
    d.addEventListener('click', e => {
      e.stopPropagation();
      window.app.sendAction('toggleDisclosure', { "id": row.id });
    });
    d.style.marginLeft = `${row.indentationLevel * INDENT}px`;
    el.appendChild(d);
  } else {
    // invisible placeholder keeps spacing the same
    const placeholder = document.createElement('span');
    placeholder.className = 'disclosure spacer';
    placeholder.style.marginLeft = `${row.indentationLevel * INDENT}px`;
    el.appendChild(placeholder);
  }

  // Title
  const title = document.createElement('span');
  if (row.isMoreItems) {
    title.classList.add('clickable'); // ← CSS cursor + hover
    title.addEventListener('click', e => {
      e.stopPropagation();          // prevent the row’s click handler
      // send the disclosure event to the server
      window.app.sendAction('toggleDisclosure', { "id": row.id });
    });
  }
  title.classList.add('title');
  title.textContent = row.title;
  el.appendChild(title);

  if (!row.isMoreItems) {
    // Rule indication / button
    const ruleButton = document.createElement('button');
    ruleButton.classList.add('rule-button');
    ruleButton.onclick = function (event) {
      event.stopPropagation();
      window.app.sendAction('toggleRule', { "id": row.id });
    };
    el.appendChild(ruleButton);

    // indication of different rule action in details
    const detailsButton = document.createElement('button');
    detailsButton.classList.add('details-button');
    detailsButton.onclick = function () {
      window.app.sendAction('toggleDisclosure', { "id": row.id });
    };
    el.appendChild(detailsButton);

    for (const cls of ['total-bytes', 'last-event']) {
      const span = document.createElement('span');
      span.classList.add(cls);
      el.appendChild(span);
    }
    updateStatisticsForRow(el, row.statistics);
  }
  attachRuleButton(el, null); // default state is not sent by initial daemon update
  el.onclick = function () {
    // toggle selection when selected row is clicked
    let row_id = row.id === getSelectedConnectionRowId() ? null : row.id;
    window.app.sendAction('selectRow', { "id": row_id });
  };
  return el;
}


/**
 * Turn a full path into just the file name.
 * @param {string} path
 * @returns {string}
 */
function fileName(path) {
  if (!path) return null;
  const parts = path.split(/[\\/]/);           // split on / or \
  return parts[parts.length - 1];             // last component
}

/**
 * Convert the bit‑mask into an array of protocol names.
 * Bits 0..4 => ICMP, TCP, UDP, SCTP, Other.
 * @param {number} mask
 * @returns {string[]}
 */
function protocolsFromMask(mask) {
  const map = ['ICMP', 'TCP', 'UDP', 'SCTP', 'Other'];
  const res = [];
  for (let i = 0; i < map.length; i++) {
    if (mask & (1 << i)) res.push(map[i]);
  }
  return res;
}

/**
 * Build the "protocol / port" part of the line.
 * Omit everything if the rule allows all protocols and all ports.
 * @param {number} protocolMask
 * @param {string} portString  (e.g. "443" or "80-443")
 * @returns {string}          (e.g. "TCP/443" or "")
 */
function formatProtoPort(protocolMask, portString) {
  const ALL_MASK = 0b11111;            // 31, i.e. every protocol
  const ALL_PORT = /^0-65535$/i;

  if (protocolMask === ALL_MASK && ALL_PORT.test(portString)) {
    return '';                           // nothing to show
  }

  const protos = protocolsFromMask(protocolMask);
  let protoPart = '';
  if (protos.length) protoPart = protos.join('/');

  // skip the port part if it's the full range
  if (ALL_PORT.test(portString)) {
    return protoPart;                    // only protocols if not all
  }

  return protoPart + '/' + portString;
}

/**
 * Map the numeric direction to an arrow string.
 * @param {number} dir 1=out, 2=in, 3=both
 * @returns {string}
 */
function arrowFor(dir) {
  switch (dir) {
    case 1: return '→';
    case 2: return '←';
    case 3: return '↔';
    default: return '→';
  }
}

/**
 * Emoji for the rule action.
 * @param {string} action "allow" or "deny"
 * @returns {string}
 */
function emojiFor(action) {
  return action.toLowerCase() === 'allow' ? '🟢' : '🔴';
}

/* ---------------------  Rendering Code  --------------------- */

/**
 * Turn a single rule object into a <div class="rule"> element.
 * @param {object} rule
 * @returns {HTMLElement}
 */
function renderRule(rule, withEnableButton) {
  const container = document.createElement('div');
  container.className = 'rule';

  if (withEnableButton) {
    // Checkbox
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'rule-enable-checkbox';
    checkbox.checked = !rule.isDisabled;
    checkbox.addEventListener('click', (event) => {
      event.stopPropagation();
    });
    checkbox.addEventListener('change', e => {
      window.app.sendAction('toggleRuleEnabled', { "ruleId": rule.id });
    });
    container.appendChild(checkbox);
  }

  // --- 1. Emoji  ---
  const emoji = document.createElement('span');
  emoji.className = 'emoji';
  emoji.textContent = emojiFor(rule.action);
  container.appendChild(emoji);

  // --- 2. Process name (bold) ---
  const proc = document.createElement('span');
  proc.className = 'process';
  const mainName = fileName(rule.primaryExecutable);
  const viaName = fileName(rule.viaExecutable);
  if (mainName && viaName) {
    proc.textContent = `${mainName} via ${viaName}`;
  } else if (mainName) {
    proc.textContent = mainName;
  } else {
    proc.textContent = "Any Process";
  }
  if (proc.textContent) container.appendChild(proc);

  // --- 3. Arrow ---
  const arrow = document.createElement('span');
  arrow.className = 'arrow';
  arrow.textContent = arrowFor(rule.direction);
  container.appendChild(arrow);

  // --- 4. Host / Domain ---
  const remote = document.createElement('span');
  remote.className = 'host';
  const remotePattern = rule.remotePattern;
  if (remotePattern) {
    switch (remotePattern.type) {
      case 'any':
        remote.textContent = 'Any';
        break;
      case 'localNet':
        remote.textContent = 'Local Network';
        break;
      case 'domains':
        remote.textContent = `domain ${remotePattern.value}`;
        break;
      case 'hosts':
      case 'ipAddresses':
        remote.textContent = remotePattern.value;
        break;
      default:
        remote.textContent = JSON.stringify(remotePattern);
    }
    container.appendChild(remote);
  }

  // --- 5. Protocol / Port ---
  const proto = document.createElement('span');
  proto.className = 'proto';
  const protoText = formatProtoPort(rule.protocol, rule.port);
  if (protoText) {
    proto.textContent = protoText;
    container.appendChild(proto);
  }

  if (typeof rule.id === 'number') {
    container.classList.add('rule-link');
    container.title = 'Show in Rules';
    container.addEventListener('click', () => {
      const rulesTab = document.querySelector('.tab[data-section="rules"]');
      if (rulesTab instanceof HTMLButtonElement) {
        rulesTab.click();
      }
      if (typeof window.selectRuleInRulesSection === 'function') {
        window.selectRuleInRulesSection(rule.id);
      }
    });
  }

  return container;
}

/* ---------------------  Rendering Code  --------------------- */

/**
 * Turn a single blocklist object into a <div class="block"> element.
 * @param {object} entry
 * @returns {HTMLElement}
 */
function renderBlocklistEntry(entry, withEnableButton) {
  const container = document.createElement('div');
  container.className = 'blocklist-entry';

  if (withEnableButton) {
    // Checkbox
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'rule-enable-checkbox';
    checkbox.checked = !entry.isDisabled;
    checkbox.addEventListener('click', (event) => {
      event.stopPropagation();
    });
    checkbox.addEventListener('change', e => {
      window.app.sendAction('toggleBlocklistEntryEnabled', {
        "entryType": entry.entryType,
        "value": entry.value
      });
    });
    container.appendChild(checkbox);
  }

  // Emoji
  const emoji = document.createElement('span');
  emoji.className = 'emoji';
  emoji.textContent = '⛔️';
  container.appendChild(emoji);

  // Value (host / domain / IP)
  const valueSpan = document.createElement('span');
  valueSpan.className = 'blocklist-item';
  valueSpan.textContent = entry.value;
  container.appendChild(valueSpan);

  const names = entry.blocklists.map(entry => entry[1]);
  if (names.length === 1) {
    /* single blocklist – show the name immediately */
    const nameSpan = document.createElement('span');
    nameSpan.className = 'list-info';
    nameSpan.textContent = '(' + names[0] + ')';
    container.appendChild(nameSpan);
  } else if (names.length > 1) {
    /* multiple blocklists – show a clickable counter + tooltip */
    const counterSpan = document.createElement('span');
    counterSpan.className = 'list-info';
    counterSpan.textContent = `(${names.length} blocklists)`;
    counterSpan.title = names.join(', '); // tooltip with all names
    counterSpan.addEventListener('click', () => {
      const list = container.querySelector('.blocklist-names');
      list.style.display = list.style.display === 'none' ? 'block' : 'none';
    });
    container.appendChild(counterSpan);

    /* hidden list that can be toggled */
    const ul = document.createElement('ul');
    ul.className = 'blocklist-names';
    names.forEach(name => {
      const li = document.createElement('li');
      li.textContent = name;
      ul.appendChild(li);
    });
    container.appendChild(ul);
  }
  /* If no blocklist entry (unlikely but for safety) we just leave the line as is. */
  if (entry && entry.entryType && entry.value) {
    const firstBlocklist = Array.isArray(entry.blocklists) && entry.blocklists.length > 0
      ? entry.blocklists[0]
      : null;
    const targetBlocklistId = Array.isArray(firstBlocklist) ? Number(firstBlocklist[0]) : null;
    container.classList.add('blocklist-entry-link');
    container.title = 'Show in Blocklist';
    container.addEventListener('click', () => {
      if (typeof window.selectBlocklistEntryInBlocklist === 'function') {
        window.selectBlocklistEntryInBlocklist(
          entry.entryType,
          entry.value,
          Number.isFinite(targetBlocklistId) ? targetBlocklistId : null,
        );
      }
    });
  }
  return container;
}

/* ----------------------------------------------------------
 Utility: maps the common protocol numbers to names
 ---------------------------------------------------------- */
const PROTOCOL_MAP = {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  58: 'ICMPv6',
  132: 'SCTP'
};

/* ---------- tiny helper --------------------------------------- */
/**
 * Append a line in the form "label: value" to the parent element.
 *
 * @param {HTMLElement} parent  The element that will receive the new line.
 * @param {string}     label   Text before the colon.
 * @param {string}     value   Text after the colon (escaped automatically).
 * @param {object}     opts    Optional formatting options:
 *   - path (boolean)   → wrap the value in a <span class="path">
 *   - via (boolean)    → prepend " via " (wrapped in <span class="via">)
 */
function addKeyValueLine(parent, label, value, opts = {}) {
  if (!value) return;                     // nothing to render

  const line = document.createElement('div');
  line.className = 'info-line';

  const field = document.createElement('span');
  field.className = 'field';
  field.textContent = label + ': ';
  line.appendChild(field);

  const val = document.createElement('span');
  val.className = 'value';

  if (opts.path) {
    const p = document.createElement('span');
    p.className = 'path';
    p.textContent = value;
    val.appendChild(p);
  } else if (opts.domain) {
    val.textContent = value;
    val.classList.add('domain-name');
  } else {
    val.textContent = value;
  }

  if (opts.via) {
    const via = document.createElement('span');
    via.className = 'via';
    via.textContent = ' via ';
    val.appendChild(via);
    const viaPath = document.createElement('span');
    viaPath.className = 'path';
    viaPath.textContent = opts.viaValue;
    val.appendChild(viaPath);
  }

  line.appendChild(val);
  parent.appendChild(line);
}

/* ---------- inspector statistics section ---------------------- */

// Read the four statistics values cached in the row's DOM spans.
function statisticsFromRowEl(rowEl) {
  const bytesSpan = rowEl?.querySelector('.total-bytes');
  const eventSpan = rowEl?.querySelector('.last-event');
  return {
    bytesReceived: Number(bytesSpan?.dataset.bytesRx   || 0),
    bytesSent:     Number(bytesSpan?.dataset.bytesTx   || 0),
    lastAllowed:   Number(eventSpan?.dataset.lastAllowed || 0),
    lastBlocked:   Number(eventSpan?.dataset.lastBlocked || 0),
  };
}

function renderInspectorStatistics(statistics) {
  const container = document.createElement('div');
  container.className = 'inspector-statistics';
  addKeyValueLine(container, 'Bytes received', byteCountString(statistics.bytesReceived));
  addKeyValueLine(container, 'Bytes sent',     byteCountString(statistics.bytesSent));
  addKeyValueLine(container, 'Last allowed',   fullDateTimeString(statistics.lastAllowed));
  addKeyValueLine(container, 'Last denied',    fullDateTimeString(statistics.lastBlocked));
  return container;
}

function updateInspectorStatistics(statistics) {
  const existing = document.querySelector('#rules .inspector-statistics');
  if (!existing) return;
  existing.replaceWith(renderInspectorStatistics(statistics));
}

/* ---------- main formatter ------------------------------------ */
function renderRowInspector(data) {
  const container = document.createElement('div');
  container.className = 'row-inspector';

  if (data.row === null) {
    const line = document.createElement('div');
    line.className = 'info-line';
    const field = document.createElement('span');
    field.className = 'field';
    field.textContent = 'All Processes';
    line.appendChild(field);
    container.appendChild(line);
    return container;
  }

  /* Process / via --------------------------------------------- */
  if (data.primaryExecutable) {
    addKeyValueLine(
      container,
      'Process',
      data.primaryExecutable,
      { path: true, via: !!data.viaExecutable, viaValue: data.viaExecutable }
    );
  }

  /* Direction ------------------------------------------------- */
  if (typeof data.isInbound === 'boolean') {
    addKeyValueLine(container, 'Direction', data.isInbound ? 'Inbound' : 'Outbound');
  }

  /* Remote ----------------------------------------------------- */
  addKeyValueLine(container, 'Remote', data.remoteName?.value, { domain: data.remoteName?.type == 'domain' });

  /* IP address ----------------------------------------------- */
  addKeyValueLine(container, 'Remote Address', data.ipAddress);

  /* Port / Protocol ------------------------------------------- */
  const protoName = PROTOCOL_MAP[data.protocol] || `Proto ${data.protocol}`;

  if (data.port && data.port !== 0) {
    addKeyValueLine(container, 'Port', `${protoName} ${data.port}`);
  } else if (data.port === 0) {
    addKeyValueLine(container, 'Protocol', protoName);
  }

  return container;
}

function setRowSelected(rowID) {
  const selectedConnectionRowId = getSelectedConnectionRowId();
  // deselecte current selection
  if (selectedConnectionRowId !== null) {
    const selected = document.getElementById(htmlID(selectedConnectionRowId));
    if (selected !== null) {
      selected.classList.remove('selected');
    }
  }
  setSelectedConnectionRowId(rowID);
  // select new
  if (rowID !== null) {
    const selected = document.getElementById(htmlID(rowID));
    if (selected !== null) {
      selected.classList.add('selected');
    }
  }
}

function parseRowIdFromElement(el) {
  if (!el || !el.id || !el.id.startsWith('row-')) {
    return null;
  }
  const idText = el.id.slice(4);
  const id = Number(idText);
  if (!Number.isFinite(id)) {
    return null;
  }
  return id;
}

function recoverConnectionSelection(preferredId = null) {
  const recovery = pendingSelectionRecovery;
  if (!recovery) {
    return false;
  }

  const candidates = [];
  if (preferredId !== null && preferredId !== undefined) {
    candidates.push(preferredId);
  }
  if (recovery.insertedFirstId !== null && recovery.insertedFirstId !== undefined) {
    candidates.push(recovery.insertedFirstId);
  }
  if (recovery.previousId !== null && recovery.previousId !== undefined) {
    candidates.push(recovery.previousId);
  }
  if (recovery.nextId !== null && recovery.nextId !== undefined) {
    candidates.push(recovery.nextId);
  }

  let selectedId = null;
  for (const candidate of candidates) {
    if (document.getElementById(htmlID(candidate))) {
      selectedId = candidate;
      break;
    }
  }

  setRowSelected(selectedId);
  window.app.sendAction('selectRow', { id: selectedId });
  pendingSelectionRecovery = null;
  return true;
}

function navigateConnectionsSelection(delta) {
  if (delta !== 1 && delta !== -1) {
    return false;
  }
  const rows = Array.from(listEl.querySelectorAll('.row'))
    .filter((row) => row.dataset.isAnimatingOut !== 'true');
  if (rows.length === 0) {
    return false;
  }
  const selectedId = getSelectedConnectionRowId();
  let currentIndex = rows.findIndex((row) => parseRowIdFromElement(row) === selectedId);
  if (currentIndex < 0) {
    currentIndex = delta > 0 ? -1 : rows.length;
  }
  const nextIndex = Math.max(0, Math.min(rows.length - 1, currentIndex + delta));
  const nextRow = rows[nextIndex];
  const nextId = parseRowIdFromElement(nextRow);
  if (nextId === null) {
    return false;
  }
  window.app.sendAction('selectRow', { id: nextId });
  nextRow.scrollIntoView({ block: 'nearest' });
  return true;
}

window.navigateConnectionsSelection = navigateConnectionsSelection;

function getSelectedConnectionRowElement() {
  const selectedId = getSelectedConnectionRowId();
  if (selectedId === null || selectedId === undefined) {
    return null;
  }
  return document.getElementById(htmlID(selectedId));
}

function canToggleDisclosureForRow(rowEl) {
  if (!rowEl) {
    return false;
  }
  return rowEl.dataset.isLeaf !== 'true' || rowEl.dataset.isMoreItems === 'true';
}

function maybeToggleConnectionDisclosureForKey(key) {
  const rowEl = getSelectedConnectionRowElement();
  if (!rowEl) {
    return false;
  }
  if (!canToggleDisclosureForRow(rowEl)) {
    return false;
  }

  const id = parseRowIdFromElement(rowEl);
  if (id === null) {
    return false;
  }

  const isMoreItems = rowEl.dataset.isMoreItems === 'true';
  const isExpanded = rowEl.dataset.isExpanded === 'true';

  if (key === ' ' || key === 'Spacebar') {
    window.app.sendAction('toggleDisclosure', { id });
    return true;
  }

  if (key === 'ArrowRight') {
    if (!isExpanded) {
      window.app.sendAction('toggleDisclosure', { id });
      return true;
    }
    return false;
  }

  if (key === 'ArrowLeft') {
    if (isMoreItems) {
      return false;
    }
    if (isExpanded) {
      window.app.sendAction('toggleDisclosure', { id });
      return true;
    }
    return false;
  }

  return false;
}

window.maybeToggleConnectionDisclosureForKey = maybeToggleConnectionDisclosureForKey;

// ----------------------------------------------------
// Last-event display: age strings and Alt-key absolute time
// ----------------------------------------------------

let altKeyHeld = false;

function renderLastEventSpans() {
  for (const span of document.querySelectorAll('.last-event')) {
    const epoch = Number(span.dataset.epochSeconds);
    const text = altKeyHeld ? absoluteTimeString(epoch) : ageString(epoch);
    span.style.visibility = text === '' ? 'hidden' : 'visible';
    span.textContent = text;
  }
}

// Refresh every 10 s — keeps age buckets current and also catches format
// boundary crossings while Alt is held (e.g. event crossing the 24 h mark).
setInterval(renderLastEventSpans, 10000);

// Alt held → absolute event time; release or window blur → age string.
document.addEventListener('keydown', (e) => {
  if (e.key === 'Alt' && !altKeyHeld) {
    altKeyHeld = true;
    renderLastEventSpans();
  }
});
document.addEventListener('keyup', (e) => {
  if (e.key === 'Alt') {
    altKeyHeld = false;
    renderLastEventSpans();
  }
});
window.addEventListener('blur', () => {
  if (altKeyHeld) {
    altKeyHeld = false;
    renderLastEventSpans();
  }
});

// Called by app.js whenever the sort mode changes so that the bytes column
// can switch between rx, tx, or rx+tx without waiting for a statistics push.
window.refreshConnectionsBytes = function () {
  for (const span of document.querySelectorAll('.total-bytes')) {
    const rx = Number(span.dataset.bytesRx || 0);
    const tx = Number(span.dataset.bytesTx || 0);
    const text = currentBytesDisplay(rx, tx);
    span.style.visibility = text === '' ? 'hidden' : 'visible';
    span.textContent = text;
  }
};

// ----------------------------------------------------
// WebSocket message handlers
// ----------------------------------------------------

function handleClear() {
  pendingSelectionRecovery = null;
  listEl.innerHTML = '';
}

function handleInsertRows(afterID, rows, animate) {
  const frag = document.createDocumentFragment();
  let elements = [];
  let targetHeight;
  for (const row of rows) {
    // If a ghost element (isAnimatingOut) with the same id already exists in
    // the DOM, remove it immediately. Otherwise getElementById would return the
    // ghost instead of the newly inserted element, corrupting all subsequent
    // lookup-based operations (removes, moves, updates) for this row id.
    const existing = document.getElementById(htmlID(row.id));
    if (existing?.dataset.isAnimatingOut) {
      existing.remove();
    }
    const el = createRow(row);
    if (animate) {
      targetHeight = el.style.height;   // height is set explicitly on row
      el.style.height = '0';
      el.style.opacity = '0';
      elements.push(el);
    }
    frag.appendChild(el);
  }
  if (afterID !== null) {
    const afterNode = document.getElementById(htmlID(afterID));
    listEl.insertBefore(frag, afterNode.nextSibling);
  } else {
    listEl.insertBefore(frag, listEl.firstChild);
  }

  if (pendingSelectionRecovery && rows.length > 0) {
    const firstInsertedId = rows[0].id;
    const insertionMatchesRecovery
      = (afterID === null && pendingSelectionRecovery.previousId === null)
      || afterID === pendingSelectionRecovery.previousId;
    if (insertionMatchesRecovery) {
      pendingSelectionRecovery.insertedFirstId = firstInsertedId;
      recoverConnectionSelection(firstInsertedId);
    }
  }

  if (animate) {
    void listEl.offsetHeight; // read to trigger re‑flow
    for (const el of elements) {
      el.style.height = targetHeight;
      el.style.opacity = '1';
    }
    elements[0].addEventListener('transitionend', e => {
      for (const el of elements) {
        el.style.height = '';
        el.style.opacity = '';
      }
    }, { once: true });
  }
}


function handleRemoveRows(startID, endID) {
  let lastElement = document.getElementById(htmlID(endID));
  let firstElement = document.getElementById(htmlID(startID));
  if (!firstElement) {
    console.log(`could not find id=${startID} for removal`);
    return; // we cannot remove anything
  }
  let elements = [];
  let el = firstElement;
  const currentSelectedId = getSelectedConnectionRowId();
  let selectedIsRemoved = false;
  while (el) {
    const id = parseRowIdFromElement(el);
    if (id !== null && id === currentSelectedId) {
      selectedIsRemoved = true;
    }
    const next = el.nextSibling;
    elements.push(el);
    el.style.height = '0';
    el.style.opacity = '0';
    el.dataset.isAnimatingOut = 'true';
    if (el == lastElement) {
      break;
    }
    el = next;
  }
  if (selectedIsRemoved) {
    pendingSelectionRecovery = {
      previousId: parseRowIdFromElement(firstElement.previousElementSibling),
      nextId: parseRowIdFromElement(lastElement ? lastElement.nextElementSibling : null),
      insertedFirstId: null,
    };
  }
  // Guard against bubbled transitionend events from child elements (e.g. the
  // .disclosure child animates `transform` and its transitionend bubbles up).
  // With { once: true } any bubbled event would consume the listener early and
  // leave the ghost elements permanently in the DOM.
  const onRemoveTransitionEnd = (e) => {
    if (e.target !== firstElement) return;
    firstElement.removeEventListener('transitionend', onRemoveTransitionEnd);
    for (const el of elements) {
      el.remove();
    }
    if (pendingSelectionRecovery) {
      recoverConnectionSelection();
    }
  };
  firstElement.addEventListener('transitionend', onRemoveTransitionEnd);
}

function handleMoveRows(startID, endID, targetID) {
  let lastElement = document.getElementById(htmlID(endID));
  let firstElement = document.getElementById(htmlID(startID));
  if (!firstElement) {
    console.log(`could not find id=${startID} for move`);
    return; // we cannot move anything
  }
  // FLIP animation (First/Last/Invert/Play): snapshot positions before the
  // DOM move, apply the move, compute the delta, set a compensating transform
  // so each row visually stays put, then release the transform via a CSS
  // transition so the rows glide to their new positions.
  const rectsBefore = new Map();
  for (const el of listEl.children) {
    if (!el.dataset.isAnimatingOut) {
      rectsBefore.set(el.id, el.getBoundingClientRect());
    }
  }
  // modify DOM
  let frag = document.createDocumentFragment();
  let el = firstElement;
  while (el) {
    const next = el.nextSibling;
    // Skip ghost elements that are fading out: moving them through a
    // DocumentFragment cancels their CSS transition. In Firefox (spec-
    // compliant) transitionend never fires afterwards, so the ghost stays
    // in the DOM permanently and creates a duplicate row with the same id.
    if (!el.dataset.isAnimatingOut) {
      frag.appendChild(el);
    }
    if (el == lastElement) {
      break;
    }
    el = next;
  }
  let targetElement = null;
  if (targetID !== null) {
    targetElement = document.getElementById(htmlID(targetID));
    listEl.insertBefore(frag, targetElement.nextSibling);
  } else {
    listEl.insertBefore(frag, listEl.firstChild);
  }

  // capture positions after modifying DOM
  const rectsAfter = new Map();
  for (const el of listEl.children) {
    if (!el.dataset.isAnimatingOut) {
      rectsAfter.set(el.id, el.getBoundingClientRect());
    }
  }

  for (const el of listEl.children) {
    const id = el.id;
    const before = rectsBefore.get(id);
    const after = rectsAfter.get(id);
    if (!before || !after) continue;
    const deltaX = before.left - after.left;
    const deltaY = before.top - after.top;
    if (deltaX || deltaY) {
      el.style.transform = `translate(${deltaX}px, ${deltaY}px)`;
      // force layout so the browser renders the model in the
      // transformed state.
      void el.offsetHeight;

      el.style.transition = 'transform 0.5s ease';
      el.style.transform = '';     // Back to natural position

      el.addEventListener('transitionend', e => {
        el.style.transition = '';
      }, { once: true });
    }
  }

}

function updateElement(rowEl, selector, text) {
  let span = rowEl.querySelector(selector);
  if (span === null) {
    return;
  }
  span.style.visibility = text == '' ? 'hidden' : 'visible';
  span.textContent = text;
}

// Return the byte string appropriate for the current sort mode.
function currentBytesDisplay(rx, tx) {
  const sort = window.app?.getConnectionsSort?.() ?? '';
  if (sort === 'totalDataSent') return byteCountString(tx);
  if (sort === 'totalDataReceived') return byteCountString(rx);
  return byteCountString(rx + tx);
}

function updateStatisticsForRow(rowEl, statistics) {
  const rx = statistics.bytesReceived || 0;
  const tx = statistics.bytesSent || 0;
  const totalBytesSpan = rowEl.querySelector('.total-bytes');
  if (totalBytesSpan) {
    totalBytesSpan.dataset.bytesRx = rx;
    totalBytesSpan.dataset.bytesTx = tx;
    updateElement(rowEl, '.total-bytes', currentBytesDisplay(rx, tx));
  }

  const lastAllowed = statistics.lastAllowed || 0;
  const lastBlocked = statistics.lastBlocked || 0;
  const lastEvent = Math.max(lastAllowed, lastBlocked);
  const lastEventSpan = rowEl.querySelector('.last-event');
  if (lastEventSpan) {
    lastEventSpan.dataset.epochSeconds = lastEvent;
    lastEventSpan.dataset.lastAllowed = lastAllowed;
    lastEventSpan.dataset.lastBlocked = lastBlocked;
    const text = ageString(lastEvent);
    lastEventSpan.style.visibility = text === '' ? 'hidden' : 'visible';
    lastEventSpan.textContent = text;
    const diff = Math.abs(lastAllowed - lastBlocked);
    const bothRecent = lastAllowed > 0 && lastBlocked > 0 && diff <= 5;
    lastEventSpan.classList.toggle('recent-allow',  !bothRecent && lastAllowed > lastBlocked + 5);
    lastEventSpan.classList.toggle('recent-deny',   !bothRecent && lastBlocked > lastAllowed + 5);
    lastEventSpan.classList.toggle('recent-mixed',  bothRecent);
  }
}

function handleUpdateStatistics(statistics) {
  const selectedId = getSelectedConnectionRowId();
  for (const statisticsUpdate of statistics) {
    if (statisticsUpdate.id === 0) {
      rootNodeStatistics = statisticsUpdate.statistics;
      if (selectedId === null) {
        updateInspectorStatistics(statisticsUpdate.statistics);
      }
      continue;
    }
    let rowEl = document.getElementById(htmlID(statisticsUpdate.id));
    if (rowEl !== null) {
      updateStatisticsForRow(rowEl, statisticsUpdate.statistics);
    }
    if (statisticsUpdate.id === selectedId) {
      updateInspectorStatistics(statisticsUpdate.statistics);
    }
  }
}

function handleUpdateRows(rows) {
  for (const row of rows) {
    let rowEl = document.getElementById(htmlID(row.id));
    if (rowEl !== null) {
      rowEl.dataset.isExpanded = row.isExpanded ? 'true' : 'false';
      rowEl.dataset.isLeaf = row.isLeaf ? 'true' : 'false';
      rowEl.dataset.isMoreItems = row.isMoreItems ? 'true' : 'false';
      rowEl.querySelector('.title').textContent = row.title;
      const d = rowEl.querySelector('.disclosure');
      if (d) {
        if (row.isExpanded) {
          d.classList.add('expanded');
        } else {
          d.classList.remove('expanded');
        }
      }
    }
  }
}

function attachRuleButton(rowEl, row) {
  const ruleButton = rowEl.querySelector('.rule-button');
  if (ruleButton === null) {
    return;
  }
  const detailsButton = rowEl.querySelector('.details-button');
  if (detailsButton === null) {
    return;
  }
  let buttonText = '<span style="filter: opacity(50%)">🟢</span>';
  let detailsButtonIsVisible = false;
  if (row !== null) {
    let isAllow = false;
    switch (row.rule) {
      case 'allowByDefault':
        isAllow = true;
        buttonText = '<span style="filter: opacity(50%)">🟢</span>';
        break;
      case 'allowByRule':
        buttonText = '🟢';
        isAllow = true;
        break;
      case 'denyByDefault': buttonText = '<span style="filter: opacity(50%)">🔴</span>'; break;
      case 'denyByRule': buttonText = '🔴'; break;
      case 'denyByBlocklist': buttonText = '⛔️'; break;
    }
    if (row.detailsDiffer) {
      let ref = isAllow ? 'details-differ-red' : 'details-differ-green';
      detailsButton.innerHTML = `<svg><use href="#${ref}"></use></svg>`;
      detailsButtonIsVisible = true;
    }
  }
  if (detailsButtonIsVisible) {
    detailsButton.style.visibility = 'visible';
  } else {
    detailsButton.innerHTML = '<svg><use href="#details-differ-green"></use></svg>';
    detailsButton.style.visibility = 'hidden';
  }
  ruleButton.innerHTML = buttonText;
}

function handleUpdateRuleButtons(rows) {
  for (const row of rows) {
    let el = document.getElementById(htmlID(row.rowId));
    attachRuleButton(el, row);
  }
}

// Per-row flash state: rowId -> { allow: {start} | null, deny: {start} | null, rafId: number | null }
const _flashState = new Map();
const FLASH_DURATION = 3000; // ms

// Derive the resting background of the .last-event cell from its current CSS classes,
// composited over white. Must stay in sync with the .recent-allow / .recent-deny rules in
// connections.css.
function _restRgb(cell) {
  if (cell.classList.contains('recent-allow')) {
    // rgba(0, 160, 60, 0.15) over white
    return { r: 217, g: 241, b: 226 };
  }
  if (cell.classList.contains('recent-deny')) {
    // rgba(200, 0, 0, 0.13) over white
    return { r: 248, g: 222, b: 222 };
  }
  if (cell.classList.contains('recent-mixed')) {
    // rgba(180, 140, 0, 0.18) over white
    return { r: 240, g: 234, b: 209 };
  }
  return { r: 255, g: 255, b: 255 };
}

function flashRow(rowId, type) {
  const el = document.getElementById(htmlID(rowId));
  if (!el) return;
  const cell = el.querySelector('.last-event');
  if (!cell) return;

  const now = performance.now();
  let state = _flashState.get(rowId);
  if (!state) {
    state = { allow: null, deny: null, rafId: null };
    _flashState.set(rowId, state);
  }

  // Retrigger: reset this channel (cancels fade-out, restarts from full intensity)
  state[type] = { start: now };
  if (state.rafId !== null) {
    cancelAnimationFrame(state.rafId);
    state.rafId = null;
  }

  function tick() {
    const t = performance.now();
    let ia = 0, id = 0; // allow intensity, deny intensity

    if (state.allow) {
      const p = (t - state.allow.start) / FLASH_DURATION;
      if (p < 1) { ia = (1 - p) * 0.7; } else { state.allow = null; }
    }
    if (state.deny) {
      const p = (t - state.deny.start) / FLASH_DURATION;
      if (p < 1) { id = (1 - p) * 0.7; } else { state.deny = null; }
    }

    if (ia === 0 && id === 0) {
      cell.style.removeProperty('background-color');
      state.rafId = null;
      _flashState.delete(rowId);
      return;
    }

    // Additive blend: green channel from allow, red channel from deny → yellow when both active
    const flashR = Math.min(255, Math.round(255 * id + 17 * ia));
    const flashG = Math.min(255, Math.round(255 * ia + 17 * id));
    const flashB = Math.min(255, Math.round(17 * (ia + id)));
    const a = Math.max(ia, id); // 0..0.7

    // Composite flash over the current resting background (re-read each frame since
    // recent-allow / recent-deny classes may change while the animation is running)
    const { r: rr, g: rg, b: rb } = _restRgb(cell);
    const R = Math.round(flashR * a + rr * (1 - a));
    const G = Math.round(flashG * a + rg * (1 - a));
    const B = Math.round(flashB * a + rb * (1 - a));
    cell.style.backgroundColor = `rgb(${R},${G},${B})`;
    state.rafId = requestAnimationFrame(tick);
  }

  state.rafId = requestAnimationFrame(tick);
}

function isConnectionsSectionVisible() {
  const section = document.querySelector('.section[data-section="connections"]');
  return !!section && section.classList.contains('is-active');
}

function handleEvents(events) {
  if (!isConnectionsSectionVisible()) {
    return;
  }
  for (const event of events) {
    switch (event.type) {
      case 'traffic':
        flashRow(event.rowId, 'allow');
        break;
      case 'blocked':
        flashRow(event.rowId, 'deny');
        break;
      default:
        console.warn('Unknown event from server', JSON.stringify(event));
    }
  }
}

function handleSetInspector(msg) {
  setRowSelected(msg.row);
  const data = msg.data;

  const rulesTable = document.getElementById('rules');
  rulesTable.innerHTML = '';                     // clear old content

  const rowInspectorEl = renderRowInspector(msg);
  rulesTable.appendChild(rowInspectorEl);
  if (msg.row !== null) {
    // Live stats for a selected row are kept current via handleUpdateStatistics.
    const rowEl = document.getElementById(htmlID(msg.row));
    rowInspectorEl.appendChild(renderInspectorStatistics(statisticsFromRowEl(rowEl)));
  } else if (rootNodeStatistics !== null) {
    // Show aggregate statistics for the whole list when nothing is selected.
    rowInspectorEl.appendChild(renderInspectorStatistics(rootNodeStatistics));
  }

  const headline = document.createElement('div');
  headline.className = 'covering-rules-headline';
  headline.innerHTML = 'Matching Rules';
  rulesTable.appendChild(headline);

  const defaultRule = document.createElement('div');
  defaultRule.className = 'rule';
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.className = 'rule-enable-checkbox';
  checkbox.checked = true;
  checkbox.disabled = true;
  defaultRule.appendChild(checkbox);

  const emoji = document.createElement('span');
  emoji.className = 'emoji';
  emoji.textContent = emojiFor(msg.defaultAction);
  defaultRule.appendChild(emoji);

  const text = document.createElement('span');
  text.className = 'host';
  if (msg.defaultAction.toLowerCase() === 'allow') {
    text.textContent = "Default: Allow any connection";
  } else {
    text.textContent = "Default: Deny any connection";
  }
  defaultRule.appendChild(text);

  defaultRule.classList.add('inactive');
  rulesTable.appendChild(defaultRule);
  let lastActiveLine = defaultRule;

  data.coveringRules.forEach((r, i) => {
    let line;
    if (r.type == 'rule') {
      line = renderRule(r, true);
    } else if (r.type == 'blocklist') {
      line = renderBlocklistEntry(r, true);
    }
    if (!r.isDisabled) {
      lastActiveLine = line;
    }
    line.classList.add('inactive');
    rulesTable.appendChild(line);
  });
  lastActiveLine.classList.remove('inactive');

  if (data.relatedRules && data.relatedRules.length > 0) {
    const headline = document.createElement('div');
    headline.className = 'related-rules-headline';
    headline.innerHTML = 'Related Rules';
    rulesTable.appendChild(headline);
    data.relatedRules.forEach(r => {
      let line;
      if (r.type == 'rule') {
        line = renderRule(r, false);
      } else if (r.type == 'blocklist') {
        line = renderBlocklistEntry(r, false);
      }
      line.classList.add('inactive'); // related rules are not active for the line
      rulesTable.appendChild(line);
    });
  }
}
