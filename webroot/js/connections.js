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
  if (age < 10) return window._localization.t('age-now');
  if (age < 100) return window._localization.t('age-seconds', { n: Math.floor(age / 10) * 10 });
  if (age < 5400) return window._localization.t('age-minutes', { n: Math.max(2, Math.floor(age / 60)) });
  if (age < 172800) return window._localization.t('age-hours',   { n: Math.max(2, Math.floor(age / 3600)) });
  if (age < 5184000) return window._localization.t('age-days',   { n: Math.max(3, Math.floor(age / 86400)) });
  return window._localization.t('age-months', { n: Math.max(3, Math.floor(age / 2592000)) });
}
window.ageString = ageString;

// Absolute event time, format depends on how long ago the event was:
//   < 24 h  → HH:MM:SS
//   < 7 d   → Weekday HH:MM  (e.g. "Tue 12:30")
//   ≥ 7 d   → date only      (e.g. "2025-11-23")
// Uses the same locale preferences as formatDateTime() (datetime.js).
function absoluteTimeString(epochSeconds) {
  if (!epochSeconds || epochSeconds <= 0) return '';
  const age = Date.now() / 1000 - epochSeconds;
  const d = new Date(epochSeconds * 1000);
  const prefs = window.getDtPrefs();
  if (age < 86400) {
    return window._fmtTime(d, prefs, true);
  }
  if (age < 604800) {
    const day = d.toLocaleDateString(undefined, { weekday: 'short' });
    return `${day} ${window._fmtTime(d, prefs, false)}`;
  }
  return window._fmtDate(d, prefs);
}

// Full date+time in local time — used in the inspector panel.
function fullDateTimeString(epochSeconds) {
  return window.formatDateTime(epochSeconds);
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
    el.classList.add('is-selected');
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

  const ruleCol = document.createElement('span');
  ruleCol.classList.add('rule-col');
  el.appendChild(ruleCol);

  if (row.isMoreItems) {
    // Placeholder keeps alignment with the rule-button column in other rows
    const placeholder = document.createElement('span');
    placeholder.classList.add('rule-button-placeholder');
    ruleCol.appendChild(placeholder);

    // details-differ button (shown when sub-rows have differing verdicts)
    const detailsButton = document.createElement('button');
    detailsButton.classList.add('details-button');
    detailsButton.onclick = function (event) {
      event.stopPropagation();
      window.app.sendAction('toggleDisclosure', { "id": row.id, "expandToDifferingDetail": true });
    };
    ruleCol.appendChild(detailsButton);

    // Placeholders keep alignment with traffic/activity columns in other rows
    for (const cls of ['total-bytes', 'last-event']) {
      const span = document.createElement('span');
      span.classList.add(cls);
      el.appendChild(span);
    }
  } else {
    // Rule indication / button
    const ruleButton = document.createElement('button');
    ruleButton.classList.add('rule-button');
    ruleButton.onclick = function (event) {
      event.stopPropagation();
      window.app.sendAction('toggleRule', { "id": row.id });
    };
    ruleCol.appendChild(ruleButton);

    // indication of different rule action in details
    const detailsButton = document.createElement('button');
    detailsButton.classList.add('details-button');
    detailsButton.onclick = function (event) {
      event.stopPropagation();
      window.app.sendAction('toggleDisclosure', { "id": row.id, "expandToDifferingDetail": true });
    };
    ruleCol.appendChild(detailsButton);

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
  let suffix;
  switch (dir) {
    case 1: suffix = 'outgoing'; break;
    case 2: suffix = 'incoming'; break;
    case 3: suffix = 'bidirectional'; break;
    default: suffix = 'outgoing';
  }
  return `<svg width="18" height="18" fill="currentColor"><use href="#rule-${suffix}"/></svg>`;
}

/**
 * Emoji for the rule action.
 * @param {string} action "allow" or "deny"
 * @returns {string}
 */
function emojiFor(action) {
  const suffix = action.toLowerCase() === 'allow' ? 'allow' : 'deny';
  return `<svg width="14" height="14"><use href="#rule-${suffix}"/></svg>`;
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
    checkbox.title = rule.isDisabled ? window._localization.t('disabled') : window._localization.t('enabled');
    checkbox.addEventListener('click', (event) => {
      event.stopPropagation();
    });
    checkbox.addEventListener('change', e => {
      if (rule.id < 0 && !rule.isDisabled) {
        const confirmed = confirm(window._localization.t('confirm-disable-factory-rule'));
        if (!confirmed) { checkbox.checked = true; return; }
      }
      window.app.sendAction('setRuleDisabled', { ruleId: rule.id, isDisabled: !rule.isDisabled });
    });
    container.appendChild(checkbox);
  }

  // --- 1. Emoji  ---
  const emoji = document.createElement('span');
  emoji.className = 'emoji';
  emoji.innerHTML = emojiFor(rule.action);
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
    proc.textContent = window._localization.t('any-process');
  }
  if (proc.textContent) container.appendChild(proc);

  // --- 3. Arrow ---
  const arrow = document.createElement('span');
  arrow.className = 'arrow';
  arrow.innerHTML = arrowFor(rule.direction);
  container.appendChild(arrow);

  // --- 4. Host / Domain ---
  const remote = document.createElement('span');
  remote.className = 'host';
  const remotePattern = rule.remotePattern;
  if (remotePattern) {
    switch (remotePattern.type) {
      case 'any':
        remote.textContent = window._localization.t('remote-any');
        break;
      case 'localNet':
        remote.textContent = window._localization.t('remote-local-network');
        break;
      case 'domains':
        remote.textContent = window._localization.t('remote-domain', { value: remotePattern.value });
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
    container.title = window._localization.t('show-in-rules');
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
 * Append .list-info elements describing the containing blocklists to `container`.
 * `names` is an already-resolved array of blocklist name strings.
 * Used by both connections.js (renderBlocklistEntry) and blocklists.js (renderEntryRow).
 */
function appendBlocklistNamesInfo(container, names) {
  if (names.length === 1) {
    const nameSpan = document.createElement('span');
    nameSpan.className = 'list-info';
    nameSpan.textContent = '(' + names[0] + ')';
    container.appendChild(nameSpan);
  } else if (names.length > 1) {
    const ul = document.createElement('ul');
    ul.className = 'blocklist-names';
    names.forEach(name => {
      const li = document.createElement('li');
      li.textContent = name;
      ul.appendChild(li);
    });
    const counterSpan = document.createElement('span');
    counterSpan.className = 'list-info';
    counterSpan.textContent = window._localization.t('n-blocklists', { n: names.length });
    counterSpan.title = names.join(', ');
    counterSpan.addEventListener('click', () => {
      ul.style.display = ul.style.display === 'none' ? 'block' : 'none';
    });
    container.appendChild(counterSpan);
    container.appendChild(ul);
  }
}
window.appendBlocklistNamesInfo = appendBlocklistNamesInfo;

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
    checkbox.title = entry.isDisabled ? window._localization.t('disabled') : window._localization.t('enabled');
    checkbox.addEventListener('click', (event) => {
      event.stopPropagation();
    });
    checkbox.addEventListener('change', e => {
      window.app.sendAction('setBlocklistEntryDisabled', {
        entryType: entry.entryType,
        value: entry.value,
        isDisabled: !entry.isDisabled,
      });
    });
    container.appendChild(checkbox);
  }

  // Emoji
  const emoji = document.createElement('span');
  emoji.className = 'emoji';
  emoji.innerHTML = '<svg width="12" height="12"><use href="#rule-blocklist"/></svg>';
  container.appendChild(emoji);

  // Value (host / domain / IP)
  const valueSpan = document.createElement('span');
  valueSpan.className = 'blocklist-item';
  valueSpan.textContent = entry.value;
  container.appendChild(valueSpan);

  appendBlocklistNamesInfo(container, entry.blocklists.map(e => e[1]));
  /* If no blocklist entry (unlikely but for safety) we just leave the line as is. */
  if (entry && entry.entryType && entry.value) {
    const firstBlocklist = Array.isArray(entry.blocklists) && entry.blocklists.length > 0
      ? entry.blocklists[0]
      : null;
    const targetBlocklistId = Array.isArray(firstBlocklist) ? Number(firstBlocklist[0]) : null;
    container.classList.add('blocklist-entry-link');
    container.title = window._localization.t('show-in-blocklist');
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

  const row = document.createElement('div');
  row.className = 'inspector-row';

  const keyEl = document.createElement('div');
  keyEl.className = 'inspector-key';
  keyEl.textContent = label;
  row.appendChild(keyEl);

  const valueEl = document.createElement('div');
  valueEl.className = 'inspector-value';

  if (opts.path) {
    const p = document.createElement('span');
    p.className = 'path';
    p.textContent = value;
    valueEl.appendChild(p);
  } else if (opts.domain) {
    valueEl.textContent = value;
    valueEl.classList.add('domain-name');
  } else {
    valueEl.textContent = value;
  }

  if (opts.via) {
    const via = document.createElement('span');
    via.className = 'via';
    via.textContent = ' via ';
    valueEl.appendChild(via);
    const viaPath = document.createElement('span');
    viaPath.className = 'path';
    viaPath.textContent = opts.viaValue;
    valueEl.appendChild(viaPath);
  }

  row.appendChild(valueEl);
  parent.appendChild(row);
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
  addKeyValueLine(container, window._localization.t('stats-bytes-received'), byteCountString(statistics.bytesReceived));
  addKeyValueLine(container, window._localization.t('stats-bytes-sent'),     byteCountString(statistics.bytesSent));
  addKeyValueLine(container, window._localization.t('stats-last-allowed'),   fullDateTimeString(statistics.lastAllowed));
  addKeyValueLine(container, window._localization.t('stats-last-denied'),    fullDateTimeString(statistics.lastBlocked));
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
    addKeyValueLine(container, window._localization.t('field-process'), window._localization.t('all-processes'));
    return container;
  }

  /* Process / via --------------------------------------------- */
  if (data.primaryExecutable) {
    addKeyValueLine(
      container,
      window._localization.t('field-process'),
      data.primaryExecutable,
      { path: true, via: !!data.viaExecutable, viaValue: data.viaExecutable }
    );
  } else {
    addKeyValueLine(container, window._localization.t('field-process'), window._localization.t('unknown-executable'));
  }

  /* Direction ------------------------------------------------- */
  if (typeof data.isInbound === 'boolean') {
    addKeyValueLine(container, window._localization.t('field-direction'), data.isInbound ? window._localization.t('direction-inbound') : window._localization.t('direction-outbound'));
  }

  /* Remote ----------------------------------------------------- */
  addKeyValueLine(container, window._localization.t('field-remote'), data.remoteName?.value, { domain: data.remoteName?.type == 'domain' });

  /* IP address ----------------------------------------------- */
  addKeyValueLine(container, window._localization.t('field-remote-address'), data.ipAddress);

  /* Port / Protocol ------------------------------------------- */
  const protoName = PROTOCOL_MAP[data.protocol] || window._localization.t('proto-unknown', { n: data.protocol });

  if (data.port && data.port !== 0) {
    addKeyValueLine(container, window._localization.t('field-port'), `${protoName} ${data.port}`);
  } else if (data.port === 0) {
    addKeyValueLine(container, window._localization.t('field-protocol'), protoName);
  }

  return container;
}

function setRowSelected(rowID) {
  const selectedConnectionRowId = getSelectedConnectionRowId();
  // deselecte current selection
  if (selectedConnectionRowId !== null) {
    const selected = document.getElementById(htmlID(selectedConnectionRowId));
    if (selected !== null) {
      selected.classList.remove('is-selected');
    }
  }
  setSelectedConnectionRowId(rowID);
  // select new
  if (rowID !== null) {
    const selected = document.getElementById(htmlID(rowID));
    if (selected !== null) {
      selected.classList.add('is-selected');
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
window.renderLastEventSpans = renderLastEventSpans;

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

function refreshConnectionsBytes() {
  for (const span of document.querySelectorAll('.total-bytes')) {
    const rx = Number(span.dataset.bytesRx || 0);
    const tx = Number(span.dataset.bytesTx || 0);
    const text = currentBytesDisplay(rx, tx);
    span.style.visibility = text === '' ? 'hidden' : 'visible';
    span.textContent = text;
  }
}

// Single entry point for all sort-related UI updates. Call after updating
// state.connectionsSort (via window.app.setConnectionsSort) so that both
// renderConnectionsHeader and refreshConnectionsBytes read the new value.
function applyConnectionsSort() {
  renderConnectionsHeader();
  refreshConnectionsBytes();
}
window.applyConnectionsSort = applyConnectionsSort;

// ----------------------------------------------------
// Connections table header
// ----------------------------------------------------

function getTrafficSortOptions() {
  return [
    { key: 'totalData',         label: window._localization.t('sort-total-traffic') },
    { key: 'totalDataReceived', label: window._localization.t('sort-bytes-in') },
    { key: 'totalDataSent',     label: window._localization.t('sort-bytes-out') },
  ];
}

function showConnectionsSortPopup(anchorEl) {
  const sort = window.app?.getConnectionsSort?.() ?? '';
  const trafficSortOptions = getTrafficSortOptions();
  const activeKey = trafficSortOptions.some(o => o.key === sort) ? sort : 'totalData';
  window.app.showSortPopup(anchorEl, trafficSortOptions, activeKey, (key) => {
    window.app.setConnectionsSort(key);
    applyConnectionsSort();
    window.app.sendAction('setConnectionsSort', { sortBy: key });
  });
}

function renderConnectionsHeader(sort) {
  const headerEl = document.getElementById('connections-header');
  if (!headerEl) return;
  headerEl.innerHTML = '';

  if (sort === undefined) {
    sort = window.app?.getConnectionsSort?.() ?? '';
  }

  const trafficLabel = sort === 'totalDataReceived' ? window._localization.t('col-traffic-in')
    : sort === 'totalDataSent' ? window._localization.t('col-traffic-out')
    : window._localization.t('col-traffic');

  const columns = [
    { col: 'connection', label: window._localization.t('col-connection'), sortKey: 'name',          indicator: '▲' },
    { col: 'rule',       label: window._localization.t('col-rule'),        sortKey: null,            indicator: null },
    { col: 'traffic',    label: trafficLabel,          sortKey: 'traffic-popup', indicator: '▼' },
    { col: 'activity',   label: window._localization.t('col-activity'),    sortKey: 'lastActivity',  indicator: '▲' },
  ];

  const trafficActive = sort === 'totalData' || sort === 'totalDataReceived' || sort === 'totalDataSent';

  for (const col of columns) {
    const cell = document.createElement('div');
    cell.className = 'connections-th';
    cell.dataset.col = col.col;

    const isActive = col.sortKey === 'name'          ? sort === 'name'
      : col.sortKey === 'traffic-popup' ? trafficActive
      : col.sortKey === 'lastActivity'  ? sort === 'lastActivity'
      : false;

    if (col.sortKey) {
      cell.classList.add('is-sortable');
      if (isActive) cell.classList.add('is-active');
    }

    const labelSpan = document.createElement('span');
    labelSpan.textContent = col.label;
    cell.appendChild(labelSpan);

    if (col.indicator && isActive) {
      const ind = document.createElement('span');
      ind.className = 'rules-sort-indicator';
      ind.textContent = col.indicator;
      cell.appendChild(ind);
    }

    if (col.sortKey === 'traffic-popup') {
      cell.addEventListener('click', () => showConnectionsSortPopup(cell));
    } else if (col.sortKey) {
      cell.addEventListener('click', () => {
        window.app.setConnectionsSort(col.sortKey);
        applyConnectionsSort();
        window.app.sendAction('setConnectionsSort', { sortBy: col.sortKey });
      });
    }

    headerEl.appendChild(cell);
  }
}

renderConnectionsHeader();

// ----------------------------------------------------
// WebSocket message handlers
// ----------------------------------------------------

function handleClear() {
  pendingSelectionRecovery = null;
  listEl.innerHTML = '';
}
window.handleClear = handleClear;

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
window.handleInsertRows = handleInsertRows;

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
window.handleRemoveRows = handleRemoveRows;

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
window.handleMoveRows = handleMoveRows;

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
window.handleUpdateStatistics = handleUpdateStatistics;

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
window.handleUpdateRows = handleUpdateRows;

function attachRuleButton(rowEl, row) {
  const ruleButton = rowEl.querySelector('.rule-button');
  const detailsButton = rowEl.querySelector('.details-button');
  if (detailsButton === null) {
    return;
  }
  let detailsButtonIsVisible = false;
  let isAllow = false;
  if (row !== null) {
    isAllow = row.rule === 'allowByDefault' || row.rule === 'allowByRule';
    if (ruleButton !== null) {
      let buttonText;
      switch (row.rule) {
        case 'allowByDefault':
          buttonText = '<svg width="14" height="14"><use href="#rule-allow" opacity="0.5"/></svg>';
          break;
        case 'allowByRule':
          buttonText = '<svg width="14" height="14"><use href="#rule-allow"/></svg>';
          break;
        case 'denyByDefault':
          buttonText = '<svg width="14" height="14"><use href="#rule-deny" opacity="0.5"/></svg>';
          break;
        case 'denyByRule':
          buttonText = '<svg width="14" height="14"><use href="#rule-deny"/></svg>';
          break;
        case 'denyByBlocklist':
          buttonText = '<svg width="14" height="14"><use href="#rule-blocklist"/></svg>';
          break;
        default:
            buttonText = '<svg width="14" height="14"><use href="#rule-allow" opacity="0.5"/></svg>';
      }
      ruleButton.innerHTML = buttonText;
      ruleButton.dataset.action = isAllow ? 'allow' : 'deny';
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
}

function handleUpdateRuleButtons(rows) {
  for (const row of rows) {
    let el = document.getElementById(htmlID(row.rowId));
    attachRuleButton(el, row);
  }
}
window.handleUpdateRuleButtons = handleUpdateRuleButtons;

let _scrollRafId = null;

function animateScrollTo(target, duration, onComplete) {
  if (_scrollRafId !== null) {
    cancelAnimationFrame(_scrollRafId);
    _scrollRafId = null;
  }
  const start = listEl.scrollTop;
  const delta = target - start;
  if (delta === 0) {
    onComplete?.();
    return;
  }
  const startTime = performance.now();
  function tick(now) {
    const t = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
    listEl.scrollTop = start + delta * eased;
    if (t < 1) {
      _scrollRafId = requestAnimationFrame(tick);
    } else {
      _scrollRafId = null;
      onComplete?.();
    }
  }
  _scrollRafId = requestAnimationFrame(tick);
}

function highlightRuleButtons(rowIds, action) {
  if (!rowIds.length) return;
  const firstEl = document.getElementById(htmlID(rowIds[0]));
  if (!firstEl) return;

  function animateRow(el) {
    const ruleBtn = el.querySelector('.rule-button');
    const sameAction = ruleBtn && ruleBtn.dataset.action === action;
    const btn = sameAction ? ruleBtn : el.querySelector('.details-button');
    if (!btn) return;
    // Remove and re-add the class to allow re-triggering mid-animation.
    btn.classList.remove('rule-button-bounce');
    void btn.offsetWidth; // force reflow
    btn.classList.add('rule-button-bounce');
    btn.addEventListener('animationend', () => {
      btn.classList.remove('rule-button-bounce');
    }, { once: true });
  }

  function doAnimate() {
    for (const id of rowIds) {
      const el = document.getElementById(htmlID(id));
      if (el) animateRow(el);
    }
  }

  function doScroll() {
    // Rows above firstEl that are still mid-animation (height < rowH) will push
    // it further down as they finish growing. Add their remaining growth to get
    // the final position rather than the current one.
    const rowH = parseFloat(getComputedStyle(listEl).getPropertyValue('--row-h'));
    let extraOffset = 0;
    for (const sibling of listEl.children) {
      if (sibling === firstEl) break;
      const h = sibling.offsetHeight;
      if (h < rowH) extraOffset += rowH - h;
    }
    const finalTop    = firstEl.offsetTop + extraOffset;
    const finalBottom = finalTop + rowH;
    if (finalBottom > listEl.scrollTop + listEl.clientHeight) {
      animateScrollTo(finalBottom - listEl.clientHeight, 300, doAnimate);
    } else if (finalTop < listEl.scrollTop) {
      animateScrollTo(finalTop, 300, doAnimate);
    } else {
      doAnimate();
    }
  }

  setTimeout(doScroll, 200);
}
window.highlightRuleButtons = highlightRuleButtons;

// Per-row flash state: rowId -> { allow: {start} | null, deny: {start} | null, rafId: number | null }
const _flashState = new Map();
const FLASH_DURATION = 3000; // ms

// Derive the resting background of the .last-event cell from its current CSS classes,
// pre-composited over the actual surface color for the active theme.
// Must stay in sync with the .recent-allow / .recent-deny rules in connections.css.
// Dark-mode detection uses html.dark, which is also the class set by any future
// system-preference option, so this check remains correct in both cases.
function _restRgb(cell) {
  const dark = document.documentElement.classList.contains('dark');
  if (dark) {
    // Surface color in dark mode: --surface = #1e2130 = rgb(30, 33, 48)
    if (cell.classList.contains('recent-allow')) {
      // rgba(0, 160, 60, 0.15) over rgb(30, 33, 48)
      return { r: 26, g: 52, b: 50 };
    }
    if (cell.classList.contains('recent-deny')) {
      // rgba(200, 0, 0, 0.13) over rgb(30, 33, 48)
      return { r: 52, g: 29, b: 42 };
    }
    if (cell.classList.contains('recent-mixed')) {
      // rgba(180, 140, 0, 0.18) over rgb(30, 33, 48)
      return { r: 57, g: 52, b: 39 };
    }
    return { r: 30, g: 33, b: 48 };
  }
  // Light mode: surface color = white = rgb(255, 255, 255)
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
window.handleEvents = handleEvents;

function handleSetInspector(msg) {
  setRowSelected(msg.row);

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
  headline.textContent = window._localization.t('matching-rules');
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
  emoji.innerHTML = emojiFor(msg.defaultAction);
  defaultRule.appendChild(emoji);

  const text = document.createElement('span');
  text.className = 'host';
  text.textContent = msg.defaultAction.toLowerCase() === 'allow'
    ? window._localization.t('default-allow')
    : window._localization.t('default-deny');
  defaultRule.appendChild(text);

  defaultRule.classList.add('inactive');
  rulesTable.appendChild(defaultRule);
  let lastActiveLine = defaultRule;

  msg.coveringRules.forEach((r, i) => {
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

  if (msg.relatedRules && msg.relatedRules.length > 0) {
    const headline = document.createElement('div');
    headline.className = 'related-rules-headline';
    headline.textContent = window._localization.t('related-rules');
    rulesTable.appendChild(headline);
    msg.relatedRules.forEach(r => {
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
window.handleSetInspector = handleSetInspector;