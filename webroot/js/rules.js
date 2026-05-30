// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

let rulesCurrentList = [];
let rulesDisplayedList = [];
const ruleSelection = window.createMultiSelection({
  getCount: () => rulesDisplayedList.length,
  getItemByIndex: (i) => rulesDisplayedList[i],
  getId: (rule) => rule.id,
  onChanged: refreshRuleSelectionStyles,
});
let rulesSortCriteria = [{ key: 'process', order: 'asc' }];
let rulesLastColumnSort = 'port';
let rulesOriginalOrder = new Map();
let rulesSearchQuery = '';
let pendingRevealRuleId = null;
let ruleDialog = null;
let ruleDialogError = null;
let ruleDialogTitle = null;
let ruleDialogId = null;
let ruleDialogPrimary = null;
let ruleDialogVia = null;
let ruleDialogAction = null;
let ruleDialogDirection = null;
let ruleDialogRemoteType = null;
let ruleDialogRemoteValueLabel = null;
let ruleDialogRemoteValue = null;
let ruleDialogProtocol = null;
let ruleDialogPort = null;
let ruleDialogPriority = null;
let ruleDialogEnabled = null;
let ruleDialogNotes = null;

function ruleFileName(path) {
  if (!path) {
    return null;
  }
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1];
}

function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function ruleDirectionArrow(direction) {
  let suffix;
  switch (direction) {
    case 1: suffix = 'outgoing'; break;
    case 2: suffix = 'incoming'; break;
    case 3: suffix = 'bidirectional'; break;
    default: suffix = 'outgoing';
  }
  return `<svg width="20" height="20" fill="currentColor"><use href="#rule-${suffix}"/></svg>`;
}

function ruleDirectionLabel(direction) {
  switch (direction) {
    case 1:
      return window._localization.t('direction-out');
    case 2:
      return window._localization.t('direction-in');
    case 3:
      return window._localization.t('direction-both');
    default:
      return window._localization.t('direction-out');
  }
}

function ruleDirectionLabelLong(direction) {
  switch (direction) {
    case 1:
      return window._localization.t('direction-outbound');
    case 2:
      return window._localization.t('direction-inbound');
    case 3:
      return window._localization.t('direction-both-ways');
    default:
      return window._localization.t('direction-outbound');
  }
}

function rulePriorityLabel(priority) {
  const names = {
    0: window._localization.t('priority-low'),
    1: window._localization.t('priority-regular'),
    2: window._localization.t('priority-high'),
    3: window._localization.t('priority-extra-high'),
  };
  const value = Number(priority);
  if (Number.isFinite(value) && Object.prototype.hasOwnProperty.call(names, value)) {
    return `${names[value]} (${value})`;
  }
  return `${priority}`;
}

function normalizedRuleAction(action) {
  return String(action || '').toLowerCase() === 'deny' ? 'deny' : 'allow';
}

function ruleActionLabel(action) {
  return normalizedRuleAction(action) === 'allow' ? window._localization.t('action-allow') : window._localization.t('action-deny');
}

function ruleActionSVG(action) {
  const suffix = normalizedRuleAction(action) === 'allow' ? 'allow' : 'deny';
  return `<svg width="14" height="14"><use href="#rule-${suffix}" /></svg>`;
}

function ruleActionEmoji(action) {
  return normalizedRuleAction(action) === 'allow' ? '🟢' : '🔴';
}

function ruleProcessLabel(rule) {
  const primary = ruleFileName(rule.primaryExecutable);
  const via = ruleFileName(rule.viaExecutable);
  if (primary && via) {
    return `${primary} via ${via}`;
  }
  if (primary) {
    return primary;
  }
  if (via) {
    return window._localization.t('any-process-via', { via });
  }
  return window._localization.t('any-process');
}

function ruleRemotePatternLabel(remotePattern) {
  if (!remotePattern || !remotePattern.type) {
    return window._localization.t('any-server');
  }
  switch (remotePattern.type) {
    case 'any':
      return window._localization.t('any-server');
    case 'localNet':
      return window._localization.t('remote-local-network');
    case 'domains':
      return `domain ${remotePattern.value || ''}`.trim();
    case 'hosts':
    case 'ipAddresses':
      return remotePattern.value || '';
    default:
      return window._localization.t('any-server');
  }
}

function ruleRemoteTypeId(remotePattern) {
  if (!remotePattern || !remotePattern.type) {
    return 1;
  }
  switch (remotePattern.type) {
    case 'any':
      return 1;
    case 'localNet':
      return 2;
    case 'hosts':
      return 3;
    case 'domains':
      return 4;
    case 'ipAddresses':
      return 5;
    default:
      return 1;
  }
}

function ruleProtocolsFromMask(mask) {
  const map = ['ICMP', 'TCP', 'UDP', 'SCTP', 'Other'];
  const result = [];
  for (let i = 0; i < map.length; i += 1) {
    if (mask & (1 << i)) {
      result.push(map[i]);
    }
  }
  return result;
}

function ruleProtocolPortLabel(protocolMask, portString) {
  const ALL_MASK = 0b11111;
  const ALL_PORT = /^0 *- *65535$/i;
  const hasAnyPort = ALL_PORT.test(portString || '');
  const hasAnyProtocol = protocolMask === ALL_MASK;

  if (hasAnyPort && hasAnyProtocol) {
    return '';
  }

  const protocols = ruleProtocolsFromMask(protocolMask);
  const protocolLabel = protocols.join('/');
  if (hasAnyPort) {
    return protocolLabel;
  }
  if (hasAnyProtocol || protocolLabel.length === 0) {
    return portString;
  }
  return `${protocolLabel} ${portString}`;
}

function ruleSortValue(rule, sortKey) {
  switch (sortKey) {
    case 'enabled':
      return rule.isDisabled ? 0 : 1;
    case 'action':
      return (rule.action || '').toLowerCase();
    case 'process':
      return (ruleProcessLabel(rule) || '').toLowerCase();
    case 'direction':
      return rule.direction || 0;
    case 'remote':
      return (ruleRemotePatternLabel(rule.remotePattern) || '').toLowerCase();
    case 'port':
      return (ruleProtocolPortLabel(rule.protocol, rule.port) || '').toLowerCase();
    case 'modificationDate': return rule.modificationDate || 0;
    case 'creationDate':     return rule.creationDate || 0;
    case 'precedence':       return rulesOriginalOrder.get(rule.id) ?? 0;
    case 'priority':         return rule.priority || 0;
    default:
      return '';
  }
}

function shortDateTime(epochSeconds) {
  if (!epochSeconds || epochSeconds <= 0) return '';
  const age = Date.now() / 1000 - epochSeconds;
  const d = new Date(epochSeconds * 1000);
  const prefs = window.getDtPrefs();
  return age < 86400 ? window._fmtTime(d, prefs, false) : window._fmtDate(d, prefs);
}

function fixedSortOrderForKey(key) {
  if (key === 'modificationDate' || key === 'creationDate' || key === 'priority') return 'desc';
  return 'asc';
}

function compareRulesForSort(a, b) {
  if (!rulesSortCriteria || rulesSortCriteria.length === 0) {
    rulesSortCriteria = [{ key: 'process', order: 'asc' }];
  }
  for (const criterion of rulesSortCriteria) {
    const left = ruleSortValue(a, criterion.key);
    const right = ruleSortValue(b, criterion.key);
    let result = 0;
    if (typeof left === 'number' && typeof right === 'number') {
      result = left - right;
    } else {
      result = String(left).localeCompare(String(right), undefined, { sensitivity: 'base' });
    }
    if (result !== 0) {
      return criterion.order === 'desc' ? -result : result;
    }
  }
  return (a.id || 0) - (b.id || 0);
}

function sortedRulesForDisplay(rules) {
  const sorted = [...rules];
  if (!rulesSortCriteria || rulesSortCriteria.length === 0) {
    rulesSortCriteria = [{ key: 'process', order: 'asc' }];
  }
  sorted.sort(compareRulesForSort);
  return sorted;
}

function normalizedRulesSearchQuery() {
  return (rulesSearchQuery || '').trim().toLowerCase();
}

function ruleMatchesSearch(rule) {
  const query = normalizedRulesSearchQuery();
  if (query.length === 0) {
    return true;
  }
  const searchableText = [
    rule.primaryExecutable || '',
    rule.viaExecutable || '',
    ruleRemotePatternLabel(rule.remotePattern),
    (rule.remotePattern && rule.remotePattern.value) || '',
    rule.port || '',
    ruleProtocolsFromMask(rule.protocol).join(' '),
    ruleProtocolPortLabel(rule.protocol, rule.port),
    rule.notes || '',
  ].join('\n').toLowerCase();
  return searchableText.includes(query);
}

function setHighlightedText(element, text) {
  const rawText = text || '';
  const query = normalizedRulesSearchQuery();
  if (!query || query.length === 0) {
    element.textContent = rawText;
    return;
  }

  const haystack = rawText.toLowerCase();
  let searchStart = 0;
  let matchIndex = haystack.indexOf(query, searchStart);
  if (matchIndex < 0) {
    element.textContent = rawText;
    return;
  }

  const fragment = document.createDocumentFragment();
  while (matchIndex >= 0) {
    if (matchIndex > searchStart) {
      fragment.appendChild(document.createTextNode(rawText.slice(searchStart, matchIndex)));
    }
    const mark = document.createElement('mark');
    mark.className = 'rules-search-highlight';
    mark.textContent = rawText.slice(matchIndex, matchIndex + query.length);
    fragment.appendChild(mark);
    searchStart = matchIndex + query.length;
    matchIndex = haystack.indexOf(query, searchStart);
  }
  if (searchStart < rawText.length) {
    fragment.appendChild(document.createTextNode(rawText.slice(searchStart)));
  }
  element.textContent = '';
  element.appendChild(fragment);
}
window.setHighlightedText = setHighlightedText;
function revealRuleInList(ruleId) {
  const container = document.getElementById('rules-list');
  if (!container) {
    return false;
  }
  const row = container.querySelector(`tbody tr[data-rule-id="${ruleId}"]`);
  if (!row) {
    return false;
  }
  const containerRect = container.getBoundingClientRect();
  const rowRect = row.getBoundingClientRect();
  const targetTop = container.scrollTop
    + (rowRect.top - containerRect.top)
    - (containerRect.height / 2)
    + (rowRect.height / 2);
  container.scrollTo({ top: Math.max(0, targetTop), behavior: 'smooth' });
  return true;
}

function selectRuleInRulesSection(ruleId) {
  if (typeof ruleId !== 'number') {
    return;
  }
  ruleSelection.setSelected([ruleId]);
  pendingRevealRuleId = ruleId;
  if (rulesCurrentList.some((rule) => rule.id === ruleId)) {
    applyRulesData(rulesCurrentList);
  }
}

window.selectRuleInRulesSection = selectRuleInRulesSection;

function setRulesSearchQuery(query) {
  rulesSearchQuery = typeof query === 'string' ? query : '';
  applyRulesData(rulesCurrentList);
}

window.setRulesSearchQuery = setRulesSearchQuery;

function toggleRulesSort(sortKey) {
  if (!sortKey) {
    return;
  }
  if (!rulesSortCriteria || rulesSortCriteria.length === 0) {
    rulesSortCriteria = [{ key: 'process', order: 'asc' }];
  }
  const existingIndex = rulesSortCriteria.findIndex((criterion) => criterion.key === sortKey);
  if (existingIndex === 0) {
    rulesSortCriteria[0].order = rulesSortCriteria[0].order === 'asc' ? 'desc' : 'asc';
  } else if (existingIndex > 0) {
    const [criterion] = rulesSortCriteria.splice(existingIndex, 1);
    rulesSortCriteria.unshift(criterion);
  } else {
    rulesSortCriteria.unshift({ key: sortKey, order: 'asc' });
  }
  if (rulesSortCriteria.length === 0) {
    rulesSortCriteria = [{ key: 'process', order: 'asc' }];
  }
  applyRulesData(rulesCurrentList);
}

function ruleProtocolInspectorLabel(protocolMask) {
  if (protocolMask === 31) {
    return window._localization.t('any-protocol');
  }
  const protocols = ruleProtocolsFromMask(protocolMask);
  return protocols.length > 0 ? protocols.join(', ') : window._localization.t('any-protocol');
}

function rulePortInspectorLabel(portString) {
  if (!portString || portString === '0-65535') {
    return window._localization.t('any-port');
  }
  return portString;
}

function ruleRemoteInspectorLabel(remotePattern) {
  if (!remotePattern || !remotePattern.type || remotePattern.type === 'any') {
    return window._localization.t('any-server');
  }
  if (remotePattern.type === 'localNet') {
    return window._localization.t('remote-local-network');
  }
  const raw = (remotePattern.value || '').trim();
  const parts = raw.length === 0
    ? []
    : raw.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
  if (remotePattern.type === 'hosts') {
    return `${parts.length <= 1 ? window._localization.t('remote-host') : window._localization.t('remote-hosts')} ${parts.join(', ')}`.trim();
  }
  if (remotePattern.type === 'domains') {
    return `${parts.length <= 1 ? window._localization.t('remote-domain-singular') : window._localization.t('remote-domains')} ${parts.join(', ')}`.trim();
  }
  if (remotePattern.type === 'ipAddresses') {
    return `${parts.length <= 1 ? window._localization.t('remote-address') : window._localization.t('remote-addresses')} ${parts.join(', ')}`.trim();
  }
  return window._localization.t('any-server');
}

function ruleHeadline(rule) {
  const action = `${ruleActionSVG(rule.action)} <span>${ruleActionLabel(rule.action)}</span>`;
  const executable = rule.primaryExecutable
    ? (rule.viaExecutable ? `${escapeHtml(rule.primaryExecutable)} via ${escapeHtml(rule.viaExecutable)}` : escapeHtml(rule.primaryExecutable))
    : (rule.viaExecutable ? window._localization.t('any-process-via', { via: escapeHtml(rule.viaExecutable) }) : window._localization.t('any-process'));
  const direction = ruleDirectionArrow(rule.direction);
  const remote = escapeHtml(ruleRemoteInspectorLabel(rule.remotePattern));
  return `${action} <span>${executable}</span> ${direction} <span>${remote}</span>`;
}

function ruleLifetimeLabel(lifetime) {
  if (typeof lifetime === 'string') {
    return lifetime;
  }
  if (lifetime && typeof lifetime === 'object') {
    const until = lifetime.until ?? lifetime.Until;
    if (typeof until === 'number') {
      return window._localization.t('lifetime-until', { datetime: window.formatDateTime(until) });
    }
  }
  return window._localization.t('lifetime-forever');
}

function ruleTimeLabel(epochSeconds) {
  if (!epochSeconds || epochSeconds <= 0) {
    return '-';
  }
  return window.formatDateTime(epochSeconds);
}

function appendInspectorRow(grid, key, value, opts = {}) {
  const row = document.createElement('div');
  row.className = 'inspector-row';
  if (opts.rowClass) row.classList.add(opts.rowClass);

  const keyEl = document.createElement('div');
  keyEl.className = 'inspector-key';
  keyEl.textContent = key;
  row.appendChild(keyEl);

  const valueEl = document.createElement('div');
  valueEl.className = 'inspector-value';
  if (opts.valueClass) valueEl.classList.add(opts.valueClass);
  if (opts.html) {
    valueEl.innerHTML = value;
  } else if (opts.plain) {
    valueEl.textContent = value && value.length > 0 ? value : '-';
  } else {
    setHighlightedText(valueEl, value && value.length > 0 ? value : '-');
  }
  row.appendChild(valueEl);

  grid.appendChild(row);
}
window.appendInspectorRow = appendInspectorRow;

function appendInspectorBox(container, headline, content) {
  const block = document.createElement('div');
  block.className = 'inspector-box-block';

  const head = document.createElement('div');
  head.className = 'inspector-box-headline';
  head.textContent = headline;
  block.appendChild(head);

  const body = document.createElement('div');
  body.className = 'inspector-box';
  setHighlightedText(body, content && content.length > 0 ? content : '-');
  block.appendChild(body);

  container.appendChild(block);
}

function saveRuleNotes(rule, value) {
  if (!window.app || typeof window.app.sendAction !== 'function') {
    return;
  }
  const nextNotes = value.trim();
  const nextRule = {
    ...rule,
    notes: nextNotes.length > 0 ? nextNotes : null,
    modificationDate: Math.floor(Date.now() / 1000),
  };
  window.app.sendAction('editRule', { rule: nextRule });
}

function renderRuleInspectorCard(rule) {
  const card = document.createElement('div');
  card.className = 'inspector-card';

  const title = document.createElement('div');
  title.className = 'inspector-headline';
  title.innerHTML = ruleHeadline(rule);
  card.appendChild(title);

  const grid = document.createElement('div');
  grid.className = 'inspector-grid';
  appendInspectorRow(grid, window._localization.t('inspector-action'), `${ruleActionLabel(rule.action)}${rule.isDisabled ? window._localization.t('rule-disabled-suffix') : ''}`);
  const executable = rule.primaryExecutable
    ? (rule.viaExecutable ? `${rule.primaryExecutable} via ${rule.viaExecutable}` : rule.primaryExecutable)
    : (rule.viaExecutable ? window._localization.t('any-process-via', { via: rule.viaExecutable }) : window._localization.t('any-process'));
  appendInspectorRow(grid, window._localization.t('inspector-priority'), rulePriorityLabel(rule.priority));
  appendInspectorRow(grid, window._localization.t('inspector-executable'), executable);
  appendInspectorRow(grid, window._localization.t('inspector-direction'), ruleDirectionLabelLong(rule.direction));
  appendInspectorRow(grid, window._localization.t('inspector-remote'), ruleRemoteInspectorLabel(rule.remotePattern));
  appendInspectorRow(grid, window._localization.t('inspector-protocol'), ruleProtocolInspectorLabel(rule.protocol));
  appendInspectorRow(grid, window._localization.t('inspector-port'), rulePortInspectorLabel(rule.port));
  appendInspectorRow(grid, window._localization.t('inspector-lifetime'), ruleLifetimeLabel(rule.lifetime));
  appendInspectorRow(grid, window._localization.t('inspector-created'), ruleTimeLabel(rule.creationDate));
  appendInspectorRow(grid, window._localization.t('inspector-modified'), ruleTimeLabel(rule.modificationDate));
  card.appendChild(grid);

  const notesBlock = document.createElement('div');
  notesBlock.className = 'inspector-box-block';
  const notesHeadline = document.createElement('div');
  notesHeadline.className = 'inspector-box-headline';
  notesHeadline.textContent = window._localization.t('notes-headline');
  notesBlock.appendChild(notesHeadline);
  const notesBox = document.createElement('div');
  notesBox.className = 'inspector-box';
  const notesInput = document.createElement('textarea');
  notesInput.className = 'inspector-notes-input';
  notesInput.rows = 3;
  notesInput.value = rule.notes || '';
  notesInput.classList.toggle(
    'is-search-match',
    normalizedRulesSearchQuery().length > 0
      && (rule.notes || '').toLowerCase().includes(normalizedRulesSearchQuery()),
  );
  notesBox.appendChild(notesInput);
  const notesSave = document.createElement('button');
  notesSave.type = 'button';
  notesSave.className = 'edit-dialog-button is-primary inspector-save-button';
  notesSave.textContent = window._localization.t('btn-save-notes');
  notesSave.addEventListener('click', () => {
    saveRuleNotes(rule, notesInput.value);
  });
  notesBox.appendChild(notesSave);
  notesBlock.appendChild(notesBox);
  card.appendChild(notesBlock);
  return card;
}

function renderRulesInspector() {
  const details = document.getElementById('rules-details');
  if (!details) {
    return;
  }
  details.innerHTML = '';

  const selectedRules = rulesCurrentList.filter(
    (rule) => ruleSelection.has(rule.id) && ruleMatchesSearch(rule),
  );
  if (selectedRules.length === 0) {
    const hint = document.createElement('div');
    hint.className = 'empty-state';
    hint.textContent = window._localization.t('rules-inspect-hint');
    details.appendChild(hint);
    return;
  }

  const container = document.createElement('div');
  container.className = 'inspector-list';
  for (const rule of selectedRules) {
    container.appendChild(renderRuleInspectorCard(rule));
  }
  details.appendChild(container);
}

function setRuleDialogError(message) {
  if (!ruleDialogError) {
    return;
  }
  ruleDialogError.textContent = message || '';
}

function updateRuleRemoteValueVisibility() {
  if (!ruleDialogRemoteType || !ruleDialogRemoteValueLabel || !ruleDialogRemoteValue) {
    return;
  }
  const remotePatternType = Number.parseInt(ruleDialogRemoteType.value, 10);
  const hideRemoteValue = remotePatternType === 1 || remotePatternType === 2;
  const headline = remotePatternType === 3
    ? window._localization.t('dlg-remote-hosts')
    : remotePatternType === 4
      ? window._localization.t('dlg-remote-domains')
      : remotePatternType === 5
        ? window._localization.t('dlg-remote-addresses')
        : window._localization.t('dlg-remote-value-label');
  const labelTextNode = ruleDialogRemoteValueLabel.querySelector('span');
  if (labelTextNode) {
    labelTextNode.textContent = headline;
  }
  ruleDialogRemoteValueLabel.classList.toggle('is-collapsed', hideRemoteValue);
  if (hideRemoteValue) {
    ruleDialogRemoteValue.value = '';
  }
}

function ruleModalPayloadFromInputs() {
  if (
    !ruleDialogPrimary
    || !ruleDialogVia
    || !ruleDialogAction
    || !ruleDialogDirection
    || !ruleDialogRemoteType
    || !ruleDialogRemoteValue
    || !ruleDialogProtocol
    || !ruleDialogPort
    || !ruleDialogPriority
    || !ruleDialogEnabled
    || !ruleDialogNotes
  ) {
    return null;
  }

  const priority = Number.parseInt(ruleDialogPriority.value, 10);
  if (!Number.isFinite(priority) || priority < 0 || priority > 255) {
    setRuleDialogError(window._localization.t('err-priority-range'));
    return null;
  }

  const direction = Number.parseInt(ruleDialogDirection.value, 10);
  const protocol = Number.parseInt(ruleDialogProtocol.value, 10);
  const remotePatternType = Number.parseInt(ruleDialogRemoteType.value, 10);
  if (!Number.isFinite(direction) || !Number.isFinite(protocol) || !Number.isFinite(remotePatternType)) {
    setRuleDialogError(window._localization.t('err-direction-required'));
    return null;
  }

  const primaryExecutable = ruleDialogPrimary.value.trim();
  const viaExecutable = ruleDialogVia.value.trim();
  const remotePatternValue = ruleDialogRemoteValue.value.trim();
  const rawPort = ruleDialogPort.value.trim();
  const port = rawPort.length === 0 || rawPort.toLowerCase() === 'any' ? 'Any' : rawPort;
  const notes = ruleDialogNotes.value.trim();

  const nowSeconds = Math.floor(Date.now() / 1000);
  const remoteTypeName = {
    1: 'any',
    2: 'localNet',
    3: 'hosts',
    4: 'domains',
    5: 'ipAddresses',
  }[remotePatternType] || 'any';
  const remotePattern = (remoteTypeName === 'any' || remoteTypeName === 'localNet')
    ? { type: remoteTypeName }
    : { type: remoteTypeName, value: remotePatternValue };
  return {
    id: 0,
    primaryExecutable: primaryExecutable.length > 0 ? primaryExecutable : null,
    viaExecutable: viaExecutable.length > 0 ? viaExecutable : null,
    remotePattern,
    port,
    protocol,
    direction,
    priority,
    action: normalizedRuleAction(ruleDialogAction.value),
    isDisabled: !ruleDialogEnabled.checked,
    lifetime: 'Forever',
    creationDate: nowSeconds,
    modificationDate: nowSeconds,
    notes: notes.length > 0 ? notes : null,
  };
}

function submitRuleModal() {
  if (!window.app || typeof window.app.sendAction !== 'function') {
    return;
  }
  const payload = ruleModalPayloadFromInputs();
  if (!payload) {
    return;
  }
  setRuleDialogError('');

  const mode = ruleDialogId ? ruleDialogId.value : '';
  if (mode) {
    payload.id = Number.parseInt(mode, 10);
    window.app.sendAction('editRule', { rule: payload });
  } else {
    payload.id = 0;
    window.app.sendAction('addRule', { rule: payload });
  }
  if (ruleDialog) {
    ruleDialog.close();
  }
}

function ensureRuleDialog() {
  if (ruleDialog) {
    return ruleDialog;
  }

  const dialog = document.createElement('dialog');
  dialog.className = 'edit-dialog';

  const form = document.createElement('form');
  form.className = 'edit-dialog-form';
  form.method = 'dialog';
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submitRuleModal();
  });

  const title = document.createElement('h2');
  title.className = 'edit-dialog-title';
  title.textContent = window._localization.t('dlg-add-rule-title');
  form.appendChild(title);

  const hiddenId = document.createElement('input');
  hiddenId.type = 'hidden';
  hiddenId.name = 'ruleId';
  form.appendChild(hiddenId);

  const primaryLabel = document.createElement('label');
  primaryLabel.className = 'edit-dialog-label';
  primaryLabel.textContent = window._localization.t('dlg-primary-exe-label');
  const primaryInput = document.createElement('input');
  primaryInput.className = 'edit-dialog-input';
  primaryInput.type = 'text';
  primaryLabel.appendChild(primaryInput);
  form.appendChild(primaryLabel);

  const viaLabel = document.createElement('label');
  viaLabel.className = 'edit-dialog-label';
  viaLabel.textContent = window._localization.t('dlg-via-exe-label');
  const viaInput = document.createElement('input');
  viaInput.className = 'edit-dialog-input';
  viaInput.type = 'text';
  viaLabel.appendChild(viaInput);
  form.appendChild(viaLabel);

  const actionDirectionRow = document.createElement('div');
  actionDirectionRow.className = 'rule-modal-row';

  const actionLabel = document.createElement('label');
  actionLabel.className = 'edit-dialog-label rule-modal-half';
  actionLabel.textContent = window._localization.t('dlg-action-label');
  const actionSelect = document.createElement('select');
  actionSelect.className = 'edit-dialog-input';
  actionSelect.innerHTML = `<option value="allow">${window._localization.t('action-allow')}</option><option value="deny">${window._localization.t('action-deny')}</option>`;
  actionLabel.appendChild(actionSelect);
  actionDirectionRow.appendChild(actionLabel);

  const directionLabel = document.createElement('label');
  directionLabel.className = 'edit-dialog-label rule-modal-half';
  directionLabel.textContent = window._localization.t('dlg-direction-label');
  const directionSelect = document.createElement('select');
  directionSelect.className = 'edit-dialog-input';
  directionSelect.innerHTML = `<option value="1">${window._localization.t('dir-out')}</option><option value="2">${window._localization.t('dir-in')}</option><option value="3">${window._localization.t('dir-both')}</option>`;
  directionLabel.appendChild(directionSelect);
  actionDirectionRow.appendChild(directionLabel);
  form.appendChild(actionDirectionRow);

  const remoteTypeLabel = document.createElement('label');
  remoteTypeLabel.className = 'edit-dialog-label';
  remoteTypeLabel.textContent = window._localization.t('dlg-remote-type-label');
  const remoteTypeSelect = document.createElement('select');
  remoteTypeSelect.className = 'edit-dialog-input';
  remoteTypeSelect.innerHTML = [
    `<option value="1">${window._localization.t('any-server')}</option>`,
    `<option value="2">${window._localization.t('remote-local-network')}</option>`,
    `<option value="3">${window._localization.t('remote-hosts')}</option>`,
    `<option value="4">${window._localization.t('remote-domains')}</option>`,
    `<option value="5">${window._localization.t('remote-ip-addresses')}</option>`,
  ].join('');
  remoteTypeLabel.appendChild(remoteTypeSelect);
  form.appendChild(remoteTypeLabel);

  const remoteValueLabel = document.createElement('label');
  remoteValueLabel.className = 'edit-dialog-label rule-modal-collapsible';
  const remoteValueTitle = document.createElement('span');
  remoteValueTitle.textContent = window._localization.t('dlg-remote-value-label');
  remoteValueLabel.appendChild(remoteValueTitle);
  const remoteValueInput = document.createElement('input');
  remoteValueInput.className = 'edit-dialog-input';
  remoteValueInput.type = 'text';
  remoteValueLabel.appendChild(remoteValueInput);
  form.appendChild(remoteValueLabel);
  remoteTypeSelect.addEventListener('change', () => {
    updateRuleRemoteValueVisibility();
  });

  const protocolPortRow = document.createElement('div');
  protocolPortRow.className = 'rule-modal-row';

  const protocolLabel = document.createElement('label');
  protocolLabel.className = 'edit-dialog-label rule-modal-half';
  protocolLabel.textContent = window._localization.t('dlg-protocol-label');
  const protocolSelect = document.createElement('select');
  protocolSelect.className = 'edit-dialog-input';
  protocolSelect.innerHTML = [
    `<option value="31">${window._localization.t('proto-any-option')}</option>`,
    '<option value="2">TCP</option>',
    '<option value="4">UDP</option>',
    '<option value="1">ICMP</option>',
    '<option value="8">SCTP</option>',
    '<option value="16">Other</option>',
  ].join('');
  protocolLabel.appendChild(protocolSelect);
  protocolPortRow.appendChild(protocolLabel);

  const portLabel = document.createElement('label');
  portLabel.className = 'edit-dialog-label rule-modal-half';
  portLabel.textContent = window._localization.t('dlg-ports-label');
  const portInput = document.createElement('input');
  portInput.className = 'edit-dialog-input';
  portInput.type = 'text';
  portInput.placeholder = window._localization.t('dlg-port-placeholder');
  portLabel.appendChild(portInput);
  protocolPortRow.appendChild(portLabel);
  form.appendChild(protocolPortRow);

  const priorityEnabledRow = document.createElement('div');
  priorityEnabledRow.className = 'rule-modal-row';

  const priorityLabel = document.createElement('label');
  priorityLabel.className = 'edit-dialog-label rule-modal-half';
  priorityLabel.textContent = window._localization.t('dlg-priority-label');
  const priorityInput = document.createElement('input');
  priorityInput.className = 'edit-dialog-input';
  priorityInput.type = 'number';
  priorityInput.min = '0';
  priorityInput.max = '255';
  priorityLabel.appendChild(priorityInput);
  priorityEnabledRow.appendChild(priorityLabel);

  const enabledLabel = document.createElement('label');
  enabledLabel.className = 'edit-dialog-checkbox-label rule-modal-half rule-modal-checkbox';
  const enabledInput = document.createElement('input');
  enabledInput.type = 'checkbox';
  enabledLabel.appendChild(enabledInput);
  enabledLabel.appendChild(document.createTextNode(window._localization.t('dlg-rule-is-enabled')));
  priorityEnabledRow.appendChild(enabledLabel);
  form.appendChild(priorityEnabledRow);

  const notesLabel = document.createElement('label');
  notesLabel.className = 'edit-dialog-label';
  notesLabel.textContent = window._localization.t('dlg-notes-label');
  const notesInput = document.createElement('textarea');
  notesInput.className = 'edit-dialog-textarea';
  notesInput.rows = 3;
  notesLabel.appendChild(notesInput);
  form.appendChild(notesLabel);

  const error = document.createElement('div');
  error.className = 'edit-dialog-error';
  form.appendChild(error);

  const actions = document.createElement('div');
  actions.className = 'edit-dialog-actions';

  const cancelButton = document.createElement('button');
  cancelButton.type = 'button';
  cancelButton.className = 'edit-dialog-button';
  cancelButton.textContent = window._localization.t('btn-cancel');
  cancelButton.addEventListener('click', () => dialog.close());
  actions.appendChild(cancelButton);

  const saveButton = document.createElement('button');
  saveButton.type = 'submit';
  saveButton.className = 'edit-dialog-button is-primary';
  saveButton.textContent = window._localization.t('btn-save');
  actions.appendChild(saveButton);

  form.appendChild(actions);
  dialog.appendChild(form);

  dialog.addEventListener('close', () => {
    setRuleDialogError('');
  });

  document.body.appendChild(dialog);

  ruleDialog = dialog;
  ruleDialogError = error;
  ruleDialogTitle = title;
  ruleDialogId = hiddenId;
  ruleDialogPrimary = primaryInput;
  ruleDialogVia = viaInput;
  ruleDialogAction = actionSelect;
  ruleDialogDirection = directionSelect;
  ruleDialogRemoteType = remoteTypeSelect;
  ruleDialogRemoteValueLabel = remoteValueLabel;
  ruleDialogRemoteValue = remoteValueInput;
  ruleDialogProtocol = protocolSelect;
  ruleDialogPort = portInput;
  ruleDialogPriority = priorityInput;
  ruleDialogEnabled = enabledInput;
  ruleDialogNotes = notesInput;
  return dialog;
}

function openRuleModal(rule) {
  const dialog = ensureRuleDialog();
  setRuleDialogError('');

  if (!ruleDialogId || !ruleDialogTitle) {
    return;
  }

  if (rule) {
    ruleDialogTitle.textContent = window._localization.t('dlg-edit-rule-title');
    ruleDialogId.value = String(rule.id);
    ruleDialogPrimary.value = rule.primaryExecutable || '';
    ruleDialogVia.value = rule.viaExecutable || '';
    ruleDialogAction.value = normalizedRuleAction(rule.action);
    ruleDialogDirection.value = String(rule.direction || 1);
    ruleDialogRemoteType.value = String(ruleRemoteTypeId(rule.remotePattern));
    ruleDialogRemoteValue.value = (rule.remotePattern && rule.remotePattern.value) || '';
    ruleDialogProtocol.value = String(rule.protocol || 31);
    ruleDialogPort.value = (!rule.port || rule.port === '0-65535') ? 'Any' : rule.port;
    ruleDialogPriority.value = String(rule.priority || 0);
    ruleDialogEnabled.checked = !rule.isDisabled;
    ruleDialogNotes.value = rule.notes || '';
  } else {
    ruleDialogTitle.textContent = window._localization.t('dlg-add-rule-title');
    ruleDialogId.value = '';
    ruleDialogPrimary.value = '';
    ruleDialogVia.value = '';
    ruleDialogAction.value = 'allow';
    ruleDialogDirection.value = '1';
    ruleDialogRemoteType.value = '1';
    ruleDialogRemoteValue.value = '';
    ruleDialogProtocol.value = '31';
    ruleDialogPort.value = 'Any';
    ruleDialogPriority.value = '1';
    ruleDialogEnabled.checked = true;
    ruleDialogNotes.value = '';
  }
  updateRuleRemoteValueVisibility();

  dialog.showModal();
  if (ruleDialogPrimary) {
    ruleDialogPrimary.focus();
  }
}



function getLastColumnSortOptions() {
  return [
    { key: 'port',             label: window._localization.t('sort-port-protocol') },
    { key: 'modificationDate', label: window._localization.t('sort-modified') },
    { key: 'creationDate',     label: window._localization.t('sort-created') },
    { key: 'precedence',       label: window._localization.t('sort-precedence') },
    { key: 'priority',         label: window._localization.t('sort-priority') },
  ];
}

function showRulesSortPopup(anchorEl) {
  window.app.showSortPopup(anchorEl, getLastColumnSortOptions(), rulesLastColumnSort, (key) => {
    rulesLastColumnSort = key;
    rulesSortCriteria = [{ key, order: fixedSortOrderForKey(key) }];
    applyRulesData(rulesCurrentList);
  });
}

function renderRuleTable(ruleList) {
  const table = document.createElement('table');
  table.className = 'rules-table';
  const thead = document.createElement('thead');
  const header = document.createElement('tr');
  const columns = [
    { title: '', sortKey: 'enabled' },
    { title: window._localization.t('col-action'), sortKey: 'action' },
    { title: window._localization.t('col-process'), sortKey: 'process' },
    { title: window._localization.t('col-dir'), sortKey: 'direction' },
    { title: window._localization.t('col-server'), sortKey: 'remote' },
    { title: window._localization.t('col-port'), sortKey: 'port', sortPopup: true },
    { title: '', sortKey: null, addButton: true },
  ];
  for (const column of columns) {
    const th = document.createElement('th');
    if (column.sortPopup) {
      th.classList.add('rules-sortable-header');
      const primary = rulesSortCriteria && rulesSortCriteria.length > 0
        ? rulesSortCriteria[0]
        : { key: 'process', order: 'asc' };
      const activeOption = getLastColumnSortOptions().find((o) => o.key === rulesLastColumnSort);
      const titleText = (rulesLastColumnSort === 'port' || !activeOption)
        ? column.title
        : activeOption.label;
      const title = document.createElement('span');
      title.textContent = titleText;
      th.appendChild(title);
      if (primary.key === rulesLastColumnSort) {
        const indicator = document.createElement('span');
        indicator.className = 'rules-sort-indicator';
        indicator.textContent = fixedSortOrderForKey(rulesLastColumnSort) === 'desc' ? '▼' : '▲';
        th.appendChild(indicator);
      }
      th.addEventListener('click', () => {
        showRulesSortPopup(th);
      });
    } else if (column.sortKey) {
      th.classList.add('rules-sortable-header');
      const title = document.createElement('span');
      title.textContent = column.title;
      th.appendChild(title);
      const primary = rulesSortCriteria && rulesSortCriteria.length > 0
        ? rulesSortCriteria[0]
        : { key: 'process', order: 'asc' };
      if (primary.key === column.sortKey) {
        const indicator = document.createElement('span');
        indicator.className = 'rules-sort-indicator';
        indicator.textContent = primary.order === 'asc' ? '▲' : '▼';
        th.appendChild(indicator);
      }
      th.addEventListener('click', () => {
        toggleRulesSort(column.sortKey);
      });
    } else if (column.addButton) {
      const btnGroup = document.createElement('div');
      btnGroup.className = 'rule-th-actions';

      const addBtn = document.createElement('button');
      addBtn.type = 'button';
      addBtn.className = 'blocklist-add-button';
      addBtn.setAttribute('aria-label', window._localization.t('btn-add-rule'));
      addBtn.title = window._localization.t('btn-add-rule');
      addBtn.innerHTML = '<svg width="14" height="14" fill="currentColor"><use href="#btn-add"/></svg>';
      addBtn.addEventListener('click', () => {
        openRuleModal(null);
      });
      btnGroup.appendChild(addBtn);

      const deleteSelectedBtn = document.createElement('button');
      deleteSelectedBtn.type = 'button';
      deleteSelectedBtn.className = 'blocklist-add-button';
      deleteSelectedBtn.setAttribute('data-role', 'delete-selected-rules');
      deleteSelectedBtn.setAttribute('aria-label', window._localization.t('btn-delete-rules'));
      deleteSelectedBtn.title = window._localization.t('btn-delete-rules');
      deleteSelectedBtn.innerHTML = '<svg width="18" height="18" fill="currentColor"><use href="#btn-remove"/></svg>';
      deleteSelectedBtn.disabled = ruleSelection.size === 0;
      deleteSelectedBtn.addEventListener('click', () => {
        if (ruleSelection.size === 0) {
          return;
        }
        const hasFactory = rulesCurrentList.some((r) => ruleSelection.has(r.id) && r.id < 0);
        if (hasFactory) {
          alert(window._localization.t('alert-factory-rule'));
          return;
        }
        if (window.app && typeof window.app.sendAction === 'function') {
          window.app.sendAction('deleteRules', { ruleIds: Array.from(ruleSelection.getAll()) });
        }
      });
      btnGroup.appendChild(deleteSelectedBtn);

      th.appendChild(btnGroup);
    } else {
      th.textContent = column.title;
    }
    header.appendChild(th);
  }
  thead.appendChild(header);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  for (let index = 0; index < ruleList.length; index += 1) {
    const rule = ruleList[index];
    const row = document.createElement('tr');
    row.dataset.ruleId = String(rule.id);
    row.dataset.ruleIndex = String(index);
    if (ruleSelection.has(rule.id)) {
      row.classList.add('is-selected');
    }
    const isHighPriority = (rule.priority || 0) > 1;
    if (isHighPriority) {
      row.classList.add('rule-high-priority');
    }
    const enabledCell = document.createElement('td');
    enabledCell.setAttribute('data-role', 'rule-enabled');
    const enabledInner = document.createElement('div');
    enabledInner.className = 'rule-cell-inner';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'rule-enable-checkbox';
    checkbox.checked = !rule.isDisabled;
    checkbox.title = rule.isDisabled ? window._localization.t('disabled') : window._localization.t('enabled');
    checkbox.addEventListener('click', (event) => {
      event.stopPropagation();
    });
    checkbox.addEventListener('change', (event) => {
      event.stopPropagation();
      if (!window.app || typeof window.app.sendAction !== 'function') {
        return;
      }
      if (rule.id < 0 && !rule.isDisabled) {
        const confirmed = confirm(window._localization.t('confirm-disable-factory-rule'));
        if (!confirmed) {
          checkbox.checked = true;
          return;
        }
      }
      window.app.sendAction('setRuleDisabled', { ruleId: rule.id, isDisabled: !rule.isDisabled });
    });
    enabledInner.appendChild(checkbox);
    enabledCell.appendChild(enabledInner);
    row.appendChild(enabledCell);

    const actionCell = document.createElement('td');
    const actionInner = document.createElement('div');
    actionInner.className = 'rule-cell-inner';
    actionInner.innerHTML = `${ruleActionSVG(rule.action)} ${ruleActionLabel(rule.action)}`;
    actionCell.title = ruleActionLabel(rule.action);
    actionCell.appendChild(actionInner);
    actionCell.setAttribute('data-role', 'rule-action');
    row.appendChild(actionCell);

    const processCell = document.createElement('td');
    const processInner = document.createElement('div');
    processInner.className = 'rule-cell-inner';
    const processText = ruleProcessLabel(rule);
    setHighlightedText(processInner, processText);
    processCell.title = processText;
    processCell.appendChild(processInner);
    row.appendChild(processCell);

    const directionCell = document.createElement('td');
    const directionInner = document.createElement('div');
    directionInner.className = 'rule-cell-inner';
    directionInner.innerHTML = `${ruleDirectionArrow(rule.direction)} <span>${escapeHtml(ruleDirectionLabel(rule.direction))}</span>`;

    directionCell.setAttribute('data-role', 'rule-direction');
    directionCell.title = ruleDirectionLabel(rule.direction);
    directionCell.appendChild(directionInner);
    row.appendChild(directionCell);

    const remoteCell = document.createElement('td');
    const remoteInner = document.createElement('div');
    remoteInner.className = 'rule-cell-inner';
    const remoteText = ruleRemotePatternLabel(rule.remotePattern);
    setHighlightedText(remoteInner, remoteText);
    remoteCell.title = remoteText;
    remoteCell.appendChild(remoteInner);
    row.appendChild(remoteCell);

    const protocolPortCell = document.createElement('td');
    const protocolPortInner = document.createElement('div');
    protocolPortInner.className = 'rule-cell-inner';
    const protocolPort = ruleProtocolPortLabel(rule.protocol, rule.port);
    if (rulesLastColumnSort === 'modificationDate') {
      protocolPortInner.textContent = shortDateTime(rule.modificationDate);
      protocolPortCell.title = window.formatDateTime(rule.modificationDate);
    } else if (rulesLastColumnSort === 'creationDate') {
      protocolPortInner.textContent = shortDateTime(rule.creationDate);
      protocolPortCell.title = window.formatDateTime(rule.creationDate);
    } else if (rulesLastColumnSort === 'precedence') {
      protocolPortInner.textContent = String((rulesOriginalOrder.get(rule.id) ?? 0) + 1);
    } else if (rulesLastColumnSort === 'priority') {
      protocolPortInner.textContent = rulePriorityLabel(rule.priority);
    } else {
      setHighlightedText(protocolPortInner, protocolPort.length > 0 ? protocolPort : '');
      protocolPortCell.title = protocolPort;
    }
    protocolPortCell.appendChild(protocolPortInner);
    row.appendChild(protocolPortCell);

    const actionsCell = document.createElement('td');
    const actionsInner = document.createElement('div');
    actionsInner.className = 'rule-cell-inner';
    const actionsWrapper = document.createElement('div');
    actionsWrapper.className = 'rule-row-actions';

    const editBtn = document.createElement('button');
    editBtn.type = 'button';
    editBtn.className = 'rule-row-btn';
    editBtn.title = window._localization.t('btn-edit-rule');
    editBtn.innerHTML = '<svg width="14" height="14" fill="currentColor"><use href="#rule-edit"/></svg>';
    editBtn.addEventListener('click', (event) => {
      event.stopPropagation();
      if (rule.id < 0) {
        alert(window._localization.t('alert-factory-rule'));
        return;
      }
      openRuleModal(rule);
    });
    actionsWrapper.appendChild(editBtn);

    const deleteBtn = document.createElement('button');
    deleteBtn.type = 'button';
    deleteBtn.className = 'rule-row-btn rule-row-btn-danger';
    deleteBtn.title = window._localization.t('btn-delete-rule');
    deleteBtn.innerHTML = '<svg width="14" height="14" fill="currentColor"><use href="#rule-delete"/></svg>';
    deleteBtn.addEventListener('click', (event) => {
      event.stopPropagation();
      if (rule.id < 0) {
        alert(window._localization.t('alert-factory-rule'));
        return;
      }
      if (window.app && typeof window.app.sendAction === 'function') {
        window.app.sendAction('deleteRules', { ruleIds: [rule.id] });
      }
    });
    actionsWrapper.appendChild(deleteBtn);
    actionsInner.appendChild(actionsWrapper);
    actionsCell.appendChild(actionsInner);

    row.appendChild(actionsCell);

    if (rule.isDisabled) {
      for (const cell of row.cells) {
        cell.classList.add('is-disabled');
      }
    }

    row.addEventListener('click', (event) => {
      ruleSelection.handleClick(event, index, rule.id);
    });
    row.addEventListener('dblclick', () => {
      if (rule.id < 0) {
        alert(window._localization.t('alert-factory-rule'));
        return;
      }
      openRuleModal(rule);
    });

    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  return table;
}

function refreshRuleSelectionStyles() {
  const container = document.getElementById('rules-list');
  if (!container) {
    return;
  }
  const rows = container.querySelectorAll('tbody tr[data-rule-id]');
  for (const row of rows) {
    const id = Number.parseInt(row.dataset.ruleId || '', 10);
    if (ruleSelection.has(id)) {
      row.classList.add('is-selected');
    } else {
      row.classList.remove('is-selected');
    }
  }
  renderRulesInspector();
  const deleteSelectedBtn = container.querySelector('[data-role="delete-selected-rules"]');
  if (deleteSelectedBtn) {
    deleteSelectedBtn.disabled = ruleSelection.size === 0;
  }
}

function navigateRulesSelection(delta, options = {}) {
  const nextIndex = ruleSelection.navigate(delta, options);
  if (nextIndex === false) {
    return false;
  }
  const nextRule = rulesDisplayedList[nextIndex];
  if (nextRule) {
    revealRuleInList(nextRule.id);
  }
  return true;
}

window.navigateRulesSelection = navigateRulesSelection;

function applyRulesData(rules, animateRowIds) {
  const container = document.getElementById('rules-list');
  if (!container) {
    return;
  }
  const details = document.getElementById('rules-details');

  container.innerHTML = '';
  rulesCurrentList = rules;
  rulesOriginalOrder = new Map(rules.map((r, i) => [r.id, i]));
  rulesDisplayedList = sortedRulesForDisplay(rulesCurrentList.filter(ruleMatchesSearch));

  const displayedIds = new Set(rulesDisplayedList.map((r) => r.id));
  const prunedIds = new Set([...ruleSelection.getAll()].filter((id) => displayedIds.has(id)));
  ruleSelection.setSelected(prunedIds);

  if (rulesDisplayedList.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = normalizedRulesSearchQuery().length > 0 ? window._localization.t('empty-no-matching-rules') : window._localization.t('empty-no-rules');
    container.appendChild(empty);
  } else {
    container.appendChild(renderRuleTable(rulesDisplayedList));
  }

  if (animateRowIds && animateRowIds.size > 0) {
    const tbody = container.querySelector('tbody');
    if (tbody) {
      for (const row of tbody.rows) {
        if (animateRowIds.has(Number(row.dataset.ruleId))) {
          row.classList.add('is-row-added');
          row.addEventListener('animationend', () => {
            row.classList.remove('is-row-added');
          }, { once: true });
        }
      }
    }
  }

  if (details) {
    renderRulesInspector();
  }
  if (pendingRevealRuleId !== null && ruleSelection.has(pendingRevealRuleId)) {
    if (revealRuleInList(pendingRevealRuleId)) {
      pendingRevealRuleId = null;
    }
  }
}

function handleSetRules(msg) {
  const rules = Array.isArray(msg.rules) ? msg.rules : [];
  applyRulesData(rules);
}
window.handleSetRules = handleSetRules;

let rulesUpdateTimer = null;

function applyUpdateRules(rulesRemoved, rulesAdded, addedIndexes, updatedIds) {
  rulesUpdateTimer = null;

  const removedSet = new Set(rulesRemoved);
  const nextRules = rulesCurrentList.filter((rule) => !removedSet.has(rule.id));

  const addedRuleIds = new Set();
  const purelyAddedIds = new Set(); // excludes rules that are updated (removed + re-added same ID)
  for (let i = 0; i < rulesAdded.length; i++) {
    const id = rulesAdded[i].id;
    addedRuleIds.add(id);
    if (!updatedIds.has(id)) {
      purelyAddedIds.add(id);
    }
    nextRules.splice(addedIndexes[i], 0, rulesAdded[i]);
  }

  if (addedRuleIds.size > 0) {
    ruleSelection.setSelected(addedRuleIds);
  }

  applyRulesData(nextRules, purelyAddedIds.size > 0 ? purelyAddedIds : undefined);

  if (addedRuleIds.size > 0) {
    refreshRuleSelectionStyles();
    const firstAddedId = rulesAdded[0].id;
    requestAnimationFrame(() => {
      const container = document.getElementById('rules-list');
      const row = container && container.querySelector(`tbody tr[data-rule-id="${firstAddedId}"]`);
      if (!row) {
        return;
      }
      const animatedEl = row.querySelector('.rule-cell-inner');
      if (animatedEl && row.classList.contains('is-row-added')) {
        animatedEl.addEventListener('animationend', () => revealRuleInList(firstAddedId), { once: true });
      } else {
        revealRuleInList(firstAddedId);
      }
    });
  }
}

function handleUpdateRules(msg) {
  const rulesRemoved = Array.isArray(msg.rulesRemoved) ? msg.rulesRemoved : [];
  const rulesAdded = Array.isArray(msg.rulesAdded) ? msg.rulesAdded : [];
  const addedIndexes = Array.isArray(msg.addedIndexes) ? msg.addedIndexes : [];
  if (rulesRemoved.length === 0 && rulesAdded.length === 0) {
    return;
  }

  // IDs that appear in both rulesRemoved and rulesAdded are updates (not pure inserts/removals).
  const addedIdSet = new Set(rulesAdded.map((r) => r.id));
  const updatedIds = new Set(rulesRemoved.filter((id) => addedIdSet.has(id)));

  // Cancel any pending removal animation from a previous update.
  if (rulesUpdateTimer !== null) {
    clearTimeout(rulesUpdateTimer);
    rulesUpdateTimer = null;
  }

  // Animate removal only for rows being purely removed (not updated).
  const purelyRemovedIds = new Set(rulesRemoved.filter((id) => !updatedIds.has(id)));
  if (purelyRemovedIds.size > 0) {
    const container = document.getElementById('rules-list');
    const tbody = container && container.querySelector('tbody');
    let hasFlash = false;
    if (tbody) {
      for (const row of tbody.rows) {
        if (purelyRemovedIds.has(Number(row.dataset.ruleId))) {
          row.classList.add('is-row-removing');
          hasFlash = true;
        }
      }
    }
    if (hasFlash) {
      rulesUpdateTimer = setTimeout(() => {
        applyUpdateRules(rulesRemoved, rulesAdded, addedIndexes, updatedIds);
      }, 250);
      return;
    }
  }

  applyUpdateRules(rulesRemoved, rulesAdded, addedIndexes, updatedIds);
}
window.handleUpdateRules = handleUpdateRules;
