// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

let rulesCurrentList = [];
let rulesDisplayedList = [];
let selectedRuleIds = new Set();
let ruleSelectionAnchorIndex = null;
let rulesSortCriteria = [{ key: 'process', order: 'asc' }];
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

function ruleDirectionArrow(direction) {
  switch (direction) {
    case 1:
      return '→';
    case 2:
      return '←';
    case 3:
      return '↔';
    default:
      return '→';
  }
}

function ruleDirectionLabel(direction) {
  switch (direction) {
    case 1:
      return 'out';
    case 2:
      return 'in';
    case 3:
      return 'both';
    default:
      return 'out';
  }
}

function rulePriorityLabel(priority) {
  const names = {
    0: 'Low',
    1: 'Regular',
    2: 'High',
    3: 'Extra High',
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
  return normalizedRuleAction(action) === 'allow' ? 'Allow' : 'Deny';
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
    return `Any Process via ${via}`;
  }
  return 'Any Process';
}

function ruleRemotePatternLabel(remotePattern) {
  if (!remotePattern || !remotePattern.type) {
    return 'Any Server';
  }
  switch (remotePattern.type) {
    case 'any':
      return 'Any Server';
    case 'localNet':
      return 'Local Network';
    case 'domains':
      return `domain ${remotePattern.value || ''}`.trim();
    case 'hosts':
    case 'ipAddresses':
      return remotePattern.value || '';
    default:
      return 'Any Server';
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
    default:
      return '';
  }
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
  selectedRuleIds = new Set([ruleId]);
  ruleSelectionAnchorIndex = null;
  pendingRevealRuleId = ruleId;
  if (rulesCurrentList.some((rule) => rule.id === ruleId)) {
    applyRulesData(rulesCurrentList);
  }
}

window.selectRuleInRulesSection = selectRuleInRulesSection;

function setRulesSearchQuery(query) {
  rulesSearchQuery = typeof query === 'string' ? query : '';
  ruleSelectionAnchorIndex = null;
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
  ruleSelectionAnchorIndex = null;
  applyRulesData(rulesCurrentList);
}

function ruleProtocolInspectorLabel(protocolMask) {
  if (protocolMask === 31) {
    return 'any protocol';
  }
  const protocols = ruleProtocolsFromMask(protocolMask);
  return protocols.length > 0 ? protocols.join(', ') : 'any protocol';
}

function rulePortInspectorLabel(portString) {
  if (!portString || portString === '0-65535') {
    return 'any port';
  }
  return portString;
}

function ruleRemoteInspectorLabel(remotePattern) {
  if (!remotePattern || !remotePattern.type || remotePattern.type === 'any') {
    return 'Any server';
  }
  if (remotePattern.type === 'localNet') {
    return 'Local Network';
  }
  const raw = (remotePattern.value || '').trim();
  const parts = raw.length === 0
    ? []
    : raw.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
  if (remotePattern.type === 'hosts') {
    return `${parts.length <= 1 ? 'Host' : 'Hosts'} ${parts.join(', ')}`.trim();
  }
  if (remotePattern.type === 'domains') {
    return `${parts.length <= 1 ? 'Domain' : 'Domains'} ${parts.join(', ')}`.trim();
  }
  if (remotePattern.type === 'ipAddresses') {
    return `${parts.length <= 1 ? 'Address' : 'Addresses'} ${parts.join(', ')}`.trim();
  }
  return 'Any server';
}

function ruleHeadlineLabel(rule) {
  const action = `${ruleActionEmoji(rule.action)} ${ruleActionLabel(rule.action)}`;
  const executable = rule.primaryExecutable
    ? (rule.viaExecutable ? `${rule.primaryExecutable} via ${rule.viaExecutable}` : rule.primaryExecutable)
    : (rule.viaExecutable ? `Any Process via ${rule.viaExecutable}` : 'Any Process');
  const direction = ruleDirectionArrow(rule.direction);
  const remote = ruleRemoteInspectorLabel(rule.remotePattern);
  return `${action} ${executable} ${direction} ${remote}`;
}

function ruleLifetimeLabel(lifetime) {
  if (typeof lifetime === 'string') {
    return lifetime;
  }
  if (lifetime && typeof lifetime === 'object') {
    const until = lifetime.until ?? lifetime.Until;
    if (typeof until === 'number') {
      return `Until ${new Date(until * 1000).toLocaleString()}`;
    }
  }
  return 'Forever';
}

function ruleTimeLabel(epochSeconds) {
  if (!epochSeconds || epochSeconds <= 0) {
    return '-';
  }
  return new Date(epochSeconds * 1000).toLocaleString();
}

function appendInspectorRow(grid, key, value) {
  const row = document.createElement('div');
  row.className = 'rule-inspector-row';

  const keyEl = document.createElement('div');
  keyEl.className = 'rule-inspector-key';
  keyEl.textContent = key;
  row.appendChild(keyEl);

  const valueEl = document.createElement('div');
  valueEl.className = 'rule-inspector-value';
  setHighlightedText(valueEl, value && value.length > 0 ? value : '-');
  row.appendChild(valueEl);

  grid.appendChild(row);
}

function appendInspectorBox(container, headline, content) {
  const block = document.createElement('div');
  block.className = 'rule-inspector-box-block';

  const head = document.createElement('div');
  head.className = 'rule-inspector-box-headline';
  head.textContent = headline;
  block.appendChild(head);

  const body = document.createElement('div');
  body.className = 'rule-inspector-box';
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
  card.className = 'rule-inspector-card';

  const title = document.createElement('div');
  title.className = 'rule-inspector-headline';
  setHighlightedText(title, ruleHeadlineLabel(rule));
  card.appendChild(title);

  const grid = document.createElement('div');
  grid.className = 'rule-inspector-grid';
  appendInspectorRow(grid, 'Action', `${ruleActionEmoji(rule.action)} ${ruleActionLabel(rule.action)}`);
  const executable = rule.primaryExecutable
    ? (rule.viaExecutable ? `${rule.primaryExecutable} via ${rule.viaExecutable}` : rule.primaryExecutable)
    : (rule.viaExecutable ? `Any Process via ${rule.viaExecutable}` : 'Any Process');
  appendInspectorRow(grid, 'Priority', rulePriorityLabel(rule.priority));
  appendInspectorRow(grid, 'Executable', executable);
  appendInspectorRow(grid, 'Direction', `${ruleDirectionArrow(rule.direction)} ${ruleDirectionLabel(rule.direction)}`);
  appendInspectorRow(grid, 'Remote', ruleRemoteInspectorLabel(rule.remotePattern));
  appendInspectorRow(grid, 'Protocol', ruleProtocolInspectorLabel(rule.protocol));
  appendInspectorRow(grid, 'Port', rulePortInspectorLabel(rule.port));
  appendInspectorRow(grid, 'Lifetime', ruleLifetimeLabel(rule.lifetime));
  appendInspectorRow(grid, 'Created', ruleTimeLabel(rule.creationDate));
  appendInspectorRow(grid, 'Modified', ruleTimeLabel(rule.modificationDate));
  card.appendChild(grid);

  const notesBlock = document.createElement('div');
  notesBlock.className = 'rule-inspector-box-block';
  const notesHeadline = document.createElement('div');
  notesHeadline.className = 'rule-inspector-box-headline';
  notesHeadline.textContent = 'Notes';
  notesBlock.appendChild(notesHeadline);
  const notesBox = document.createElement('div');
  notesBox.className = 'rule-inspector-box';
  const notesInput = document.createElement('textarea');
  notesInput.className = 'rule-inspector-notes-input';
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
  notesSave.className = 'blocklist-modal-button is-primary rule-inspector-save-button';
  notesSave.textContent = 'Save Notes';
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
    (rule) => selectedRuleIds.has(rule.id) && ruleMatchesSearch(rule),
  );
  if (selectedRules.length === 0) {
    const hint = document.createElement('div');
    hint.className = 'empty-state';
    hint.textContent = 'Select one or more rules to inspect.';
    details.appendChild(hint);
    return;
  }

  const container = document.createElement('div');
  container.className = 'rules-inspector';
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
    ? 'Remote Hosts'
    : remotePatternType === 4
      ? 'Remote Domains'
      : remotePatternType === 5
        ? 'Remote Addresses'
        : 'Remote Value';
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
    setRuleDialogError('Priority must be between 0 and 255.');
    return null;
  }

  const direction = Number.parseInt(ruleDialogDirection.value, 10);
  const protocol = Number.parseInt(ruleDialogProtocol.value, 10);
  const remotePatternType = Number.parseInt(ruleDialogRemoteType.value, 10);
  if (!Number.isFinite(direction) || !Number.isFinite(protocol) || !Number.isFinite(remotePatternType)) {
    setRuleDialogError('Direction, protocol and remote type are required.');
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
  dialog.className = 'blocklist-modal';

  const form = document.createElement('form');
  form.className = 'blocklist-modal-form';
  form.method = 'dialog';
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submitRuleModal();
  });

  const title = document.createElement('h2');
  title.className = 'blocklist-modal-title';
  title.textContent = 'Add Rule';
  form.appendChild(title);

  const hiddenId = document.createElement('input');
  hiddenId.type = 'hidden';
  hiddenId.name = 'ruleId';
  form.appendChild(hiddenId);

  const primaryLabel = document.createElement('label');
  primaryLabel.className = 'blocklist-modal-label';
  primaryLabel.textContent = 'Primary executable (optional)';
  const primaryInput = document.createElement('input');
  primaryInput.className = 'blocklist-modal-input';
  primaryInput.type = 'text';
  primaryLabel.appendChild(primaryInput);
  form.appendChild(primaryLabel);

  const viaLabel = document.createElement('label');
  viaLabel.className = 'blocklist-modal-label';
  viaLabel.textContent = 'Via executable (optional)';
  const viaInput = document.createElement('input');
  viaInput.className = 'blocklist-modal-input';
  viaInput.type = 'text';
  viaLabel.appendChild(viaInput);
  form.appendChild(viaLabel);

  const actionDirectionRow = document.createElement('div');
  actionDirectionRow.className = 'rule-modal-row';

  const actionLabel = document.createElement('label');
  actionLabel.className = 'blocklist-modal-label rule-modal-half';
  actionLabel.textContent = 'Action';
  const actionSelect = document.createElement('select');
  actionSelect.className = 'blocklist-modal-input';
  actionSelect.innerHTML = '<option value="allow">Allow</option><option value="deny">Deny</option>';
  actionLabel.appendChild(actionSelect);
  actionDirectionRow.appendChild(actionLabel);

  const directionLabel = document.createElement('label');
  directionLabel.className = 'blocklist-modal-label rule-modal-half';
  directionLabel.textContent = 'Direction';
  const directionSelect = document.createElement('select');
  directionSelect.className = 'blocklist-modal-input';
  directionSelect.innerHTML = '<option value="1">Out</option><option value="2">In</option><option value="3">Both</option>';
  directionLabel.appendChild(directionSelect);
  actionDirectionRow.appendChild(directionLabel);
  form.appendChild(actionDirectionRow);

  const remoteTypeLabel = document.createElement('label');
  remoteTypeLabel.className = 'blocklist-modal-label';
  remoteTypeLabel.textContent = 'Remote type';
  const remoteTypeSelect = document.createElement('select');
  remoteTypeSelect.className = 'blocklist-modal-input';
  remoteTypeSelect.innerHTML = [
    '<option value="1">Any server</option>',
    '<option value="2">Local network</option>',
    '<option value="3">Hosts</option>',
    '<option value="4">Domains</option>',
    '<option value="5">IP addresses</option>',
  ].join('');
  remoteTypeLabel.appendChild(remoteTypeSelect);
  form.appendChild(remoteTypeLabel);

  const remoteValueLabel = document.createElement('label');
  remoteValueLabel.className = 'blocklist-modal-label rule-modal-collapsible';
  const remoteValueTitle = document.createElement('span');
  remoteValueTitle.textContent = 'Remote Value';
  remoteValueLabel.appendChild(remoteValueTitle);
  const remoteValueInput = document.createElement('input');
  remoteValueInput.className = 'blocklist-modal-input';
  remoteValueInput.type = 'text';
  remoteValueLabel.appendChild(remoteValueInput);
  form.appendChild(remoteValueLabel);
  remoteTypeSelect.addEventListener('change', () => {
    updateRuleRemoteValueVisibility();
  });

  const protocolPortRow = document.createElement('div');
  protocolPortRow.className = 'rule-modal-row';

  const protocolLabel = document.createElement('label');
  protocolLabel.className = 'blocklist-modal-label rule-modal-half';
  protocolLabel.textContent = 'Protocol';
  const protocolSelect = document.createElement('select');
  protocolSelect.className = 'blocklist-modal-input';
  protocolSelect.innerHTML = [
    '<option value="31">Any</option>',
    '<option value="2">TCP</option>',
    '<option value="4">UDP</option>',
    '<option value="1">ICMP</option>',
    '<option value="8">SCTP</option>',
    '<option value="16">Other</option>',
  ].join('');
  protocolLabel.appendChild(protocolSelect);
  protocolPortRow.appendChild(protocolLabel);

  const portLabel = document.createElement('label');
  portLabel.className = 'blocklist-modal-label rule-modal-half';
  portLabel.textContent = 'Ports (e.g. 22, 443, 8000-9000)';
  const portInput = document.createElement('input');
  portInput.className = 'blocklist-modal-input';
  portInput.type = 'text';
  portInput.placeholder = 'Any';
  portLabel.appendChild(portInput);
  protocolPortRow.appendChild(portLabel);
  form.appendChild(protocolPortRow);

  const priorityEnabledRow = document.createElement('div');
  priorityEnabledRow.className = 'rule-modal-row';

  const priorityLabel = document.createElement('label');
  priorityLabel.className = 'blocklist-modal-label rule-modal-half';
  priorityLabel.textContent = 'Priority';
  const priorityInput = document.createElement('input');
  priorityInput.className = 'blocklist-modal-input';
  priorityInput.type = 'number';
  priorityInput.min = '0';
  priorityInput.max = '255';
  priorityLabel.appendChild(priorityInput);
  priorityEnabledRow.appendChild(priorityLabel);

  const enabledLabel = document.createElement('label');
  enabledLabel.className = 'blocklist-modal-checkbox-label rule-modal-half rule-modal-checkbox';
  const enabledInput = document.createElement('input');
  enabledInput.type = 'checkbox';
  enabledLabel.appendChild(enabledInput);
  enabledLabel.appendChild(document.createTextNode(' Rule is enabled'));
  priorityEnabledRow.appendChild(enabledLabel);
  form.appendChild(priorityEnabledRow);

  const notesLabel = document.createElement('label');
  notesLabel.className = 'blocklist-modal-label';
  notesLabel.textContent = 'Notes';
  const notesInput = document.createElement('textarea');
  notesInput.className = 'blocklist-modal-textarea';
  notesInput.rows = 3;
  notesLabel.appendChild(notesInput);
  form.appendChild(notesLabel);

  const error = document.createElement('div');
  error.className = 'blocklist-modal-error';
  form.appendChild(error);

  const actions = document.createElement('div');
  actions.className = 'blocklist-modal-actions';

  const cancelButton = document.createElement('button');
  cancelButton.type = 'button';
  cancelButton.className = 'blocklist-modal-button';
  cancelButton.textContent = 'Cancel';
  cancelButton.addEventListener('click', () => dialog.close());
  actions.appendChild(cancelButton);

  const saveButton = document.createElement('button');
  saveButton.type = 'submit';
  saveButton.className = 'blocklist-modal-button is-primary';
  saveButton.textContent = 'Save';
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
    ruleDialogTitle.textContent = 'Edit Rule';
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
    ruleDialogTitle.textContent = 'Add Rule';
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

function setupRulesHeaderButtons() {
  const title = document.querySelector('.section[data-section="rules"] .left-pane .pane-title');
  if (!title) {
    return;
  }

  if (!title.querySelector('[data-role="add-rule"]')) {
    title.classList.add('blocklist-pane-title');

    const label = document.createElement('span');
    label.textContent = title.textContent || 'Rule List';
    title.textContent = '';
    title.appendChild(label);

    const actions = document.createElement('div');
    actions.className = 'blocklist-pane-actions';
    title.appendChild(actions);

    const addButton = document.createElement('button');
    addButton.type = 'button';
    addButton.className = 'blocklist-add-button';
    addButton.setAttribute('data-role', 'add-rule');
    addButton.setAttribute('aria-label', 'Add rule');
    addButton.title = 'Add rule';
    addButton.textContent = '+';
    addButton.addEventListener('click', () => {
      openRuleModal(null);
    });
    actions.appendChild(addButton);
  }
}

function renderRuleTable(ruleList) {
  const table = document.createElement('table');
  table.className = 'rules-table';
  const thead = document.createElement('thead');
  const header = document.createElement('tr');
  const columns = [
    { title: '', sortKey: 'enabled' },
    { title: 'Action', sortKey: 'action' },
    { title: 'Process', sortKey: 'process' },
    { title: 'Dir', sortKey: 'direction' },
    { title: 'Server', sortKey: 'remote' },
    { title: 'Port', sortKey: 'port' },
    { title: '', sortKey: null },
  ];
  for (const column of columns) {
    const th = document.createElement('th');
    if (column.sortKey) {
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
    if (selectedRuleIds.has(rule.id)) {
      row.classList.add('is-selected');
    }
    const isHighPriority = (rule.priority || 0) > 1;
    if (isHighPriority) {
      row.classList.add('rule-high-priority');
    }

    const enabledCell = document.createElement('td');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'rule-enable-checkbox';
    checkbox.checked = !rule.isDisabled;
    checkbox.title = rule.isDisabled ? 'Disabled' : 'Enabled';
    checkbox.addEventListener('click', (event) => {
      event.stopPropagation();
    });
    checkbox.addEventListener('change', (event) => {
      event.stopPropagation();
      if (!window.app || typeof window.app.sendAction !== 'function') {
        return;
      }
      window.app.sendAction('toggleRuleEnabled', { ruleId: rule.id });
    });
    enabledCell.appendChild(checkbox);
    row.appendChild(enabledCell);

    const actionCell = document.createElement('td');
    const actionText = `${ruleActionEmoji(rule.action)} ${ruleActionLabel(rule.action)}`;
    setHighlightedText(actionCell, actionText);
    actionCell.title = actionText;
    row.appendChild(actionCell);

    const processCell = document.createElement('td');
    const processText = ruleProcessLabel(rule);
    setHighlightedText(processCell, processText);
    processCell.title = processText;
    row.appendChild(processCell);

    const directionCell = document.createElement('td');
    const directionText = `${ruleDirectionArrow(rule.direction)} ${ruleDirectionLabel(rule.direction)}`;
    setHighlightedText(directionCell, directionText);
    directionCell.title = directionText;
    row.appendChild(directionCell);

    const remoteCell = document.createElement('td');
    const remoteText = ruleRemotePatternLabel(rule.remotePattern);
    setHighlightedText(remoteCell, remoteText);
    remoteCell.title = remoteText;
    row.appendChild(remoteCell);

    const protocolPortCell = document.createElement('td');
    const protocolPort = ruleProtocolPortLabel(rule.protocol, rule.port);
    setHighlightedText(protocolPortCell, protocolPort.length > 0 ? protocolPort : '');
    protocolPortCell.title = protocolPort;
    row.appendChild(protocolPortCell);

    const actionsCell = document.createElement('td');
    actionsCell.className = 'rule-row-actions';

    const editBtn = document.createElement('button');
    editBtn.type = 'button';
    editBtn.className = 'rule-row-btn';
    editBtn.title = 'Edit rule';
    editBtn.textContent = '✎';
    editBtn.addEventListener('click', (event) => {
      event.stopPropagation();
      openRuleModal(rule);
    });
    actionsCell.appendChild(editBtn);

    const deleteBtn = document.createElement('button');
    deleteBtn.type = 'button';
    deleteBtn.className = 'rule-row-btn rule-row-btn-danger';
    deleteBtn.title = 'Delete rule';
    deleteBtn.textContent = '×';
    deleteBtn.addEventListener('click', (event) => {
      event.stopPropagation();
      if (window.app && typeof window.app.sendAction === 'function') {
        window.app.sendAction('deleteRules', { ruleIds: [rule.id] });
      }
    });
    actionsCell.appendChild(deleteBtn);

    row.appendChild(actionsCell);

    row.addEventListener('click', (event) => {
      updateRuleSelection(event, index, rule.id);
    });
    row.addEventListener('dblclick', () => {
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
    if (selectedRuleIds.has(id)) {
      row.classList.add('is-selected');
    } else {
      row.classList.remove('is-selected');
    }
  }
  setupRulesHeaderButtons();
  renderRulesInspector();
}

function updateRuleSelection(event, index, ruleId) {
  if (event.shiftKey && ruleSelectionAnchorIndex !== null) {
    const start = Math.min(ruleSelectionAnchorIndex, index);
    const end = Math.max(ruleSelectionAnchorIndex, index);
    if (!event.ctrlKey && !event.metaKey) {
      selectedRuleIds.clear();
    }
    for (let i = start; i <= end; i += 1) {
      selectedRuleIds.add(rulesDisplayedList[i].id);
    }
  } else if (event.ctrlKey || event.metaKey) {
    if (selectedRuleIds.has(ruleId)) {
      selectedRuleIds.delete(ruleId);
    } else {
      selectedRuleIds.add(ruleId);
    }
    ruleSelectionAnchorIndex = index;
  } else {
    selectedRuleIds.clear();
    selectedRuleIds.add(ruleId);
    ruleSelectionAnchorIndex = index;
  }
  refreshRuleSelectionStyles();
}

function selectedRuleIndices() {
  const indices = [];
  for (let i = 0; i < rulesDisplayedList.length; i += 1) {
    if (selectedRuleIds.has(rulesDisplayedList[i].id)) {
      indices.push(i);
    }
  }
  return indices;
}

function navigateRulesSelection(delta, options = {}) {
  if (delta !== 1 && delta !== -1) {
    return false;
  }
  if (rulesDisplayedList.length === 0) {
    return false;
  }

  const extend = options.extend === true;
  const selectedIndices = selectedRuleIndices();
  let currentIndex = ruleSelectionAnchorIndex;
  if (currentIndex === null || currentIndex < 0 || currentIndex >= rulesDisplayedList.length) {
    if (selectedIndices.length > 0) {
      currentIndex = delta > 0 ? selectedIndices[selectedIndices.length - 1] : selectedIndices[0];
    } else {
      currentIndex = delta > 0 ? -1 : rulesDisplayedList.length;
    }
  }

  const nextIndex = Math.max(0, Math.min(rulesDisplayedList.length - 1, currentIndex + delta));
  const nextRule = rulesDisplayedList[nextIndex];
  if (!nextRule) {
    return false;
  }

  if (extend) {
    if (ruleSelectionAnchorIndex === null
      || ruleSelectionAnchorIndex < 0
      || ruleSelectionAnchorIndex >= rulesDisplayedList.length) {
      ruleSelectionAnchorIndex = Math.max(0, Math.min(rulesDisplayedList.length - 1, currentIndex));
    }
    const start = Math.min(ruleSelectionAnchorIndex, nextIndex);
    const end = Math.max(ruleSelectionAnchorIndex, nextIndex);
    selectedRuleIds.clear();
    for (let i = start; i <= end; i += 1) {
      selectedRuleIds.add(rulesDisplayedList[i].id);
    }
  } else {
    selectedRuleIds.clear();
    selectedRuleIds.add(nextRule.id);
    ruleSelectionAnchorIndex = nextIndex;
  }

  refreshRuleSelectionStyles();
  revealRuleInList(nextRule.id);
  return true;
}

window.navigateRulesSelection = navigateRulesSelection;

function applyRulesData(rules) {
  const container = document.getElementById('rules-list');
  if (!container) {
    return;
  }
  const details = document.getElementById('rules-details');
  setupRulesHeaderButtons();

  container.innerHTML = '';
  rulesCurrentList = rules;
  rulesDisplayedList = sortedRulesForDisplay(rulesCurrentList.filter(ruleMatchesSearch));

  const displayedIds = new Set(rulesDisplayedList.map((r) => r.id));
  selectedRuleIds = new Set(Array.from(selectedRuleIds).filter((id) => displayedIds.has(id)));
  if (ruleSelectionAnchorIndex !== null
    && (ruleSelectionAnchorIndex < 0 || ruleSelectionAnchorIndex >= rulesDisplayedList.length)) {
    ruleSelectionAnchorIndex = null;
  }

  if (rulesDisplayedList.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = normalizedRulesSearchQuery().length > 0 ? 'No matching rules' : 'No rules';
    container.appendChild(empty);
  } else {
    container.appendChild(renderRuleTable(rulesDisplayedList));
  }

  if (details) {
    renderRulesInspector();
  }
  if (pendingRevealRuleId !== null && selectedRuleIds.has(pendingRevealRuleId)) {
    if (revealRuleInList(pendingRevealRuleId)) {
      pendingRevealRuleId = null;
    }
  }
  setupRulesHeaderButtons();
}

function handleSetRules(msg) {
  const rules = Array.isArray(msg.rules) ? msg.rules : [];
  applyRulesData(rules);
}

function handleUpdateRules(msg) {
  const rulesRemoved = Array.isArray(msg.rulesRemoved) ? msg.rulesRemoved : [];
  const rulesAdded = Array.isArray(msg.rulesAdded) ? msg.rulesAdded : [];
  if (rulesRemoved.length === 0 && rulesAdded.length === 0) {
    return;
  }

  const removedSet = new Set(rulesRemoved);
  const addedById = new Map();
  const addedOrder = [];
  for (const rule of rulesAdded) {
    if (!rule || typeof rule.id !== 'number') {
      continue;
    }
    if (!addedById.has(rule.id)) {
      addedOrder.push(rule.id);
    }
    addedById.set(rule.id, rule);
  }

  const nextRules = [];
  for (const rule of rulesCurrentList) {
    if (!rule || typeof rule.id !== 'number') {
      continue;
    }
    if (addedById.has(rule.id)) {
      nextRules.push(addedById.get(rule.id));
      addedById.delete(rule.id);
      continue;
    }
    if (removedSet.has(rule.id)) {
      continue;
    }
    nextRules.push(rule);
  }

  for (const id of addedOrder) {
    const rule = addedById.get(id);
    if (rule) {
      nextRules.push(rule);
    }
  }

  applyRulesData(nextRules);
}
