// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

const VIRTUAL_ROW_HEIGHT = 24;
const VIRTUAL_OVERSCAN = 20;
const VIRTUAL_PAGE_SIZE = 240;
const VIRTUAL_MAX_IN_FLIGHT = 2;
const detailsState = new Map(); // blocklistId -> { totalEntries, entries: Map<index, entry>, pending: Set<rangeKey> }
const blocklistsById = new Map(); // blocklistId -> blocklist
let previousBlocklistIds = null;
let blocklistUpdateTimer = null;
let activeVirtualList = null;
let activeDetailsBlocklistId = null;
let addBlocklistDialog = null;
let addBlocklistError = null;
let addBlocklistName = null;
let addBlocklistDescription = null;
let addBlocklistUrl = null;
let addBlocklistNamesAreHosts = null;
let addBlocklistUpdatePeriod = null;
let addBlocklistTitle = null;
let addBlocklistConfirm = null;
let addBlocklistPresetRow = null;
let editBlocklistId = null;
let addUserEntriesDialog = null;
let addUserEntriesError = null;
let addUserEntriesText = null;
let addUserEntriesNamesAreHosts = null;
const userEntrySelection = window.createMultiSelection({
  getCount: () => {
    const d = ensureBlocklistDetails(getSelectedBlocklistId());
    return d ? d.totalEntries : 0;
  },
  getItemByIndex: (i) => {
    const d = ensureBlocklistDetails(getSelectedBlocklistId());
    return d ? d.entries.get(i) : undefined;
  },
  getId: (entry) => entrySelectionKey(entry.entryType, entry.value),
  onChanged: () => { refreshVirtualList(); setupBlocklistDetailsHeaderAddButton(); },
});
let highlightedEntry = null; // { blocklistId, entryType, value }
let pendingLocateEntry = null; // { blocklistId, entryType, value, index, inFlight }
let pendingAddedEntryValues = null; // Set<string> of values just submitted via addUserBlocklistEntries
let pendingScrollToAdded = false; // scroll to the first newly added entry once

function getUpdatePeriodPresetOptions() {
  return [
    { minutes: 60,    label: window._localization.t('update-every-hour') },
    { minutes: 360,   label: window._localization.t('update-every-6-hours') },
    { minutes: 1440,  label: window._localization.t('update-every-day') },
    { minutes: 10080, label: window._localization.t('update-every-week') },
  ];
}

function blocklistPresets() {
  return [
    {
      name: window._localization.t('preset-name-none'),
      description: '',
      url: '',
      namesAreHosts: false
    },
    {
      name: 'Peter Lowe',
      description: window._localization.t('preset-description-lowe'),
      url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain&mimetype=plaintext',
      namesAreHosts: false
    },
    {
      name: 'Hagezi Multi PRO',
      description: window._localization.t('preset-description-hagezi-pro'),
      url: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.txt',
      namesAreHosts: false
    },
    {
      name: 'Hagezi Threat Intelligence Medium',
      description: window._localization.t('preset-description-hagezi-threat'),
      url: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt',
      namesAreHosts: false
    },
    {
      name: 'OISD.nl',
      description: window._localization.t('preset-description-oisd'),
      url: 'https://big.oisd.nl/domainswild2',
      namesAreHosts: false
    },
    {
      name: '1Hosts Lite',
      description: window._localization.t('preset-description-1hosts'),
      url: 'https://github.com/badmojr/1Hosts/raw/master/Lite/domains.txt',
      namesAreHosts: false
    },
    {
      name: 'FireHOL Level 1',
      description: window._localization.t('preset-description-firehol'),
      url: 'https://iplists.firehol.org/files/firehol_level1.netset',
      namesAreHosts: false
    }
  ];
}

function getUserBlocklistId() {
  if (window.app && typeof window.app.getUserBlocklistId === 'function') {
    return window.app.getUserBlocklistId();
  }
  return -1;
}

function ensureBlocklistDetails(blocklistId) {
  let details = detailsState.get(blocklistId);
  if (!details) {
    details = {
      totalEntries: 0,
      entries: new Map(),
      pending: new Set(),
    };
    detailsState.set(blocklistId, details);
  }
  return details;
}

function getBlocklistsDetailsContainer() {
  return document.querySelector('.section[data-section="blocklists"] [data-role="details"]');
}

function getBlocklistsSearchQuery() {
  const input = document.querySelector('.section[data-section="blocklists"] [data-role="search"]');
  if (!input) {
    return '';
  }
  return input.value.trim();
}

function setBlocklistsSearchQuery(query) {
  const input = document.querySelector('.section[data-section="blocklists"] [data-role="search"]');
  if (!input) {
    return;
  }
  const nextQuery = query || '';
  input.value = nextQuery;
  input.parentNode.classList.toggle('is-filtered', nextQuery.trim().length > 0);
  if (window.app && typeof window.app.sendAction === 'function') {
    window.app.sendAction('setSearch', { query: nextQuery });
  }
}

function getEmptyEntriesText() {
  return getBlocklistsSearchQuery().length > 0 ? window._localization.t('empty-no-matching-entries') : window._localization.t('empty-no-entries');
}

function getSelectedBlocklistId() {
  if (!window.app || typeof window.app.getSelectedBlocklistId !== 'function') {
    return getUserBlocklistId();
  }
  const id = window.app.getSelectedBlocklistId();
  return id === null || id === undefined ? getUserBlocklistId() : id;
}

function setSelectedBlocklistId(blocklistId) {
  if (!window.app || typeof window.app.setSelectedBlocklistId !== 'function') {
    return;
  }
  window.app.setSelectedBlocklistId(blocklistId);
}

function entryMatchesEntryRef(entry, entryRef) {
  return !!entry && !!entryRef && entry.entryType === entryRef.entryType && entry.value === entryRef.value;
}

function requestLocateBlocklistEntry() {
  if (!pendingLocateEntry || pendingLocateEntry.inFlight) {
    return;
  }
  if (!window.app || typeof window.app.sendAction !== 'function') {
    return;
  }
  pendingLocateEntry.inFlight = true;
  window.app.sendAction('locateBlocklistEntry', {
    blocklistId: pendingLocateEntry.blocklistId,
    entryType: pendingLocateEntry.entryType,
    value: pendingLocateEntry.value,
  });
}

function centerVirtualListOnIndex(ctx, index) {
  if (!ctx || !ctx.listEl || !Number.isFinite(index) || index < 0) {
    return;
  }
  const headerHeight = ctx.headerEl ? ctx.headerEl.offsetHeight : 0;
  const targetTop = Math.max(
    0,
    headerHeight
      + (index * VIRTUAL_ROW_HEIGHT)
      - (ctx.listEl.clientHeight / 2)
      + (VIRTUAL_ROW_HEIGHT / 2),
  );
  ctx.listEl.scrollTop = targetTop;
  renderVirtualListRows(ctx);
}

function requestEntryRangeAroundIndex(blocklistId, index) {
  if (!Number.isFinite(index) || index < 0) {
    return;
  }
  if (!window.app || typeof window.app.sendAction !== 'function') {
    return;
  }
  const start = Math.max(0, index - Math.floor(VIRTUAL_PAGE_SIZE / 2));
  window.app.sendAction('loadBlocklistEntries', {
    blocklistId,
    start,
    limit: VIRTUAL_PAGE_SIZE,
  });
}

function tryCompletePendingLocate() {
  if (!pendingLocateEntry) {
    return;
  }
  if (getSelectedBlocklistId() !== pendingLocateEntry.blocklistId) {
    return;
  }
  if (!Number.isFinite(pendingLocateEntry.index)) {
    requestLocateBlocklistEntry();
    return;
  }

  if (activeVirtualList && activeVirtualList.blocklistId === pendingLocateEntry.blocklistId) {
    centerVirtualListOnIndex(activeVirtualList, pendingLocateEntry.index);
  }

  const details = ensureBlocklistDetails(pendingLocateEntry.blocklistId);
  const entryAtIndex = details.entries.get(pendingLocateEntry.index);
  if (!entryMatchesEntryRef(entryAtIndex, pendingLocateEntry)) {
    requestEntryRangeAroundIndex(pendingLocateEntry.blocklistId, pendingLocateEntry.index);
    return;
  }

  highlightedEntry = {
    blocklistId: pendingLocateEntry.blocklistId,
    entryType: pendingLocateEntry.entryType,
    value: pendingLocateEntry.value,
  };
  pendingLocateEntry = null;
  refreshVirtualList();
}

function selectBlocklistEntryInBlocklist(entryType, value, blocklistId) {
  const targetBlocklistId = Number(blocklistId);
  if (!entryType || !value || !Number.isFinite(targetBlocklistId)) {
    return;
  }
  highlightedEntry = null;
  pendingLocateEntry = {
    blocklistId: targetBlocklistId,
    entryType,
    value,
    index: null,
    inFlight: false,
  };
  const blocklistsTab = document.querySelector('.tab[data-section="blocklists"]');
  if (blocklistsTab instanceof HTMLButtonElement) {
    blocklistsTab.click();
  }
  if (getSelectedBlocklistId() !== targetBlocklistId) {
    setSelectedBlocklistId(targetBlocklistId);
    if (window.app && typeof window.app.sendAction === 'function') {
      window.app.sendAction('selectBlocklist', { id: targetBlocklistId });
    }
  }
  renderBlocklistDetails();
  requestLocateBlocklistEntry();
}

window.selectBlocklistEntryInBlocklist = selectBlocklistEntryInBlocklist;

function handleSetBlocklistEntryLocation(msg) {
  if (!pendingLocateEntry) {
    return;
  }

  if (
    pendingLocateEntry.blocklistId !== msg.blocklistId
    || pendingLocateEntry.entryType !== msg.entryType
    || pendingLocateEntry.value !== msg.value
  ) {
    return;
  }

  pendingLocateEntry.inFlight = false;

  if (msg.clearSearch) {
    setBlocklistsSearchQuery('');
  }

  const index = msg.index;
  if (index === null || index === undefined) {
    pendingLocateEntry = null;
    return;
  }

  pendingLocateEntry.index = Number(index);
  renderBlocklistDetails();
  tryCompletePendingLocate();
}
window.handleSetBlocklistEntryLocation = handleSetBlocklistEntryLocation;

function setAddBlocklistError(message) {
  if (!addBlocklistError) {
    return;
  }
  addBlocklistError.textContent = message || '';
}

function setAddUserEntriesError(message) {
  if (!addUserEntriesError) {
    return;
  }
  addUserEntriesError.textContent = message || '';
}

function submitAddUserEntriesModal() {
  if (!addUserEntriesDialog || !addUserEntriesText || !addUserEntriesNamesAreHosts) {
    return;
  }
  const selectedId = getSelectedBlocklistId();
  if (selectedId !== getUserBlocklistId()) {
    addUserEntriesDialog.close();
    return;
  }
  const entries = addUserEntriesText.value
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (entries.length === 0) {
    setAddUserEntriesError(window._localization.t('err-add-at-least-one'));
    addUserEntriesText.focus();
    return;
  }
  const namesAreHosts = addUserEntriesNamesAreHosts.checked;
  if (window.app && typeof window.app.sendAction === 'function') {
    window.app.sendAction('addUserBlocklistEntries', { entries, namesAreHosts });
    pendingAddedEntryValues = new Set(entries);
    pendingScrollToAdded = true;
  }
  addUserEntriesDialog.close();
}

function ensureUserEntriesDialog() {
  if (addUserEntriesDialog) {
    return addUserEntriesDialog;
  }

  const dialog = document.createElement('dialog');
  dialog.className = 'edit-dialog';

  const form = document.createElement('form');
  form.className = 'edit-dialog-form';
  form.method = 'dialog';
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submitAddUserEntriesModal();
  });

  const title = document.createElement('h2');
  title.className = 'edit-dialog-title';
  title.textContent = window._localization.t('dlg-add-entries-title');
  form.appendChild(title);

  const entriesLabel = document.createElement('label');
  entriesLabel.className = 'edit-dialog-label';
  entriesLabel.textContent = window._localization.t('dlg-entries-label');
  const entriesInput = document.createElement('textarea');
  entriesInput.className = 'edit-dialog-textarea';
  entriesInput.name = 'entries';
  entriesInput.rows = 10;
  entriesLabel.appendChild(entriesInput);
  form.appendChild(entriesLabel);

  const namesAreHostsLabel = document.createElement('label');
  namesAreHostsLabel.className = 'edit-dialog-checkbox-label';
  const namesAreHostsInput = document.createElement('input');
  namesAreHostsInput.type = 'checkbox';
  namesAreHostsInput.name = 'namesAreHosts';
  namesAreHostsLabel.appendChild(namesAreHostsInput);
  namesAreHostsLabel.appendChild(document.createTextNode(window._localization.t('dlg-names-are-hosts')));
  form.appendChild(namesAreHostsLabel);

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

  const addButton = document.createElement('button');
  addButton.type = 'submit';
  addButton.className = 'edit-dialog-button is-primary';
  addButton.textContent = window._localization.t('btn-add');
  actions.appendChild(addButton);

  form.appendChild(actions);
  dialog.appendChild(form);

  dialog.addEventListener('close', () => {
    setAddUserEntriesError('');
    form.reset();
  });

  document.body.appendChild(dialog);

  addUserEntriesDialog = dialog;
  addUserEntriesError = error;
  addUserEntriesText = entriesInput;
  addUserEntriesNamesAreHosts = namesAreHostsInput;
  return dialog;
}

function openUserEntriesModal() {
  const dialog = ensureUserEntriesDialog();
  setAddUserEntriesError('');
  dialog.showModal();
  if (addUserEntriesText) {
    addUserEntriesText.focus();
  }
}

function isUserBlocklistSelected() {
  return getSelectedBlocklistId() === getUserBlocklistId();
}

function entrySelectionKey(entryType, value) {
  return `${entryType}\n${value}`;
}

function clearSelectedUserEntries() {
  userEntrySelection.clear();
}

function submitBlocklistModal() {
  if (
    !addBlocklistDialog
    || !addBlocklistName
    || !addBlocklistDescription
    || !addBlocklistUrl
    || !addBlocklistNamesAreHosts
  ) {
    return;
  }

  const name = addBlocklistName.value.trim();
  const description = addBlocklistDescription.value.trim();
  const updateFromUrl = addBlocklistUrl.value.trim();
  const namesAreHosts = addBlocklistNamesAreHosts.checked;
  const updatePeriodMinutes = addBlocklistUpdatePeriod
    ? Number(addBlocklistUpdatePeriod.value)
    : 1440;

  if (name.length === 0) {
    setAddBlocklistError(window._localization.t('err-name-required'));
    addBlocklistName.focus();
    return;
  }
  if (updateFromUrl.length === 0) {
    setAddBlocklistError(window._localization.t('err-url-required'));
    addBlocklistUrl.focus();
    return;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(updateFromUrl);
  } catch (_error) {
    setAddBlocklistError(window._localization.t('err-url-invalid'));
    addBlocklistUrl.focus();
    return;
  }
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    setAddBlocklistError(window._localization.t('err-url-http-only'));
    addBlocklistUrl.focus();
    return;
  }
  if (!Number.isFinite(updatePeriodMinutes) || updatePeriodMinutes <= 0) {
    setAddBlocklistError(window._localization.t('err-update-period-invalid'));
    addBlocklistUpdatePeriod?.focus();
    return;
  }

  if (window.app && typeof window.app.sendAction === 'function') {
    if (editBlocklistId === null || editBlocklistId === undefined) {
      window.app.sendAction('addBlocklist', {
        name,
        description,
        updateFromUrl,
        namesAreHosts,
        updatePeriodMinutes,
      });
    } else {
      window.app.sendAction('editBlocklist', {
        blocklistId: editBlocklistId,
        name,
        description,
        updateFromUrl,
        namesAreHosts,
        updatePeriodMinutes,
      });
    }
  }
  addBlocklistDialog.close();
}

function ensureAddBlocklistDialog() {
  if (addBlocklistDialog) {
    return addBlocklistDialog;
  }

  const dialog = document.createElement('dialog');
  dialog.className = 'edit-dialog';

  const form = document.createElement('form');
  form.className = 'edit-dialog-form';
  form.method = 'dialog';
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submitBlocklistModal();
  });

  const title = document.createElement('h2');
  title.className = 'edit-dialog-title';
  title.textContent = window._localization.t('dlg-add-blocklist-title');
  form.appendChild(title);

  const presetLabel = document.createElement('label');
  presetLabel.className = 'edit-dialog-label';
  presetLabel.textContent = window._localization.t('preset-label');
  const presetSelect = document.createElement('select');
  presetSelect.className = 'edit-dialog-select';
  presetSelect.name = 'preset';

  const presets = blocklistPresets();
  presets.forEach((preset, index) => {
    const opt = document.createElement('option');
    opt.value = String(index);
    opt.textContent = preset.name;
    presetSelect.appendChild(opt);
  });
  presetSelect.addEventListener('change', () => {
    const preset = presets[Number(presetSelect.value)];
    if (preset) {
      nameInput.value = preset.name;
      descriptionInput.value = preset.description;
      urlInput.value = preset.url;
      namesAreHostsInput.checked = preset.namesAreHosts;
    }
  });

  presetLabel.appendChild(presetSelect);
  form.appendChild(presetLabel);
  addBlocklistPresetRow = presetLabel;

  const nameLabel = document.createElement('label');
  nameLabel.className = 'edit-dialog-label';
  nameLabel.textContent = window._localization.t('dlg-name-label');
  const nameInput = document.createElement('input');
  nameInput.className = 'edit-dialog-input';
  nameInput.type = 'text';
  nameInput.name = 'name';
  nameInput.required = true;
  nameLabel.appendChild(nameInput);
  form.appendChild(nameLabel);

  const descriptionLabel = document.createElement('label');
  descriptionLabel.className = 'edit-dialog-label';
  descriptionLabel.textContent = window._localization.t('dlg-description-label');
  const descriptionInput = document.createElement('textarea');
  descriptionInput.className = 'edit-dialog-textarea';
  descriptionInput.name = 'description';
  descriptionInput.rows = 5;
  descriptionLabel.appendChild(descriptionInput);
  form.appendChild(descriptionLabel);

  const urlLabel = document.createElement('label');
  urlLabel.className = 'edit-dialog-label';
  urlLabel.textContent = window._localization.t('dlg-url-label');
  const urlInput = document.createElement('input');
  urlInput.className = 'edit-dialog-input';
  urlInput.type = 'url';
  urlInput.name = 'url';
  urlInput.required = true;
  urlInput.placeholder = 'https://example.com/blocklist.txt';
  urlLabel.appendChild(urlInput);
  form.appendChild(urlLabel);

  const namesAreHostsLabel = document.createElement('label');
  namesAreHostsLabel.className = 'edit-dialog-checkbox-label';
  const namesAreHostsInput = document.createElement('input');
  namesAreHostsInput.type = 'checkbox';
  namesAreHostsInput.name = 'namesAreHosts';
  namesAreHostsLabel.appendChild(namesAreHostsInput);
  namesAreHostsLabel.appendChild(document.createTextNode(window._localization.t('dlg-treat-as-hostnames')));
  form.appendChild(namesAreHostsLabel);

  const updatePeriodLabel = document.createElement('label');
  updatePeriodLabel.className = 'edit-dialog-label';
  updatePeriodLabel.textContent = window._localization.t('dlg-update-period-label');
  const updatePeriodSelect = document.createElement('select');
  updatePeriodSelect.className = 'edit-dialog-select';
  updatePeriodSelect.name = 'updatePeriodMinutes';
  updatePeriodLabel.appendChild(updatePeriodSelect);
  form.appendChild(updatePeriodLabel);

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

  const addButton = document.createElement('button');
  addButton.type = 'submit';
  addButton.className = 'edit-dialog-button is-primary';
  addButton.textContent = window._localization.t('btn-add');
  actions.appendChild(addButton);

  form.appendChild(actions);
  dialog.appendChild(form);

  dialog.addEventListener('close', () => {
    setAddBlocklistError('');
    editBlocklistId = null;
    form.reset();
  });

  document.body.appendChild(dialog);

  addBlocklistDialog = dialog;
  addBlocklistError = error;
  addBlocklistName = nameInput;
  addBlocklistDescription = descriptionInput;
  addBlocklistUrl = urlInput;
  addBlocklistNamesAreHosts = namesAreHostsInput;
  addBlocklistUpdatePeriod = updatePeriodSelect;
  addBlocklistTitle = title;
  addBlocklistConfirm = addButton;
  setUpdatePeriodOptions(1440);
  return dialog;
}

function openBlocklistModal(blocklist) {
  const dialog = ensureAddBlocklistDialog();
  setAddBlocklistError('');
  if (blocklist) {
    editBlocklistId = blocklist.id;
    addBlocklistPresetRow.style.display = 'none';
    addBlocklistTitle.textContent = window._localization.t('dlg-edit-blocklist-title');
    addBlocklistConfirm.textContent = window._localization.t('btn-save');
    addBlocklistName.value = blocklist.name || '';
    addBlocklistDescription.value = blocklist.description || '';
    addBlocklistUrl.value = blocklist.updateFromUrl || '';
    addBlocklistNamesAreHosts.checked = blocklist.namesAreHosts === true;
    setUpdatePeriodOptions(blocklist.updatePeriodMinutes);
  } else {
    editBlocklistId = null;
    addBlocklistPresetRow.style.display = '';
    addBlocklistTitle.textContent = window._localization.t('dlg-add-blocklist-title');
    addBlocklistConfirm.textContent = window._localization.t('btn-add');
    addBlocklistDialog.querySelector('form')?.reset();
    setUpdatePeriodOptions(1440);
  }
  dialog.showModal();
  if (addBlocklistName) {
    addBlocklistName.focus();
  }
}

function setupBlocklistHeaderAddButton() {
  const title = document.querySelector('.section[data-section="blocklists"] .left-pane .pane-title');
  if (!title || title.querySelector('[data-role="add-blocklist"]')) {
    return;
  }

  title.classList.add('blocklist-pane-title');

  const label = document.createElement('span');
  label.textContent = title.textContent || window._localization.t('blocklists-header');
  title.textContent = '';
  title.appendChild(label);

  const addButton = document.createElement('button');
  addButton.type = 'button';
  addButton.className = 'blocklist-add-button';
  addButton.setAttribute('data-role', 'add-blocklist');
  addButton.setAttribute('aria-label', window._localization.t('btn-add-blocklist'));
  addButton.title = window._localization.t('btn-add-blocklist');
  addButton.innerHTML = '<svg width="14" height="14" fill="currentColor"><use href="#btn-add"/></svg>';
  addButton.addEventListener('click', () => {
    openBlocklistModal(null);
  });
  title.appendChild(addButton);
}

function setupBlocklistDetailsHeaderAddButton() {
  const title = document.querySelector('.section[data-section="blocklists"] .right-pane .pane-title');
  if (!title) {
    return;
  }

  let addButton = title.querySelector('[data-role="add-user-entries"]');
  let removeButton = title.querySelector('[data-role="remove-user-entries"]');
  let actions = title.querySelector('[data-role="user-entries-actions"]');
  if (!addButton || !removeButton) {
    title.classList.add('blocklist-pane-title');

    const label = document.createElement('span');
    label.textContent = title.textContent || window._localization.t('blocklist-details-header');
    title.textContent = '';
    title.appendChild(label);

    actions = document.createElement('div');
    actions.className = 'blocklist-pane-actions';
    actions.setAttribute('data-role', 'user-entries-actions');
    title.appendChild(actions);

    addButton = document.createElement('button');
    addButton.type = 'button';
    addButton.className = 'blocklist-add-button';
    addButton.setAttribute('data-role', 'add-user-entries');
    addButton.setAttribute('aria-label', window._localization.t('btn-add-entries'));
    addButton.title = window._localization.t('btn-add-entries');
    addButton.innerHTML = '<svg width="14" height="14" fill="currentColor"><use href="#btn-add"/></svg>';
    addButton.hidden = true;
    addButton.addEventListener('click', () => {
      openUserEntriesModal();
    });
    actions.appendChild(addButton);

    removeButton = document.createElement('button');
    removeButton.type = 'button';
    removeButton.className = 'blocklist-add-button';
    removeButton.setAttribute('data-role', 'remove-user-entries');
    removeButton.setAttribute('aria-label', window._localization.t('btn-remove-entries'));
    removeButton.title = window._localization.t('btn-remove-entries');
    removeButton.innerHTML = '<svg width="18" height="18" fill="currentColor"><use href="#btn-remove"/></svg>';
    removeButton.hidden = true;
    removeButton.disabled = true;
    removeButton.addEventListener('click', () => {
      if (userEntrySelection.size === 0) {
        return;
      }
      if (window.app && typeof window.app.sendAction === 'function') {
        const selectedIds = userEntrySelection.getAll();
        const d = ensureBlocklistDetails(getSelectedBlocklistId());
        const entries = d
          ? Array.from(d.entries.values())
            .filter((e) => selectedIds.has(entrySelectionKey(e.entryType, e.value)))
            .map((e) => ({ entryType: e.entryType, value: e.value }))
          : [];
        window.app.sendAction('removeUserBlocklistEntries', { entries });
      }
      clearSelectedUserEntries();
      refreshVirtualList();
      setupBlocklistDetailsHeaderAddButton();
    });
    actions.appendChild(removeButton);
  }

  const visible = isUserBlocklistSelected();
  addButton.hidden = !visible;
  removeButton.hidden = !visible;
  removeButton.disabled = userEntrySelection.size === 0;
}

function formatEntryTitle(entry) {
  const value = entry.value || '';
  if (entry.entryType === 'domain') {
    return `domain ${value}`;
  }
  return value;
}

function formatLocalTime(secondsSinceEpoch) {
  return window.formatDateTime(Number(secondsSinceEpoch));
}

function normalizeUpdatePeriodMinutes(value) {
  const minutes = Number(value);
  if (!Number.isFinite(minutes) || minutes <= 0) {
    return 1440;
  }
  return Math.max(1, Math.round(minutes));
}

function formatUpdatePeriodForDisplay(minutesValue) {
  const minutes = normalizeUpdatePeriodMinutes(minutesValue);
  if (minutes === 60) {
    return window._localization.t('update-every-hour');
  }
  if (minutes === 360) {
    return window._localization.t('update-every-6-hours');
  }
  if (minutes === 1440) {
    return window._localization.t('update-every-day');
  }
  if (minutes === 10080) {
    return window._localization.t('update-every-week');
  }
  if (minutes < 120) {
    return window._localization.t('update-every-minutes', { n: minutes });
  } else if (minutes < 2880) {
    return window._localization.t('update-every-hours', { n: Math.round(minutes / 60) });
  } else {
    return window._localization.t('update-every-days', { n: Math.round(minutes / 1440) });
  }
}

function setUpdatePeriodOptions(selectedMinutesValue) {
  if (!addBlocklistUpdatePeriod) {
    return;
  }
  const selectedMinutes = normalizeUpdatePeriodMinutes(selectedMinutesValue);
  addBlocklistUpdatePeriod.innerHTML = '';

  const presetOptions = getUpdatePeriodPresetOptions();
  const presetMinutes = new Set(presetOptions.map((option) => option.minutes));
  presetOptions.forEach((option) => {
    const optionEl = document.createElement('option');
    optionEl.value = String(option.minutes);
    optionEl.textContent = option.label;
    addBlocklistUpdatePeriod.appendChild(optionEl);
  });
  if (!presetMinutes.has(selectedMinutes)) {
    const extraOption = document.createElement('option');
    extraOption.value = String(selectedMinutes);
    extraOption.textContent = formatUpdatePeriodForDisplay(selectedMinutes);
    addBlocklistUpdatePeriod.appendChild(extraOption);
  }
  addBlocklistUpdatePeriod.value = String(selectedMinutes);
}

function animateBlocklistReflow(table, mutateLayout) {
  if (!table || typeof mutateLayout !== 'function') {
    return;
  }

  const cards = Array.from(table.querySelectorAll('.blocklist-card'));
  const firstPositions = new Map();
  cards.forEach((card) => {
    firstPositions.set(card, card.getBoundingClientRect().top);
  });

  mutateLayout();

  cards.forEach((card) => {
    const firstTop = firstPositions.get(card);
    if (firstTop === undefined) {
      return;
    }

    const lastTop = card.getBoundingClientRect().top;
    const deltaY = firstTop - lastTop;
    if (Math.abs(deltaY) < 0.5) {
      return;
    }

    card.style.transition = 'none';
    card.style.transform = `translateY(${deltaY}px)`;
    card.getBoundingClientRect();

    requestAnimationFrame(() => {
      card.style.transition = 'transform 180ms ease';
      card.style.transform = '';
    });

    card.addEventListener('transitionend', () => {
      card.style.transition = '';
      card.style.transform = '';
    }, { once: true });
  });
}

function renderBlocklist(blocklist) {
  const container = document.createElement('div');
  container.className = 'blocklist-card';
  container.dataset.blocklistId = String(blocklist.id);
  if (blocklist.id === getSelectedBlocklistId()) {
    container.classList.add('is-selected');
  }
  if (blocklist.disabled === true) {
    container.classList.add('is-disabled');
  }

  const headlineRow = document.createElement('div');
  headlineRow.className = 'blocklist-card-headline';

  const enabledCheckbox = document.createElement('input');
  enabledCheckbox.type = 'checkbox';
  enabledCheckbox.className = 'blocklist-card-checkbox';
  enabledCheckbox.checked = blocklist.disabled !== true;
  enabledCheckbox.disabled = blocklist.id < 0;
  enabledCheckbox.title = blocklist.disabled !== true ? window._localization.t('enabled') : window._localization.t('disabled');
  enabledCheckbox.addEventListener('click', (event) => {
    event.stopPropagation();
  });
  enabledCheckbox.addEventListener('change', (event) => {
    event.stopPropagation();
    if (blocklist.id < 0) {
      return;
    }
    blocklist.disabled = !enabledCheckbox.checked;
    const knownBlocklist = blocklistsById.get(blocklist.id);
    if (knownBlocklist) {
      knownBlocklist.disabled = blocklist.disabled;
    }
    if (window.app && typeof window.app.sendAction === 'function') {
      window.app.sendAction('setBlocklistDisabled', {
        blocklistId: blocklist.id,
        isDisabled: !enabledCheckbox.checked,
      });
    }
  });
  headlineRow.appendChild(enabledCheckbox);

  const name = document.createElement('div');
  name.className = 'blocklist-name';
  if (blocklist.lastUpdateError) {
    name.classList.add('blocklist-update-row-error');
    name.textContent = blocklist.name + ' (update failed)';
  } else {
    name.textContent = blocklist.name;
  }
  headlineRow.appendChild(name);

  const actions = document.createElement('div');
  actions.className = 'blocklist-card-actions';

  if (blocklist.id >= 0) {
    const editButton = document.createElement('button');
    editButton.type = 'button';
    editButton.className = 'blocklist-card-btn';
    editButton.title = window._localization.t('btn-edit-blocklist');
    editButton.textContent = '✎';
    editButton.addEventListener('click', (event) => {
      event.stopPropagation();
      openBlocklistModal(blocklist);
    });
    actions.appendChild(editButton);

    const deleteButton = document.createElement('button');
    deleteButton.type = 'button';
    deleteButton.className = 'blocklist-card-btn blocklist-card-btn-danger';
    deleteButton.title = window._localization.t('btn-delete-blocklist');
    deleteButton.textContent = '×';
    deleteButton.addEventListener('click', (event) => {
      event.stopPropagation();
      if (window.app && typeof window.app.sendAction === 'function') {
        window.app.sendAction('deleteBlocklist', { blocklistId: blocklist.id });
      }
    });
    actions.appendChild(deleteButton);
  }

  headlineRow.appendChild(actions);
  container.appendChild(headlineRow);

  const description = document.createElement('div');
  description.className = 'blocklist-description';
  description.textContent = blocklist.description || '';
  container.appendChild(description);

  container.addEventListener('click', () => {
    const previousSelection = getSelectedBlocklistId();
    const nextSelection = blocklist.id;
    if (previousSelection !== nextSelection && previousSelection === getUserBlocklistId()) {
      clearSelectedUserEntries();
    }
    const table = document.getElementById('blocklists');
    animateBlocklistReflow(table, () => {
      setSelectedBlocklistId(nextSelection);

      if (window.app && typeof window.app.sendAction === 'function') {
        window.app.sendAction('selectBlocklist', { id: nextSelection });
      }

      table.querySelectorAll('.blocklist-card').forEach((card) => {
        card.classList.remove('is-selected');
      });
      container.classList.add('is-selected');
    });

    renderBlocklistDetails();
  });

  return container;
}

function parseBlocklistIdFromCard(card) {
  if (!card) {
    return null;
  }
  const id = Number(card.dataset.blocklistId);
  return Number.isFinite(id) ? id : null;
}

function navigateBlocklistsSelection(delta) {
  if (delta !== 1 && delta !== -1) {
    return false;
  }
  const list = document.getElementById('blocklists');
  if (!list) {
    return false;
  }
  const cards = Array.from(list.querySelectorAll('.blocklist-card'));
  if (cards.length === 0) {
    return false;
  }

  const selectedId = getSelectedBlocklistId();
  let currentIndex = cards.findIndex((card) => card.classList.contains('is-selected'));
  if (currentIndex < 0) {
    currentIndex = cards.findIndex((card) => parseBlocklistIdFromCard(card) === selectedId);
  }
  if (currentIndex < 0) {
    currentIndex = delta > 0 ? -1 : cards.length;
  }

  const nextIndex = Math.max(0, Math.min(cards.length - 1, currentIndex + delta));
  const nextCard = cards[nextIndex];
  if (!nextCard) {
    return false;
  }
  nextCard.click();
  nextCard.scrollIntoView({ block: 'nearest' });
  return true;
}

window.navigateBlocklistsSelection = navigateBlocklistsSelection;

function setDetailsEmptyState(container, text) {
  container.innerHTML = '';
  const empty = document.createElement('div');
  empty.className = 'blocklist-details-empty';
  empty.textContent = text;
  container.appendChild(empty);
}

function renderEntryRow(entry, index) {
  const row = document.createElement('div');
  row.className = 'blocklist-entry-row';
  const parentBlocklist = blocklistsById.get(getSelectedBlocklistId());
  if (entry.isDisabled || parentBlocklist?.disabled === true) {
    row.classList.add('is-disabled');
  }

  if (
    highlightedEntry
    && highlightedEntry.blocklistId === getSelectedBlocklistId()
    && entryMatchesEntryRef(entry, highlightedEntry)
  ) {
    row.classList.add('is-highlighted');
  }

  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.className = 'blocklist-entry-checkbox';
  checkbox.checked = !entry.isDisabled;
  checkbox.title = entry.isDisabled ? window._localization.t('disabled') : window._localization.t('enabled');
  checkbox.addEventListener('click', (event) => {
    event.stopPropagation();
  });
  checkbox.addEventListener('change', () => {
    if (!window.app || typeof window.app.sendAction !== 'function') {
      return;
    }
    const value = entry.value;
    if (!value) {
      return;
    }
    const entryType = entry.entryType;
    window.app.sendAction('setBlocklistEntryDisabled', { entryType, value, isDisabled: !entry.isDisabled });
  });
  row.appendChild(checkbox);

  const title = document.createElement('div');
  title.className = 'blocklist-entry-title';

  const valueSpan = document.createElement('span');
  valueSpan.className = 'blocklist-entry-value';
  valueSpan.textContent = formatEntryTitle(entry);
  title.appendChild(valueSpan);

  if (Array.isArray(entry.blocklists) && entry.blocklists.length > 0) {
    window.appendBlocklistNamesInfo(title, entry.blocklists.map(id => blocklistsById.get(id)?.name).filter(Boolean));
  }

  row.appendChild(title);

  if (isUserBlocklistSelected()) {
    const key = entrySelectionKey(entry.entryType, entry.value);
    if (userEntrySelection.has(key)) {
      row.classList.add('is-selected');
    }
    row.addEventListener('click', (event) => {
      if (activeVirtualList) {
        activeVirtualList.listEl.focus({ preventScroll: true });
      }
      userEntrySelection.handleClick(event, index, key);
    });
  }

  return row;
}

function renderPlaceholderRow() {
  const row = document.createElement('div');
  row.className = 'blocklist-entry-row is-placeholder';

  const spacer = document.createElement('div');
  spacer.className = 'blocklist-entry-checkbox';
  row.appendChild(spacer);

  const label = document.createElement('div');
  label.className = 'blocklist-entry-title';
  label.textContent = window._localization.t('loading');
  row.appendChild(label);

  return row;
}

function requestMissingRanges(ctx, startIndex, endIndex) {
  const details = ensureBlocklistDetails(ctx.blocklistId);
  const loaded = details.entries;

  if (details.pending.size >= VIRTUAL_MAX_IN_FLIGHT) {
    return;
  }

  let firstMissing = null;
  for (let i = startIndex; i <= endIndex; i += 1) {
    if (!loaded.has(i)) {
      firstMissing = i;
      break;
    }
  }
  if (firstMissing === null) {
    return;
  }

  const rangeStart = firstMissing;
  let rangeEnd = firstMissing;
  while (
    rangeEnd + 1 <= endIndex
    && !loaded.has(rangeEnd + 1)
    && (rangeEnd - rangeStart + 1) < VIRTUAL_PAGE_SIZE
  ) {
    rangeEnd += 1;
  }

  const key = `${rangeStart}:${rangeEnd}`;
  if (details.pending.has(key)) {
    return;
  }
  if (!window.app || typeof window.app.sendAction !== 'function') {
    return;
  }

  details.pending.add(key);
  window.app.sendAction('loadBlocklistEntries', {
    blocklistId: ctx.blocklistId,
    start: rangeStart,
    limit: rangeEnd - rangeStart + 1,
  });
}

function clearPendingForRange(details, start, end) {
  const toDelete = [];
  details.pending.forEach((key) => {
    const parts = key.split(':');
    if (parts.length !== 2) {
      return;
    }
    const pendingStart = Number(parts[0]);
    const pendingEnd = Number(parts[1]);
    if (Number.isNaN(pendingStart) || Number.isNaN(pendingEnd)) {
      return;
    }
    // Drop any pending request that overlaps this returned chunk.
    if (pendingStart <= end && pendingEnd >= start) {
      toDelete.push(key);
    }
  });
  toDelete.forEach((key) => details.pending.delete(key));
}

// Render only the rows currently in (or near) the visible viewport.
// Top and bottom spacer divs fill the space occupied by off-screen rows so
// the scrollbar thumb reflects the full list length. Missing entries trigger
// a backend fetch and are shown as placeholders until the data arrives.
function renderVirtualListRows(ctx) {
  const details = ensureBlocklistDetails(ctx.blocklistId);
  const total = details.totalEntries || 0;

  if (total === 0) {
    ctx.rowsContainer.innerHTML = '';
    ctx.topSpacer.style.height = '0px';
    ctx.bottomSpacer.style.height = '0px';
    const empty = document.createElement('div');
    empty.className = 'blocklist-entry-empty';
    empty.textContent = getEmptyEntriesText();
    ctx.rowsContainer.appendChild(empty);
    return;
  }

  const headerHeight = ctx.headerEl ? ctx.headerEl.offsetHeight : 0;
  const scrollTop = Math.max(0, ctx.listEl.scrollTop - headerHeight);
  const visibleRows = Math.max(1, Math.ceil(ctx.listEl.clientHeight / VIRTUAL_ROW_HEIGHT));

  const startIndex = Math.max(0, Math.floor(scrollTop / VIRTUAL_ROW_HEIGHT) - VIRTUAL_OVERSCAN);
  const endIndex = Math.min(total - 1, startIndex + visibleRows + (VIRTUAL_OVERSCAN * 2));

  requestMissingRanges(ctx, startIndex, endIndex);

  ctx.topSpacer.style.height = `${startIndex * VIRTUAL_ROW_HEIGHT}px`;
  ctx.bottomSpacer.style.height = `${Math.max(0, (total - endIndex - 1) * VIRTUAL_ROW_HEIGHT)}px`;

  const loaded = details.entries;
  ctx.rowsContainer.innerHTML = '';

  for (let idx = startIndex; idx <= endIndex; idx += 1) {
    const entry = loaded.get(idx);
    if (entry) {
      ctx.rowsContainer.appendChild(renderEntryRow(entry, idx));
    } else {
      ctx.rowsContainer.appendChild(renderPlaceholderRow());
    }
  }
}

function refreshVirtualList() {
  if (activeVirtualList) {
    renderVirtualListRows(activeVirtualList);
  }
}

function renderBlocklistPropertiesCard(blocklist) {
  const card = document.createElement('div');
  card.className = 'inspector-card blocklist-properties-card';

  const headline = document.createElement('div');
  headline.className = 'inspector-headline';
  headline.textContent = blocklist.name || '';
  card.appendChild(headline);

  if (blocklist.description && blocklist.description.trim().length > 0) {
    const descBox = document.createElement('div');
    descBox.className = 'inspector-box';
    window.setHighlightedText(descBox, blocklist.description);
    card.appendChild(descBox);
  }

  const hasUrl = blocklist.updateFromUrl !== null && blocklist.updateFromUrl !== '';

  if (hasUrl) {
    const grid = document.createElement('div');
    grid.className = 'inspector-grid';

    appendInspectorRow(grid, window._localization.t('field-update'),
      formatUpdatePeriodForDisplay(blocklist.updatePeriodMinutes), { plain: true });

    const lastUpdateSec = Number(blocklist.lastUpdate ?? 0);
    const lastSuccessfulSec = Number(blocklist.lastSuccessfulUpdate ?? 0);
    const hasLastUpdate = Number.isFinite(lastUpdateSec) && lastUpdateSec > 0;
    const hasLastSuccessful = Number.isFinite(lastSuccessfulSec) && lastSuccessfulSec > 0;
    const lastUpdateError = blocklist.lastUpdateError;
    const hasError = lastUpdateError !== null && lastUpdateError !== undefined && lastUpdateError !== '';

    if (hasError) {
      const failedValue = (hasLastUpdate ? formatLocalTime(lastUpdateSec) + ': ' : '') + lastUpdateError;
      appendInspectorRow(grid, window._localization.t('field-update-failed'), failedValue,
        { plain: true, rowClass: 'blocklist-update-row-error' });
      appendInspectorRow(grid, window._localization.t('field-last-success'),
        hasLastSuccessful ? formatLocalTime(lastSuccessfulSec) : window._localization.t('never'), { plain: true });
    } else {
      appendInspectorRow(grid, window._localization.t('field-last-update'),
        hasLastUpdate ? formatLocalTime(lastUpdateSec) : window._localization.t('never'), { plain: true });
    }

    appendInspectorRow(grid, window._localization.t('field-url'), blocklist.updateFromUrl,
      { plain: true, valueClass: 'blocklist-inspector-url' });

    card.appendChild(grid);
  }

  return card;
}

function renderBlocklistDetails() {
  const detailsContainer = getBlocklistsDetailsContainer();
  if (!detailsContainer) {
    return;
  }

  const selectedId = getSelectedBlocklistId();
  const details = ensureBlocklistDetails(selectedId);
  setupBlocklistDetailsHeaderAddButton();

  if (activeDetailsBlocklistId === selectedId && activeVirtualList) {
    const count = detailsContainer.querySelector('.blocklist-detail-count');
    if (count) {
      count.textContent = window._localization.t('entry-count', { n: (details.totalEntries || 0).toLocaleString() });
    }
    const headerEl = activeVirtualList.headerEl;
    if (headerEl) {
      const bl = blocklistsById.get(selectedId);
      const oldCard = headerEl.querySelector('.blocklist-properties-card');
      if (bl && oldCard) {
        oldCard.replaceWith(renderBlocklistPropertiesCard(bl));
      }
    }
    refreshVirtualList();
    return;
  }

  activeDetailsBlocklistId = selectedId;

  const wrapper = document.createElement('div');
  wrapper.className = 'blocklist-details';

  const listEl = document.createElement('div');
  listEl.className = 'blocklist-entry-list';

  // Header: properties card + headline row — lives inside the scroll container
  // so it scrolls together with the entries.
  const headerEl = document.createElement('div');
  headerEl.className = 'blocklist-details-header';

  const blocklist = blocklistsById.get(selectedId);
  if (blocklist) {
    headerEl.appendChild(renderBlocklistPropertiesCard(blocklist));
  }

  const headlineRow = document.createElement('div');
  headlineRow.className = 'blocklist-detail-headline-row';

  const headline = document.createElement('div');
  headline.className = 'blocklist-detail-headline';
  headline.textContent = window._localization.t('blocked-entries');
  headlineRow.appendChild(headline);

  const count = document.createElement('div');
  count.className = 'blocklist-detail-count';
  count.textContent = `${(details.totalEntries || 0).toLocaleString()} entries`;
  headlineRow.appendChild(count);
  setupBlocklistDetailsHeaderAddButton();

  headerEl.appendChild(headlineRow);
  listEl.appendChild(headerEl);

  if ((details.totalEntries || 0) === 0) {
    const empty = document.createElement('div');
    empty.className = 'blocklist-entry-empty';
    empty.textContent = getEmptyEntriesText();
    listEl.appendChild(empty);
    wrapper.appendChild(listEl);
    detailsContainer.innerHTML = '';
    detailsContainer.appendChild(wrapper);
    activeVirtualList = null;
    return;
  }

  const topSpacer = document.createElement('div');
  const rowsContainer = document.createElement('div');
  const bottomSpacer = document.createElement('div');

  listEl.appendChild(topSpacer);
  listEl.appendChild(rowsContainer);
  listEl.appendChild(bottomSpacer);

  activeVirtualList = {
    blocklistId: selectedId,
    listEl,
    headerEl,
    topSpacer,
    rowsContainer,
    bottomSpacer,
  };

  listEl.addEventListener('scroll', () => {
    renderVirtualListRows(activeVirtualList);
  });

  if (isUserBlocklistSelected()) {
    listEl.tabIndex = 0;
    listEl.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') {
        return;
      }
      const delta = event.key === 'ArrowDown' ? 1 : -1;
      const nextIndex = userEntrySelection.navigate(delta, { extend: event.shiftKey });
      if (nextIndex !== false) {
        centerVirtualListOnIndex(activeVirtualList, nextIndex);
        event.preventDefault();
        event.stopPropagation();
      }
    });
  }

  wrapper.appendChild(listEl);

  detailsContainer.innerHTML = '';
  detailsContainer.appendChild(wrapper);

  renderVirtualListRows(activeVirtualList);
}

function applySetBlocklists(msg) {
  blocklistUpdateTimer = null;

  const blocklists = msg.blocklists;
  const incomingIds = new Set(blocklists.map((b) => b.id));

  blocklistsById.clear();
  for (const blocklist of blocklists) {
    blocklistsById.set(blocklist.id, blocklist);
  }

  const table = document.getElementById('blocklists');
  table.classList.add('blocklists-list');
  table.innerHTML = '';

  const COMBINED_LIST_ID = -100;
  const combined = blocklists.find((b) => b.id === COMBINED_LIST_ID);
  const rest = blocklists.filter((b) => b.id !== COMBINED_LIST_ID);

  const selected = getSelectedBlocklistId();
  if (previousBlocklistIds !== null) {
    const newIds = rest.filter((b) => !previousBlocklistIds.has(b.id)).map((b) => b.id);
    if (newIds.length > 0) {
      setSelectedBlocklistId(newIds[0]);
    } else if (!blocklists.some((b) => b.id === selected)) {
      setSelectedBlocklistId(getUserBlocklistId());
    }
  } else if (!blocklists.some((b) => b.id === selected)) {
    setSelectedBlocklistId(getUserBlocklistId());
  }

  if (combined) {
    const combinedCard = renderBlocklist(combined);
    combinedCard.classList.add('is-combined');
    table.appendChild(combinedCard);
    const separator = document.createElement('div');
    separator.className = 'blocklist-section-separator';
    table.appendChild(separator);
  }
  for (const blocklist of rest) {
    table.appendChild(renderBlocklist(blocklist));
  }

  // Animate cards that are new since the previous render.
  if (previousBlocklistIds !== null) {
    for (const card of table.querySelectorAll('.blocklist-card')) {
      const id = Number(card.dataset.blocklistId);
      if (!previousBlocklistIds.has(id)) {
        card.classList.add('is-card-added');
        card.addEventListener('animationend', () => {
          card.classList.remove('is-card-added');
        }, { once: true });
      }
    }
  }
  previousBlocklistIds = incomingIds;

  const selectedCard = table.querySelector('.blocklist-card.is-selected');
  if (selectedCard) {
    selectedCard.scrollIntoView({ block: 'nearest' });
  }

  if (window.app && typeof window.app.sendAction === 'function') {
    window.app.sendAction('selectBlocklist', { id: getSelectedBlocklistId() });
  }

  renderBlocklistDetails();
  tryCompletePendingLocate();
}

function handleSetBlocklists(msg) {
  setupBlocklistHeaderAddButton();
  setupBlocklistDetailsHeaderAddButton();

  // Cancel any pending removal animation from a previous update.
  if (blocklistUpdateTimer !== null) {
    clearTimeout(blocklistUpdateTimer);
    blocklistUpdateTimer = null;
  }

  // If we have a previous render, flash cards that are being removed.
  if (previousBlocklistIds !== null) {
    const incomingIds = new Set(msg.blocklists.map((b) => b.id));
    const table = document.getElementById('blocklists');
    let hasFlash = false;
    if (table) {
      for (const card of table.querySelectorAll('.blocklist-card')) {
        const id = Number(card.dataset.blocklistId);
        if (previousBlocklistIds.has(id) && !incomingIds.has(id)) {
          card.classList.add('is-card-removing');
          hasFlash = true;
        }
      }
    }
    if (hasFlash) {
      blocklistUpdateTimer = setTimeout(() => {
        applySetBlocklists(msg);
      }, 250);
      return;
    }
  }

  applySetBlocklists(msg);
}
window.handleSetBlocklists = handleSetBlocklists;

function handleSetBlocklistDetails(msg) {
  const blocklistId = msg.blocklistId;
  if (blocklistId === null || blocklistId === undefined) {
    return;
  }

  const details = ensureBlocklistDetails(blocklistId);
  details.totalEntries = msg.totalEntries || 0;
  // Invalidate all cached rows because blocklist contents may have changed.
  details.entries.clear();
  details.pending.clear();
  if (blocklistId === getUserBlocklistId()) {
    clearSelectedUserEntries();
    setupBlocklistDetailsHeaderAddButton();
  }

  if (blocklistId === getSelectedBlocklistId()) {
    renderBlocklistDetails();
    tryCompletePendingLocate();
  }
}
window.handleSetBlocklistDetails = handleSetBlocklistDetails;

function handleSetBlocklistEntries(msg) {
  const blocklistId = msg.blocklistId;
  const start = msg.start;
  const entries = msg.entries;

  if (blocklistId === null || blocklistId === undefined || !Array.isArray(entries)) {
    return;
  }

  const details = ensureBlocklistDetails(blocklistId);
  for (let i = 0; i < entries.length; i += 1) {
    details.entries.set(start + i, entries[i]);
  }

  clearPendingForRange(details, start, start + entries.length - 1);

  if (blocklistId === getUserBlocklistId() && pendingAddedEntryValues !== null) {
    let firstMatchIndex = null;
    const updatedSelection = userEntrySelection.getAll();
    for (let i = 0; i < entries.length; i += 1) {
      const entry = entries[i];
      if (entry.value && pendingAddedEntryValues.has(entry.value)) {
        const key = entrySelectionKey(entry.entryType, entry.value);
        updatedSelection.add(key);
        if (firstMatchIndex === null) {
          firstMatchIndex = start + i;
        }
        pendingAddedEntryValues.delete(entry.value);
      }
    }
    if (firstMatchIndex !== null) {
      userEntrySelection.setSelected(updatedSelection, firstMatchIndex);
    }
    if (pendingAddedEntryValues.size === 0) {
      pendingAddedEntryValues = null;
    }
    if (firstMatchIndex !== null && pendingScrollToAdded && blocklistId === getSelectedBlocklistId()) {
      pendingScrollToAdded = false;
      centerVirtualListOnIndex(activeVirtualList, firstMatchIndex);
    }
  }

  if (blocklistId === getSelectedBlocklistId()) {
    refreshVirtualList();
    tryCompletePendingLocate();
  }
}
window.handleSetBlocklistEntries = handleSetBlocklistEntries;

setupBlocklistHeaderAddButton();
setupBlocklistDetailsHeaderAddButton();
