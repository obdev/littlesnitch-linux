// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

// Default English localization table — used until the backend sends strings
// for the user's language. Keys match the string IDs used throughout the UI.
const _strings = {

  // --- Global / app ---
  'filter-disabled':                  'Network Filter disabled',
  'filter-enabled':                   'Network Filter enabled',
  'about-version':                    'Version {$version}',
  'location-internet-and-local-host': 'Internet + Local Host',
  'location-invalid':                 '(Invalid)',
  'disabled':                         'Disabled',
  'enabled':                          'Enabled',
  'loading':                          'Loading\u2026',
  'never':                            'never',
  'btn-cancel':                       'Cancel',
  'btn-add':                          'Add',
  'btn-save':                         'Save',

  // --- Software update banner ---
  'update-available':      'New Version {$latestVersion} is available (you have {$currentVersion}).',
  'update-download':       'Download…',
  'update-snooze':         'Remind me later',
  'update-skip':           'Skip this version',

  // --- Age strings (connections activity column) ---
  'age-now':     'now',
  'age-seconds': '{$n} s ago',
  'age-minutes': '{$n} min ago',
  'age-hours':   '{$n} hr ago',
  'age-days':    '{$n} d ago',
  'age-months':  '{$n} mo ago',

  // --- Connections table columns ---
  'col-connection':  'Connection',
  'col-rule':        'Rule',
  'col-traffic':     'Traffic',
  'col-traffic-in':  'In',
  'col-traffic-out': 'Out',
  'col-activity':    'Activity',

  // --- Connections sort popup ---
  'sort-total-traffic': 'Total Traffic',
  'sort-bytes-in':      'Bytes In',
  'sort-bytes-out':     'Bytes Out',

  // --- Connection inspector ---
  'all-processes':       'All Processes',
  'any-process':         'Any Process',
  'any-process-via':     'Any Process via {$via}',
  'remote-any':          'Any',
  'remote-local-network':'Local Network',
  'remote-domain':       'domain {$value}',
  'show-in-rules':       'Show in Rules',
  'show-in-blocklist':   'Show in Blocklist',
  'n-blocklists':        '({$n} blocklists)',
  'matching-rules':      'Matching Rules',
  'related-rules':       'Related Rules',
  'default-allow':       'Default: Allow any connection',
  'default-deny':        'Default: Deny any connection',

  // --- Inspector field labels (connections) ---
  'field-process':        'Process',
  'field-direction':      'Direction',
  'field-remote':         'Remote',
  'field-remote-address': 'Remote Address',
  'field-port':           'Port',
  'field-protocol':       'Protocol',
  'direction-inbound':    'Inbound',
  'direction-outbound':   'Outbound',
  'direction-both-ways':  'Inbound & Outbound',
  'proto-unknown':        'Proto {$n}',

  // --- Connection statistics ---
  'stats-bytes-received': 'Bytes received',
  'stats-bytes-sent':     'Bytes sent',
  'stats-last-allowed':   'Last allowed',
  'stats-last-denied':    'Last denied',

  // --- Blocklists section ---
  'blocklists-header':        'Blocklists',
  'blocklist-details-header': 'Blocklist Details',
  'blocked-entries':          'Blocked entries',
  'entry-count':              '{$n} entries',
  'btn-add-blocklist':        'Add blocklist',
  'btn-edit-blocklist':       'Edit blocklist',
  'btn-delete-blocklist':     'Delete blocklist',
  'btn-add-entries':          'Add entries',
  'btn-remove-entries':       'Remove selected entries',
  'empty-no-matching-entries':'No matching entries',
  'empty-no-entries':         'No entries',

  // --- Blocklist inspector field labels ---
  'field-update':        'Update',
  'field-update-failed': 'Update Failed',
  'field-last-success':  'Last Success',
  'field-last-update':   'Last Update',
  'field-url':           'URL',

  // --- Update period labels ---
  'update-every-hour':    'every hour',
  'update-every-6-hours': 'every 6 hours',
  'update-every-day':     'every day',
  'update-every-week':    'every week',
  'update-every-minutes': 'every {$n} minutes',
  'update-every-hours':   'every {$n} hours',
  'update-every-days':    'every {$n} days',

  // --- Add Blocklist Entries dialog ---
  'dlg-add-entries-title': 'Add Blocklist Entries',
  'dlg-entries-label':     'Entries (one per line)',
  'dlg-names-are-hosts':   ' names are hosts, not domains',
  'err-add-at-least-one':  'Add at least one entry.',

  // --- Add / Edit Blocklist dialog ---
  'dlg-add-blocklist-title':    'Add Blocklist',
  'dlg-edit-blocklist-title':   'Edit Blocklist',
  'dlg-name-label':             'Name',
  'dlg-description-label':      'Description',
  'dlg-url-label':              'URL',
  'dlg-treat-as-hostnames':     ' Treat as list of hostnames',
  'dlg-update-period-label':    'Update Period',
  'err-name-required':          'Name is required.',
  'err-url-required':           'URL is required.',
  'err-url-http-only':          'Only HTTP and HTTPS URLs are supported.',
  'err-url-invalid':            'Please enter a valid HTTP(S) URL.',
  'err-update-period-invalid':  'Please select a valid update period.',

  // --- Rules section ---
  'rules-inspect-hint':   'Select one or more rules to inspect.',
  'notes-headline':       'Notes',
  'btn-save-notes':       'Save Notes',
  'btn-add-rule':         'Add rule',
  'btn-delete-rules':     'Delete selected rules',
  'btn-edit-rule':        'Edit rule',
  'btn-delete-rule':      'Delete rule',
  'empty-no-matching-rules': 'No matching rules',
  'empty-no-rules':          'No rules',

  // --- Rules table columns ---
  'col-action':  'Action',
  'col-process': 'Process',
  'col-dir':     'Dir',
  'col-server':  'Server',
  'col-port':    'Port',

  // --- Rules sort popup ---
  'sort-port-protocol': 'Port and Protocol',
  'sort-modified':      'Modified',
  'sort-created':       'Created',
  'sort-precedence':    'Precedence',
  'sort-priority':      'Priority',

  // --- Rule values ---
  'action-allow':          'Allow',
  'action-deny':           'Deny',
  'rule-disabled-suffix':  ' (disabled)',
  'priority-low':          'Low',
  'priority-regular':      'Regular',
  'priority-high':         'High',
  'priority-extra-high':   'Extra High',
  'direction-out':         'out',
  'direction-in':          'in',
  'direction-both':        'both',
  'dir-out':               'Out',
  'dir-in':                'In',
  'dir-both':              'Both',
  'any-server':            'Any Server',
  'remote-host':           'Host',
  'remote-hosts':          'Hosts',
  'remote-domain-singular':'Domain',
  'remote-domains':        'Domains',
  'remote-address':        'Address',
  'remote-addresses':      'Addresses',
  'remote-ip-addresses':   'IP addresses',
  'any-protocol':          'any protocol',
  'any-port':              'any port',
  'proto-any-option':      'Any',
  'lifetime-forever':      'Forever',
  'lifetime-until':        'Until {$datetime}',

  // --- Rule inspector field labels ---
  'inspector-action':      'Action',
  'inspector-priority':    'Priority',
  'inspector-executable':  'Executable',
  'inspector-direction':   'Direction',
  'inspector-remote':      'Remote',
  'inspector-protocol':    'Protocol',
  'inspector-port':        'Port',
  'inspector-lifetime':    'Lifetime',
  'inspector-created':     'Created',
  'inspector-modified':    'Modified',

  // --- Add / Edit Rule dialog ---
  'dlg-add-rule-title':      'Add Rule',
  'dlg-edit-rule-title':     'Edit Rule',
  'dlg-primary-exe-label':   'Primary executable (optional)',
  'dlg-via-exe-label':       'Via executable (optional)',
  'dlg-action-label':        'Action',
  'dlg-direction-label':     'Direction',
  'dlg-remote-type-label':   'Remote type',
  'dlg-remote-value-label':  'Remote Value',
  'dlg-remote-hosts':        'Remote Hosts',
  'dlg-remote-domains':      'Remote Domains',
  'dlg-remote-addresses':    'Remote Addresses',
  'dlg-protocol-label':      'Protocol',
  'dlg-ports-label':         'Ports (e.g. 22, 443, 8000-9000)',
  'dlg-port-placeholder':    'Any',
  'dlg-priority-label':      'Priority',
  'dlg-rule-is-enabled':     ' Rule is enabled',
  'dlg-notes-label':         'Notes',

  // --- Rule dialog validation errors ---
  'err-priority-range':      'Priority must be between 0 and 255.',
  'err-direction-required':  'Direction, protocol and remote type are required.',

  // --- App / product ---
  // app-title is derived: 'Little Snitch' + brand-connector + 'Linux'
  'brand-connector':  ' for ',
  'daemon-offline':   'Daemon offline \u2014 reconnecting\u2026',

  // --- Navigation tabs ---
  'tab-connections': 'Connections',
  'tab-blocklists':  'Blocklists',
  'tab-rules':       'Rules',

  // --- Theme selector ---
  'theme-os-default': 'OS Default',
  'theme-light':      'Light',
  'theme-dark':       'Dark',

  // --- About dialog ---
  'about-btn-label':   'About Little Snitch for Linux',
  'about-icon-alt':    'Little Snitch for Linux icon',
  'about-main-commit': 'Main commit',
  'about-ebpf-commit': 'eBPF commit',
  'about-update-newer':    'Version {$version} is available',
  'about-update-error':    'Error checking for update: {$error}',
  'about-last-checked':    'last checked: {$time}',
  'about-last-successful': 'last successful check: {$time}',
  'about-up-to-date':      'version is up-to-date',
  'about-check-now':       'Check now',

  // --- Logout menu ---
  'logout-btn-label':  'Logout',
  'btn-logout':        'Logout {$username}',
  'signed-out':        'Signed out.',

  // --- Pane titles ---
  'connection-details-header': 'Connection Details',
  'rule-details-header':       'Rule Details',

  // --- Connections filter popup ---
  'filter-placeholder':       'Filter',
  'filter-direction-label':   'Direction',
  'filter-remote-label':      'Remote',
  'filter-action-label':      'Action',
  'filter-dir-any':           'Any',
  'filter-dir-out':           'Out only',
  'filter-dir-in':            'In only',
  'filter-remote-all':        'Internet + Local Nets',
  'filter-remote-internet':   'Internet only',
  'filter-remote-localnet':   'Local Nets only',
  'filter-remote-localhost':  'Local Host only',
  'filter-remote-everything': 'Any',
  'filter-action-any':        'Any',
  'filter-action-allow':      'Allowed only',
  'filter-action-deny':       'Denied only',

  // --- Visible period filter ---
  'show-1-minute':   'Show 1 minute',
  'show-10-minutes': 'Show 10 minutes',
  'show-1-hour':     'Show 1 hour',
  'show-6-hours':    'Show 6 hours',
  'show-1-day':      'Show 1 day',
  'show-7-days':     'Show 7 days',
  'show-30-days':    'Show 30 days',
  'show-all':        'Show all',

  // --- Search placeholders ---
  'search-connections-placeholder': 'Filter connections...',
  'search-blocklists-placeholder':  'Filter selected blocklist...',
  'search-rules-placeholder':       'Filter rules...',

  // --- Blocklist filter ---
  'show-only-disabled': 'Show only disabled entries',

  // --- Column widths (CSS length values applied as custom properties) ---
  'col-rule-w':     '39px',
  'col-traffic-w':  '6em',
  'col-activity-w': '7em',
  'col-action-w':   '75px',
  'col-dir-w':      '70px',
  'col-port-w':     '15%',

  // --- Traffic diagram ---
  'traffic-total':      'Total',
  'traffic-received':   'Received',
  'traffic-sent':       'Sent',
  'traffic-blocked':    'Blocked',
  'traffic-mode-total': 'Total bytes',
  'traffic-mode-rate':  'Average rate',
  'time-filter':        'Time filter',
  'remove-time-filter': 'Remove time filter',

  // --- Factory rule alerts ---
  'alert-factory-rule':
    'Factory rules cannot be modified!\nYou should not need to modify a factory rule. ' +
    'If you really need to and if you know what you are doing, you can disable the ' +
    'factory rule or override it with a higher precedence rule.',
  'confirm-disable-factory-rule':
    'You are disabling a factory rule!\nFactory rules ensure proper functioning of your ' +
    'computer. You can still continue disabling the rule if you know what you are doing.',
};

/**
 * Return the localized string for `key`. Occurrences of `{$name}` in the
 * string are replaced with the matching value from `vars`.
 * Falls back to the key itself when the key is not found.
 *
 * @param {string} key
 * @param {Object} [vars]
 * @returns {string}
 */
function t(key, vars = {}) {
  let s = _strings[key] ?? key;
  for (const [k, v] of Object.entries(vars))
    s = s.replaceAll(`{$${k}}`, v);
  return s;
}

/**
 * Replace the localization table with data received from the backend.
 * Partial tables are merged in — keys present in the backend table override
 * the defaults; keys absent in the backend table keep their default value.
 *
 * @param {Object} table  Plain key→string map from the backend
 */
function setLocalizationTable(table) {
  if (table && typeof table === 'object') {
    Object.assign(_strings, table);
    applyLocalizationToDOM();
  }
}

/**
 * Apply the current localization table to all elements in the DOM that carry
 * `data-i18n`, `data-i18n-placeholder`, `data-i18n-aria-label`, or
 * `data-i18n-alt` attributes.  Also updates `<title>`.
 *
 * Safe to call multiple times; each call re-applies the current `_strings`.
 */
function applyLocalizationToDOM() {
  document.querySelectorAll('[data-i18n]:not([data-i18n="app-title"])').forEach(el => {
    for (const node of el.childNodes) {
      if (node.nodeType === Node.TEXT_NODE && node.textContent.trim() !== '') {
        node.textContent = window._localization.t(el.dataset.i18n);
        return; // replace only the first text node found
      }
    }
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    el.placeholder = window._localization.t(el.dataset.i18nPlaceholder);
  });
  document.querySelectorAll('[data-i18n-aria-label]').forEach(el => {
    el.setAttribute('aria-label', t(el.dataset.i18nAriaLabel));
  });
  document.querySelectorAll('[data-i18n-alt]').forEach(el => {
    el.alt = window._localization.t(el.dataset.i18nAlt);
  });
  // Column widths as CSS custom properties
  const root = document.documentElement;
  [
    'col-rule-w', 'col-traffic-w', 'col-activity-w', // connections table
    'col-action-w', 'col-dir-w', 'col-port-w',       // rules table
  ].forEach(key => root.style.setProperty('--' + key, t(key)));

  const appTitle = 'Little Snitch' + window._localization.t('brand-connector') + 'Linux';
  const titleEl = document.querySelector('title');
  if (titleEl) titleEl.textContent = appTitle;
  document.querySelectorAll('[data-i18n="app-title"]').forEach(el => {
    el.textContent = appTitle;
  });
}

window._localization = {
    t: t,
    strings: _strings
};

// Apply English defaults as soon as the script loads (scripts run after <body>
// content, so the DOM is already present).
applyLocalizationToDOM();
