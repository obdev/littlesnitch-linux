// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH
//
// Unified date/time formatting for the web UI.
//
// All timestamps visible in the app flow through formatDateTime() and the
// helper functions exported here, so that locale preferences are applied
// consistently in every location.
//
// Preferences are read from the browser/system locale on every call.
// To apply an app-wide override (e.g. for a future per-user settings UI),
// set window.dtPrefsOverride = { hour12: <bool>, dateSep: '-' | '/' | '.' }
// before this script runs.  Every individual call picks up that object
// instead of re-reading the locale.

// ---------------------------------------------------------------------------
// Preferences
// ---------------------------------------------------------------------------

// Returns the current date/time preferences.  Called on every format
// operation so that a runtime change to window.dtPrefsOverride takes
// effect immediately without a page reload.
//
// Date format: the separator and component order are inseparable locale
// conventions (YYYY-MM-DD / DD.MM.YYYY / MM/DD/YYYY).  _fmtDate() reads
// them together from Intl.DateTimeFormat rather than trying to detect only
// the separator.  If window.dtPrefsOverride.dateSep is set, _fmtDate()
// falls back to ISO order (YYYY-dateSep-MM-dateSep-DD) with that separator.
//
// Note: Intl reflects the POSIX locale (LANG/LC_TIME), not the desktop-level
// date format preference in KDE/GNOME.  If those two differ, set
// window.dtPrefsOverride = { dateSep: '-' } (or '/' or '.') as a workaround
// until a settings UI is available.
function getDtPrefs() {
  if (window.dtPrefsOverride) return window.dtPrefsOverride;
  return {
    hour12: new Intl.DateTimeFormat(undefined, { hour: 'numeric' })
      .resolvedOptions().hour12,
    // dateSep intentionally absent: _fmtDate uses Intl directly.
  };
}

// ---------------------------------------------------------------------------
// Low-level helpers (also used directly by absoluteTimeString in
// connections.js to build the adaptive short-form timestamp)
// ---------------------------------------------------------------------------

function _pad(n) {
  return String(n).padStart(2, '0');
}

// Detect the locale's date component order from Intl and map it to the
// conventional separator for that order:
//   year-first  (ISO)      →  '-'   e.g. 2026-03-21
//   day-first   (European) →  '.'   e.g. 21.03.2026
//   month-first (US)       →  '/'   e.g. 03/21/2026
//
// The test date uses year=2001, month=03, day=05 so every component is
// unambiguous in the formatted output.
//
// Limitation: Intl maps POSIX locales via BCP 47, which does not perfectly
// reflect all POSIX locale conventions.  In particular, en_DK (which the
// POSIX standard defines as ISO/year-first) is mapped by Intl to a
// day-first European format.  When Intl order does not match what the user
// expects, set window.dtPrefsOverride.dateSep as a workaround.
function _getLocaleDateFmt() {
  const sample = new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(new Date(2001, 2, 5));
  // Split on non-digit runs to get the three numeric parts in order.
  const parts = sample.replace(/\D+/g, ' ').trim().split(' ');
  if (parts[0] === '2001') return { order: 'YMD', sep: '-' };
  if (parts[0] === '05')   return { order: 'DMY', sep: '.' };
  if (parts[0] === '03')   return { order: 'MDY', sep: '/' };
  return { order: 'YMD', sep: '-' }; // safe fallback
}

// Format just the date portion of d.
// Uses locale-detected component order + conventional separator unless
// prefs.dateSep is set (via window.dtPrefsOverride), in which case ISO
// order (YYYY-MM-DD) is used with that separator.
function _fmtDate(d, prefs) {
  const y   = d.getFullYear();
  const m   = _pad(d.getMonth() + 1);
  const day = _pad(d.getDate());
  if (prefs.dateSep !== undefined) {
    const s = prefs.dateSep;
    return `${y}${s}${m}${s}${day}`;
  }
  const { order, sep } = _getLocaleDateFmt();
  if (order === 'DMY') return `${day}${sep}${m}${sep}${y}`;
  if (order === 'MDY') return `${m}${sep}${day}${sep}${y}`;
  return `${y}${sep}${m}${sep}${day}`;
}

// Format just the time portion of d according to prefs.
// Time parts are always separated by colons, never dots.
// showSecs controls whether seconds are included.
// Returns e.g. "14:30:05", "14:30", "2:30:05 pm", "2:30 pm".
function _fmtTime(d, prefs, showSecs) {
  const h = prefs.hour12 ? (d.getHours() % 12 || 12) : d.getHours();
  const base = `${_pad(h)}:${_pad(d.getMinutes())}`;
  const t = showSecs ? `${base}:${_pad(d.getSeconds())}` : base;
  return prefs.hour12 ? `${t} ${d.getHours() < 12 ? 'am' : 'pm'}` : t;
}

// ---------------------------------------------------------------------------
// Primary export
// ---------------------------------------------------------------------------

// Format a Unix timestamp (seconds) as a full date+time string.
// showSeconds=true  → "2026-03-21 14:30:05"  (for inspector panels)
// showSeconds=false → "2026-03-21 14:30"      (for space-constrained areas)
// prefsOverride: object whose fields are merged on top of getDtPrefs(), e.g.
//   { hour12: false } to force 24h regardless of the locale setting.
// Returns '' for missing/zero timestamps.
function formatDateTime(epochSeconds, showSeconds = true, prefsOverride = null) {
  if (!epochSeconds || epochSeconds <= 0) return '';
  const prefs = prefsOverride ? { ...getDtPrefs(), ...prefsOverride } : getDtPrefs();
  const d = new Date(epochSeconds * 1000);
  return `${_fmtDate(d, prefs)} ${_fmtTime(d, prefs, showSeconds)}`;
}
