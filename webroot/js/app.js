// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

(() => {
  const USER_BLOCKLIST_ID = -1;

  const state = {
    activeSection: "connections",
    filterDisabled: false,
    connectionsFilters: {
      direction: "both",
      action: null,
      location: "everything",
      visiblePeriodLimit: "none",
    },
    connectionsSort: "name",
    connectionsSearchTerm: "",
    selectedConnectionRowId: null,
    selectedBlocklistId: USER_BLOCKLIST_ID,
    loginUsername: null,
  };

  let ws = null;
  let reconnectTimerId = null;
  const RECONNECT_INTERVAL_MS = 10000;
  let searchDebounceTimer = null;
  const PAUSE_UPDATES_INTERVAL_MS = 2000;
  const PAUSE_UPDATES_IDLE_MS = 30000;
  let pauseUpdatesIntervalId = null;
  let pauseUpdatesIdleTimeoutId = null;
  let pauseUpdatesLastSentAt = 0;
  let lastMouseMoveAt = 0;
  let isMouseInsideWindow = true;
  let undoStack = [];
  let undoTimerId = null;
  let lastSoftwareUpdate = null;

  function setOfflineIndicator(isOffline) {
    const indicator = document.querySelector('[data-role="offline-indicator"]');
    if (indicator) {
      indicator.hidden = !isOffline;
    }
  }

  function scheduleReconnect() {
    if (reconnectTimerId !== null) {
      return;
    }
    reconnectTimerId = setTimeout(() => {
      reconnectTimerId = null;
      ws = createWebSocket();
    }, RECONNECT_INTERVAL_MS);
  }

  function createWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    // If `window.location.host` is empty, page is loaded from file for debugging.
    const socketUrl =
      window.location.host !== ""
        ? `${protocol}//${window.location.host}/stream`
        : "ws://127.0.0.1:3031/stream";
    tempSURL = null;
    const socket = new WebSocket(socketUrl);

    socket.addEventListener("open", () => {
      console.log("WebSocket connected");
      setOfflineIndicator(false);
    });

    socket.addEventListener("message", (event) => {
      try {
        const messages = JSON.parse(event.data);
        handleServerCommand(messages);
      } catch (error) {
        console.error("Failed to parse WebSocket message", error);
      }
    });

    socket.addEventListener("close", (event) => {
      if (event.reason === "logout") {
        console.log("WebSocket closed by logout, reloading page");
        const placeholder = document.createElement("div");
        placeholder.className = "logout-placeholder";
        placeholder.textContent = window._localization.t("signed-out");
        document.body.replaceChildren(placeholder);
        window.location.reload();
        return;
      }
      console.log("WebSocket closed, will retry in 10 s");
      setOfflineIndicator(true);
      scheduleReconnect();
    });

    socket.addEventListener("error", (error) => {
      console.error("WebSocket error", error);
    });

    return socket;
  }

  function sendAction(type, payload = {}) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return;
    }
    payload.action = type;
    ws.send(JSON.stringify(payload));
  }

  function setSelectedConnectionRowId(rowId) {
    state.selectedConnectionRowId = rowId;
  }

  function getSelectedConnectionRowId() {
    return state.selectedConnectionRowId;
  }

  function setSelectedBlocklistId(blocklistId) {
    state.selectedBlocklistId = blocklistId === null || blocklistId === undefined
      ? USER_BLOCKLIST_ID
      : blocklistId;
  }

  function getSelectedBlocklistId() {
    return state.selectedBlocklistId === null || state.selectedBlocklistId === undefined
      ? USER_BLOCKLIST_ID
      : state.selectedBlocklistId;
  }

  function getUserBlocklistId() {
    return USER_BLOCKLIST_ID;
  }

  function handleServerCommand(messageArray) {
    if (!Array.isArray(messageArray)) {
      return;
    }
    for (const msg of messageArray) {
      switch (msg.update) {
        case "clearConnectionRows":
          window.handleClear();
          break;
        case "insertConnectionRows":
          window.handleInsertRows(msg.afterId, msg.rows, msg.animate);
          break;
        case "removeConnectionRows":
          window.handleRemoveRows(msg.startId, msg.endId);
          break;
        case "moveConnetionRows":
          window.handleMoveRows(msg.startId, msg.endId, msg.targetId);
          break;
        case "updateConnectionRows":
          window.handleUpdateRows(msg.rows);
          window.handleUpdateStatistics(msg.statistics);
          break;
        case "updateRuleButtons":
          window.handleUpdateRuleButtons(msg.rows);
          break;
        case "highlightRuleForRows":
          window.highlightRuleButtons(msg.ids, msg.action);
          break;
        case "trafficEvents":
          window.handleEvents(msg.data);
          break;
        case "setInspector":
          window.handleSetInspector(msg);
          break;
        case "setBlocklists":
          window.handleSetBlocklists(msg);
          break;
        case "setRules":
          window.handleSetRules(msg);
          break;
        case "updateRules":
          window.handleUpdateRules(msg);
          break;
        case "setBlocklistDetails":
          window.handleSetBlocklistDetails(msg);
          break;
        case "setBlocklistEntries":
          window.handleSetBlocklistEntries(msg);
          break;
        case "setBlocklistEntryLocation":
          window.handleSetBlocklistEntryLocation(msg);
          break;
        case "setBlocklistStatus":
          handleSetBlocklistStatus(msg);
          break;
        case "setConnectionsStatus":
          handleSetConnectionsStatus(msg);
          break;
        case "setTrafficData":
          window.handleSetTrafficData?.(msg);
          break;
        case "updateTrafficData":
          window.handleUpdateTrafficData?.(msg);
          break;
        case "setAboutInfo":
          handleSetAboutInfo(msg);
          break;
        case "setUndoStack":
          handleSetUndoStack(msg);
          break;
        case "setLoginData":
          handleSetLoginData(msg);
          break;
        case "localizationTable":
          window.setLocalizationTable(msg.table);
          window.applyConnectionsSort?.();
          window.rebuildTrafficPlot?.();
          refreshLogoutLabel();
          break;
        case "globalSettings":
          handleSetGlobalSettings(msg);
          break;
        case "softwareUpdate":
          handleSoftwareUpdate(msg);
          break;
        default:
          console.warn("Unknown msg from server", JSON.stringify(msg));
      }
    }
  }

  function applyTheme(value) {
    const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const isDark = value === "dark" || (!value && systemDark);
    document.documentElement.classList.toggle("dark", isDark);
  }

  function updateThemeMenu(value) {
    const themeToggle = document.querySelector('button.theme-toggle');
    if (themeToggle != null) {
      const themeName = value ?? "automatic";
      themeToggle.innerHTML = `<svg width=\"18\" height=\"18\" fill=\"currentColor\"><use href="#theme-${themeName}\" href=\"#theme-${themeName}\"/></svg>`;
    }
    document.querySelectorAll('[data-role="theme-option"]').forEach((item) => {
      item.classList.toggle("is-selected", item.dataset.value === (value ?? ""));
    });
  }

  function setupThemeToggle() {
    const btn = document.querySelector('[data-role="theme-toggle"]');
    const popup = document.querySelector('[data-role="theme-popup"]');
    if (!btn || !popup) return;

    const stored = localStorage.getItem("theme");
    applyTheme(stored);
    updateThemeMenu(stored);

    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (!localStorage.getItem("theme")) {
        applyTheme(null);
      }
    });

    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const shouldOpen = popup.hidden;
      closeAllMenus();
      popup.hidden = !shouldOpen;
    });

    popup.addEventListener("click", (e) => {
      e.stopPropagation();
      const item = e.target.closest('[data-role="theme-option"]');
      if (!item) return;
      const value = item.dataset.value || null;
      if (value) {
        localStorage.setItem("theme", value);
      } else {
        localStorage.removeItem("theme");
      }
      applyTheme(value);
      updateThemeMenu(value);
      closeAllMenus();
    });
  }

  function setupTabs() {
    const tabs = Array.from(document.querySelectorAll(".tab"));
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        const nextSection = tab.dataset.section;
        if (!nextSection || nextSection === state.activeSection) {
          return;
        }

        state.activeSection = nextSection;
        if (nextSection !== "connections") {
          stopPauseUpdatesPing();
        }

        document.querySelectorAll(".tab").forEach((el) => {
          const active = el.dataset.section === nextSection;
          el.classList.toggle("is-active", active);
          el.setAttribute("aria-selected", active ? "true" : "false");
        });

        document.querySelectorAll(".section").forEach((el) => {
          el.classList.toggle("is-active", el.dataset.section === nextSection);
        });

        sendAction("setSection", { section: nextSection });
      });
    });
  }

  function shouldPingPauseUpdates() {
    if (state.activeSection !== "connections" || !isMouseInsideWindow) {
      return false;
    }
    if (document.hidden || !document.hasFocus()) {
      return false;
    }
    if (lastMouseMoveAt <= 0) {
      return false;
    }
    return Date.now() - lastMouseMoveAt <= PAUSE_UPDATES_IDLE_MS;
  }

  function clearPauseUpdatesIdleTimeout() {
    if (pauseUpdatesIdleTimeoutId !== null) {
      clearTimeout(pauseUpdatesIdleTimeoutId);
      pauseUpdatesIdleTimeoutId = null;
    }
  }

  function stopPauseUpdatesPing() {
    if (pauseUpdatesIntervalId !== null) {
      clearInterval(pauseUpdatesIntervalId);
      pauseUpdatesIntervalId = null;
    }
    clearPauseUpdatesIdleTimeout();
    pauseUpdatesLastSentAt = 0;
  }

  function sendPauseUpdatesPingIfDue() {
    if (!shouldPingPauseUpdates()) {
      stopPauseUpdatesPing();
      return;
    }
    const now = Date.now();
    if (now - pauseUpdatesLastSentAt < PAUSE_UPDATES_INTERVAL_MS) {
      return;
    }
    sendAction("pauseUpdates");
    pauseUpdatesLastSentAt = now;
  }

  function ensurePauseUpdatesPing() {
    if (pauseUpdatesIntervalId !== null) {
      return;
    }
    pauseUpdatesIntervalId = setInterval(() => {
      sendPauseUpdatesPingIfDue();
    }, 500);
  }

  function schedulePauseUpdatesIdleStop() {
    clearPauseUpdatesIdleTimeout();
    pauseUpdatesIdleTimeoutId = setTimeout(() => {
      stopPauseUpdatesPing();
    }, PAUSE_UPDATES_IDLE_MS);
  }

  function setupPauseUpdatesPing() {
    const markMouseOutside = () => {
      isMouseInsideWindow = false;
      stopPauseUpdatesPing();
    };

    window.addEventListener("mousemove", () => {
      isMouseInsideWindow = true;
      lastMouseMoveAt = Date.now();
      if (state.activeSection !== "connections") {
        return;
      }
      ensurePauseUpdatesPing();
      schedulePauseUpdatesIdleStop();
      sendPauseUpdatesPingIfDue();
    }, { passive: true });

    window.addEventListener("mouseleave", markMouseOutside);
    window.addEventListener("blur", markMouseOutside);
    document.addEventListener("mouseleave", markMouseOutside);
    document.addEventListener("pointerleave", markMouseOutside);
    document.documentElement.addEventListener("mouseout", (event) => {
      if (!event.relatedTarget) {
        markMouseOutside();
      }
    });

    window.addEventListener("mouseenter", () => {
      isMouseInsideWindow = true;
    });

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        stopPauseUpdatesPing();
      }
    });
  }

  function setupSearch() {
    const inputs = Array.from(document.querySelectorAll('[data-role="search"]'));
    inputs.forEach((input) => {
      const updateFilteredState = () => {
        input.parentNode.classList.toggle("is-filtered", input.value.trim().length > 0);
      };
      const applySearchQuery = (query) => {
        const section = input.dataset.section;
        if (!section || section !== state.activeSection) {
          return;
        }
        if (section === "rules") {
          if (typeof window.setRulesSearchQuery === "function") {
            window.setRulesSearchQuery(query);
          }
        } else {
          sendAction("setSearch", { query });
        }
      };

      updateFilteredState();

      input.addEventListener("input", () => {
        updateFilteredState();

        if (searchDebounceTimer !== null) {
          clearTimeout(searchDebounceTimer);
        }
        const query = input.value;
        searchDebounceTimer = setTimeout(() => {
          applySearchQuery(query);
          searchDebounceTimer = null;
        }, 250);
      });

      const clearButton = input.parentElement?.querySelector('[data-role="search-clear"]');
      if (clearButton instanceof HTMLButtonElement) {
        clearButton.addEventListener("click", () => {
          if (searchDebounceTimer !== null) {
            clearTimeout(searchDebounceTimer);
            searchDebounceTimer = null;
          }
          input.value = "";
          updateFilteredState();
          applySearchQuery("");
          input.focus();
        });
      }
    });
  }

  function setupBlocklistFilter() {
    const checkbox = document.querySelector('[data-role="blocklist-disabled-only"]');
    if (!(checkbox instanceof HTMLInputElement)) return;
    checkbox.addEventListener("change", () => {
      sendAction("setBlocklistFilter", { disabledEntriesOnly: checkbox.checked });
    });
  }

  function setupSortMenus() {
    const sortButtons = Array.from(document.querySelectorAll('[data-role="sort-toggle"]'));

    sortButtons.forEach((button) => {
      button.addEventListener("mousedown", (event) => {
        if (event.button !== 0) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        const section = button.dataset.section;
        toggleMenu(`[data-role="sort-menu"][data-section="${section}"]`);
      });
      button.addEventListener("click", (event) => {
        // We already toggled on mousedown; block click bubbling so outside-click
        // handler does not immediately close the menu.
        event.stopPropagation();
      });
    });

    const sortMenus = Array.from(document.querySelectorAll('[data-role="sort-menu"]'));
    sortMenus.forEach((menu) => {
      menu.addEventListener("click", (event) => {
        const target = event.target.closest("[data-sort]");
        if (!target) {
          return;
        }

        const section = menu.dataset.section;
        const sortBy = target.dataset.sort;
        if (!section || !sortBy) {
          return;
        }

        if (section === "connections") {
          menu.hidden = true;
          setConnectionsSort(sortBy);
          window.applyConnectionsSort?.();
          sendAction("setConnectionsSort", { sortBy });
        }
      });
    });
  }

  function locationToFilters(loc) {
    switch (loc) {
      case "all":                    return { localnet: null,  localhost: false };
      case "internet":               return { localnet: false, localhost: false };
      case "localnet":               return { localnet: true,  localhost: false };
      case "localhost":              return { localnet: false, localhost: true  };
      case "everything":             return { localnet: null,  localhost: null  };
      case "internet-and-localhost": return { localnet: false, localhost: null  };
      case "invalid":                return { localnet: true,  localhost: true  };
      default:                       return { localnet: null,  localhost: null  };
    }
  }

  function filtersToLocation(localnet, localhost) {
    if (localnet === null  && localhost === false) return "all";
    if (localnet === false && localhost === false) return "internet";
    if (localnet === true  && localhost === false) return "localnet";
    if (localnet === false && localhost === true)  return "localhost";
    if (localnet === null  && localhost === null)  return "everything";
    if (localnet === null  && localhost === true)  return "localhost"; // map to existing option
    if (localnet === true  && localhost === null)  return "localnet";  // map to existing option
    if (localnet === false && localhost === null)  return "internet-and-localhost"; // temporary
    if (localnet === true  && localhost === true)  return "invalid";   // temporary
    return "everything";
  }

  function readConnectionsFiltersFromControls() {
    const section = document.querySelector('.section[data-section="connections"]');
    const directionValue = section?.querySelector('[data-role="direction-filter"]')?.value || "both";
    const actionValue = section?.querySelector('[data-role="verdict-filter"]')?.value || "any";
    const locationValue = section?.querySelector('[data-role="location-filter"]')?.value || "everything";
    const visiblePeriodValue = section?.querySelector('[data-role="visible-period-filter"]')?.value || "none";
    // Map HTML select values to the numeric/boolean/null values the backend expects.
    // direction: 1=outbound, 2=inbound, 3=both. action: null=any.
    const direction = directionValue === "in" ? 2 : directionValue === "out" ? 1 : 3;
    const action = actionValue === "any" ? null : actionValue;
    const { localnet, localhost } = locationToFilters(locationValue);
    const parsedVisiblePeriod = Number.parseInt(visiblePeriodValue, 10);
    const visiblePeriodLimit = Number.isFinite(parsedVisiblePeriod) && parsedVisiblePeriod > 0
      ? parsedVisiblePeriod
      : null;
    return { direction, action, localnet, localhost, visiblePeriodLimit };
  }

  function applyConnectionsStatusToControls() {
    const section = document.querySelector('.section[data-section="connections"]');
    if (section) {
      const directionInput = section.querySelector('[data-role="direction-filter"]');
      const actionInput = section.querySelector('[data-role="verdict-filter"]');
      const locationInput = section.querySelector('[data-role="location-filter"]');
      const visiblePeriodInput = section.querySelector('[data-role="visible-period-filter"]');
      if (directionInput instanceof HTMLSelectElement) {
        directionInput.value = state.connectionsFilters.direction || "both";
      }
      if (actionInput instanceof HTMLSelectElement) {
        actionInput.value = state.connectionsFilters.action || "any";
      }
      if (locationInput instanceof HTMLSelectElement) {
        const loc = state.connectionsFilters.location || "everything";
        const tempValues = ["internet-and-localhost", "invalid"];
        // Remove temp options that are no longer needed
        tempValues.forEach((v) => {
          if (v !== loc) {
            locationInput.querySelector(`option[value="${v}"][data-temp]`)?.remove();
          }
        });
        // Add temp option if needed and not yet present
        if (tempValues.includes(loc) && !locationInput.querySelector(`option[value="${loc}"]`)) {
          const opt = document.createElement("option");
          opt.value = loc;
          opt.textContent = window._localization.t(loc === 'internet-and-localhost' ? 'location-internet-and-local-host' : 'location-invalid');
          opt.dataset.temp = "1";
          locationInput.appendChild(opt);
        }
        locationInput.value = loc;
      }
      if (visiblePeriodInput instanceof HTMLSelectElement) {
        visiblePeriodInput.value = state.connectionsFilters.visiblePeriodLimit || "none";
      }
      updateFilterChips();
    }
    const searchInput = document.querySelector('[data-role="search"][data-section="connections"]');
    if (searchInput instanceof HTMLInputElement && searchInput.value !== (state.connectionsSearchTerm || "")) {
      searchInput.value = state.connectionsSearchTerm || "";
      searchInput.parentNode.classList.toggle("is-filtered", searchInput.value.trim().length > 0);
    }
  }

  function handleSetBlocklistStatus(msg) {
    const checkbox = document.querySelector('[data-role="blocklist-disabled-only"]');
    if (checkbox instanceof HTMLInputElement) {
      checkbox.checked = !!msg.disabledEntriesOnly;
    }
    const searchInput = document.querySelector('[data-role="search"][data-section="blocklists"]');
    if (searchInput instanceof HTMLInputElement && searchInput.value !== (msg.searchTerm || "")) {
      searchInput.value = msg.searchTerm || "";
      searchInput.parentNode.classList.toggle("is-filtered", searchInput.value.trim().length > 0);
    }
  }

  function handleSetConnectionsStatus(msg) {
    const status = msg.status || {};
    const directionBits = Number(status.filters?.direction ?? 3);
    state.connectionsFilters.direction = directionBits === 2 ? "in" : directionBits === 1 ? "out" : "both";
    const action = status.filters?.action;
    state.connectionsFilters.action = action === "allow" || action === "deny" ? action : "any";
    const localnet = status.filters?.localnet ?? null;
    const localhost = status.filters?.localhost ?? null;
    state.connectionsFilters.location = filtersToLocation(localnet, localhost);
    const visiblePeriodLimit = status.filters?.visiblePeriodLimit;
    state.connectionsFilters.visiblePeriodLimit =
      typeof visiblePeriodLimit === "number" && Number.isFinite(visiblePeriodLimit)
        ? String(Math.trunc(visiblePeriodLimit))
        : "none";
    state.connectionsSort = status.sortBy || "name";
    state.connectionsSearchTerm = status.searchTerm || "";
    applyConnectionsStatusToControls();
    window.applyConnectionsSort?.();
  }

  function updateFilterChips() {
    const section = document.querySelector('.section[data-section="connections"]');
    if (!section) return;
    const chipsEl = section.querySelector('[data-role="filter-chips"]');
    const placeholder = section.querySelector('[data-role="filter-placeholder"]');
    const btn = section.querySelector('[data-role="filter-toggle"]');
    if (!chipsEl) return;

    const dirEl = section.querySelector('[data-role="direction-filter"]');
    const locEl = section.querySelector('[data-role="location-filter"]');
    const verdictEl = section.querySelector('[data-role="verdict-filter"]');

    const activeChips = [];
    if (dirEl instanceof HTMLSelectElement && dirEl.value !== "both") {
      activeChips.push(dirEl.options[dirEl.selectedIndex]?.text || dirEl.value);
    }
    if (locEl instanceof HTMLSelectElement && locEl.value !== "everything") {
      activeChips.push(locEl.options[locEl.selectedIndex]?.text || locEl.value);
    }
    if (verdictEl instanceof HTMLSelectElement && verdictEl.value !== "any") {
      activeChips.push(verdictEl.options[verdictEl.selectedIndex]?.text || verdictEl.value);
    }

    chipsEl.innerHTML = activeChips.map((t) => `<span class="filter-chip">${t}</span>`).join("");
    if (placeholder instanceof HTMLElement) {
      placeholder.hidden = activeChips.length > 0;
    }
    if (btn instanceof HTMLElement) {
      btn.classList.toggle("is-active", activeChips.length > 0);
    }
  }

  function setupFilterControl() {
    const section = document.querySelector('.section[data-section="connections"]');
    if (!section) return;
    const toggleBtn = section.querySelector('[data-role="filter-toggle"]');
    const popup = section.querySelector('[data-role="filter-popup"]');
    if (!toggleBtn || !popup) return;

    toggleBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const isOpen = !popup.hidden;
      popup.hidden = isOpen;
      toggleBtn.setAttribute("aria-expanded", String(!isOpen));
    });

    document.addEventListener("click", (e) => {
      if (!popup.hidden) {
        const control = section.querySelector('[data-role="filter-control"]');
        if (control && !control.contains(/** @type {Node} */ (e.target))) {
          popup.hidden = true;
          toggleBtn.setAttribute("aria-expanded", "false");
        }
      }
    });
  }

  function setupConnectionFilters() {
    const section = document.querySelector('.section[data-section="connections"]');
    if (!section) {
      return;
    }
    const controls = Array.from(section.querySelectorAll(
      '[data-role="direction-filter"],[data-role="verdict-filter"],[data-role="location-filter"],[data-role="visible-period-filter"]',
    ));
    controls.forEach((control) => {
      control.addEventListener("change", (event) => {
        const target = event.target;
        if (!(target instanceof HTMLSelectElement)) {
          return;
        }
        updateFilterChips();
        const filters = readConnectionsFiltersFromControls();
        sendAction("setConnectionsFilters", { filters });
      });
    });

  }

  function isTextEditingTarget(target) {
    if (!(target instanceof Element)) {
      return false;
    }
    if (target.closest('input, textarea, select, [contenteditable="true"], [contenteditable=""]')) {
      return true;
    }
    return false;
  }

  function setupKeyboardNavigation() {
    document.addEventListener("keydown", (event) => {
      if (event.defaultPrevented) {
        return;
      }
      const isArrowNavKey = event.key === "ArrowUp" || event.key === "ArrowDown";
      const isDisclosureKey = event.key === "ArrowLeft" || event.key === "ArrowRight"
        || event.key === " " || event.key === "Spacebar";
      if (!isArrowNavKey && !isDisclosureKey) {
        return;
      }
      if (document.querySelector("dialog[open]")) {
        return;
      }
      if (isTextEditingTarget(event.target)) {
        return;
      }

      let handled = false;
      if (state.activeSection === "connections") {
        if (isArrowNavKey && typeof window.navigateConnectionsSelection === "function") {
          const delta = event.key === "ArrowDown" ? 1 : -1;
          handled = window.navigateConnectionsSelection(delta) === true;
        } else if (isDisclosureKey && typeof window.maybeToggleConnectionDisclosureForKey === "function") {
          handled = window.maybeToggleConnectionDisclosureForKey(event.key) === true;
        }
      } else if (state.activeSection === "blocklists") {
        if (isArrowNavKey && typeof window.navigateBlocklistsSelection === "function") {
          const delta = event.key === "ArrowDown" ? 1 : -1;
          handled = window.navigateBlocklistsSelection(delta) === true;
        }
      } else if (state.activeSection === "rules") {
        if (isArrowNavKey && typeof window.navigateRulesSelection === "function") {
          const delta = event.key === "ArrowDown" ? 1 : -1;
          handled = window.navigateRulesSelection(delta, { extend: event.shiftKey }) === true;
        }
      }

      if (handled) {
        event.preventDefault();
      }
    });
  }

  function toggleMenu(selector) {
    const current = document.querySelector(selector);
    if (!current) {
      return;
    }

    const shouldOpen = current.hidden;
    closeAllMenus();
    current.hidden = !shouldOpen;
  }

  function closeAllMenus() {
    document.querySelectorAll(".popup-menu").forEach((menu) => {
      menu.hidden = true;
    });
  }

  function setupOutsideClickClose() {
    document.addEventListener("click", () => {
      closeAllMenus();
    });
  }

  function handleSetAboutInfo(msg) {
    const dialog = document.getElementById("about-dialog");
    if (!dialog) {
      return;
    }
    const set = (role, text) => {
      const el = dialog.querySelector(`[data-role="${role}"]`);
      if (el) {
        el.textContent = text;
      }
    };
    set("about-version", window._localization.t('about-version', { version: msg.version }));
    set("about-main-commit", msg.mainCommit);
    set("about-ebpf-commit", msg.ebpfCommit);
    set("about-copyright", msg.copyright);
    const link = dialog.querySelector('[data-role="about-website"]');
    if (link instanceof HTMLAnchorElement) {
      if (msg.websiteUrl) {
        link.href = msg.websiteUrl;
        link.textContent = msg.websiteUrl;
        link.hidden = false;
      } else {
        link.hidden = true;
      }
    }
    renderAboutUpdateInfo();
  }

  function handleSoftwareUpdate(msg) {
    lastSoftwareUpdate = msg;
    renderAboutUpdateInfo();
    const banner = document.querySelector('[data-role="update-banner"]');
    if (!banner) return;
    if (!msg.isNewer || msg.isSnoozed || !msg.updateCheckEnabled || msg.updateIntervalHours === 0) {
      banner.hidden = true;
      return;
    }
    const latestVersion = msg.status?.latestVersion ?? '';
    const textEl = banner.querySelector('[data-role="update-banner-text"]');
    if (textEl) {
      textEl.textContent = window._localization.t('update-available', { latestVersion, currentVersion: msg.currentVersion });
    }
    const downloadBtn = banner.querySelector('[data-role="update-download-btn"]');
    if (downloadBtn instanceof HTMLAnchorElement) {
      if (msg.downloadUrl) {
        downloadBtn.href = msg.downloadUrl;
        downloadBtn.hidden = false;
      } else {
        downloadBtn.hidden = true;
      }
    }
    const snoozeBtn = banner.querySelector('[data-role="update-snooze-btn"]');
    if (snoozeBtn) {
      snoozeBtn.onclick = () => sendAction('snoozeSoftwareUpdate', { snoozeForMinutes: 60 * 24 });
    }
    const skipBtn = banner.querySelector('[data-role="update-skip-btn"]');
    if (skipBtn) {
      skipBtn.onclick = () => sendAction('snoozeSoftwareUpdate', { version: latestVersion });
    }
    banner.hidden = false;
  }

  function renderAboutUpdateInfo() {
    const dialog = document.getElementById('about-dialog');
    if (!dialog) return;
    const container = dialog.querySelector('[data-role="about-update-info"]');
    if (!container) return;
    container.textContent = '';

    const msg = lastSoftwareUpdate;
    if (!msg || !msg.updateCheckEnabled) return;

    const addLine = (text) => {
      const div = document.createElement('div');
      div.textContent = text;
      container.appendChild(div);
    };

    const addCheckNowBtn = () => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'about-check-now-btn';
      btn.textContent = window._localization.t('about-check-now');
      btn.onclick = () => sendAction('checkForUpdate');
      container.appendChild(btn);
    };

    if (msg.isNewer && msg.status?.latestVersion) {
      const div = document.createElement('div');
      const text = window._localization.t('about-update-newer', { version: msg.status.latestVersion });
      if (msg.downloadUrl) {
        const a = document.createElement('a');
        a.href = msg.downloadUrl;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.className = 'about-update-link';
        a.textContent = text;
        div.appendChild(a);
      } else {
        div.textContent = text;
      }
      container.appendChild(div);
    }

    if (msg.status?.lastError) {
      addLine(window._localization.t('about-update-error', { error: msg.status.lastError }));
      if (msg.status.lastFailedCheck) {
        addLine(window._localization.t('about-last-checked', { time: formatDateTime(msg.status.lastFailedCheck / 1e9, false) }));
      }
      if (msg.status.lastSuccessfulCheck) {
        addLine(window._localization.t('about-last-successful', { time: formatDateTime(msg.status.lastSuccessfulCheck / 1e9, false) }));
      }
      addCheckNowBtn();
    } else if (!msg.isNewer) {
      addLine(window._localization.t('about-up-to-date'));
      if (msg.status?.lastSuccessfulCheck) {
        addLine(window._localization.t('about-last-checked', { time: formatDateTime(msg.status.lastSuccessfulCheck / 1e9, false) }));
      }
      addCheckNowBtn();
    }
  }

  function handleSetUndoStack(msg) {
    undoStack = Array.isArray(msg.items) ? msg.items : [];
    renderUndoWidget();
    syncUndoTimer();
  }

  function renderUndoWidget() {
    const widget = document.querySelector('[data-role="undo-widget"]');
    if (!widget) return;
    if (undoStack.length === 0) {
      widget.hidden = true;
      widget.classList.remove('is-bubble');
      return;
    }
    const wasHidden = widget.hidden;
    const wasBubble = widget.classList.contains('is-bubble');
    widget.hidden = false;
    const newest = undoStack[undoStack.length - 1];
    const isBubble = (Math.floor(Date.now() / 1000) - newest.createdAt) < 10;

    const capsule = widget.querySelector('[data-role="undo-bubble"]');
    const labelEl = widget.querySelector('[data-role="undo-label"]');
    if (capsule) capsule.dataset.itemId = String(newest.id);
    if (labelEl) labelEl.textContent = newest.title;

    if (isBubble) {
      if (!wasHidden && wasBubble) {
        // Restart entry animation: clear inline styles, reflow, re-apply.
        if (capsule) capsule.style.animation = 'none';
        if (labelEl) labelEl.style.animation = 'none';
        void capsule?.offsetWidth;
      }
      widget.classList.add('is-bubble');
      // Apply entry animations as inline styles, decoupled from is-bubble, so
      // clearing them later lets the max-width transition fire on shrink.
      if (capsule) capsule.style.animation = 'undo-capsule-enter 0.55s cubic-bezier(0.34, 1.56, 0.64, 1) 0.05s both';
      if (labelEl) labelEl.style.animation = 'undo-label-enter 0.3s ease 0.48s both';
    } else {
      // Clear inline animations before removing is-bubble so the max-width
      // transition can fire from the rule-based 240px value.
      if (capsule) capsule.style.animation = '';
      if (labelEl) labelEl.style.animation = '';
      widget.classList.remove('is-bubble');
    }

    const popup = widget.querySelector('[data-role="undo-popup"]');
    if (popup) {
      const newestId = newest.id;
      popup.replaceChildren(...undoStack.map((item) => {
        const btn = document.createElement('button');
        btn.className = 'menu-item';
        btn.dataset.itemId = String(item.id);
        const titleSpan = document.createElement('span');
        titleSpan.textContent = item.title;
        if (item.id === newestId) titleSpan.style.fontWeight = '600';
        const ageSpan = document.createElement('span');
        ageSpan.className = 'undo-item-age';
        ageSpan.textContent = ageString(item.createdAt);
        btn.append(titleSpan, ageSpan);
        return btn;
      }));
    }
  }

  function syncUndoTimer() {
    if (undoStack.length > 0 && undoTimerId === null) {
      undoTimerId = setInterval(updateUndoAgeTick, 1000);
    } else if (undoStack.length === 0 && undoTimerId !== null) {
      clearInterval(undoTimerId);
      undoTimerId = null;
    }
  }

  function updateUndoAgeTick() {
    if (undoStack.length === 0) return;
    const widget = document.querySelector('[data-role="undo-widget"]');
    if (!widget) return;
    const newest = undoStack[undoStack.length - 1];
    const isBubble = (Math.floor(Date.now() / 1000) - newest.createdAt) < 10;
    widget.classList.toggle('is-bubble', isBubble);
    const popup = widget.querySelector('[data-role="undo-popup"]');
    if (popup && !popup.hidden) {
      popup.querySelectorAll('.menu-item[data-item-id]').forEach((row, i) => {
        const item = undoStack[i];
        if (!item) return;
        const ageEl = row.querySelector('.undo-item-age');
        if (ageEl) ageEl.textContent = ageString(item.createdAt);
      });
    }
  }

  function setupUndoWidget() {
    const widget = document.querySelector('[data-role="undo-widget"]');
    if (!widget) return;

    const capsule = widget.querySelector('[data-role="undo-bubble"]');
    const popup = widget.querySelector('[data-role="undo-popup"]');

    capsule?.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      e.stopPropagation();
      if (widget.classList.contains('is-bubble')) {
        const itemId = Number(capsule.dataset.itemId);
        if (itemId) sendAction('undo', { itemId });
      } else if (popup) {
        const shouldOpen = popup.hidden;
        closeAllMenus();
        popup.hidden = !shouldOpen;
        capsule.setAttribute('aria-expanded', String(!shouldOpen));
      }
    });
    capsule?.addEventListener('click', (e) => e.stopPropagation());

    popup?.addEventListener('click', (e) => {
      const row = e.target.closest('[data-item-id]');
      if (!row) return;
      const itemId = Number(row.dataset.itemId);
      if (itemId) {
        popup.hidden = true;
        capsule?.setAttribute('aria-expanded', 'false');
        sendAction('undo', { itemId });
      }
    });
  }

  function updateFilterSwitch(filterDisabled) {
    const input = document.querySelector('[data-role="filter-switch-input"]');
    if (input instanceof HTMLInputElement) {
      input.checked = !filterDisabled;
    }
    const label = document.querySelector('[data-role="filter-switch"] .filter-switch-label');
    if (label) {
      label.textContent = filterDisabled ? window._localization.t('filter-disabled') : window._localization.t('filter-enabled');
    }
  }

  function handleSetGlobalSettings(msg) {
    state.filterDisabled = !!msg.filterDisabled;
    updateFilterSwitch(state.filterDisabled);
  }

  function setupFilterSwitch() {
    const input = document.querySelector('[data-role="filter-switch-input"]');
    if (!(input instanceof HTMLInputElement)) return;
    input.addEventListener('change', () => {
      state.filterDisabled = !input.checked;
      updateFilterSwitch(state.filterDisabled);
      sendAction('setFilterDisabled', { filterDisabled: state.filterDisabled });
    });
  }

  function refreshLogoutLabel() {
    const item = document.querySelector('[data-role="logout-item"]');
    if (item && state.loginUsername) {
      item.textContent = window._localization.t('btn-logout', { username: state.loginUsername });
    }
  }

  function handleSetLoginData(msg) {
    state.loginUsername = msg.username || null;
    const control = document.querySelector('[data-role="logout-control"]');
    if (control instanceof HTMLElement) {
      control.hidden = !state.loginUsername;
    }
    refreshLogoutLabel();
  }

  function setupLogoutMenu() {
    const btn = document.querySelector('[data-role="logout-toggle"]');
    const popup = document.querySelector('[data-role="logout-popup"]');
    const item = document.querySelector('[data-role="logout-item"]');
    if (!btn || !popup || !item) return;

    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const shouldOpen = popup.hidden;
      closeAllMenus();
      popup.hidden = !shouldOpen;
      btn.setAttribute('aria-expanded', String(shouldOpen));
    });

    popup.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!(e.target instanceof Element)) return;
      if (!e.target.closest('[data-role="logout-item"]')) return;
      popup.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
      sendAction('logout');
    });
  }

  function setupAboutDialog() {
    const dialog = document.getElementById("about-dialog");
    if (!(dialog instanceof HTMLDialogElement)) {
      return;
    }
    const button = document.querySelector('[data-role="about-button"]');
    if (button) {
      button.addEventListener("click", () => {
        dialog.showModal();
      });
    }
    const closeButton = dialog.querySelector(".about-close-button");
    if (closeButton) {
      closeButton.addEventListener("click", () => {
        dialog.close();
      });
    }
    // Close on backdrop click.
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) {
        dialog.close();
      }
    });
  }

  let _splitterMode = null;
  let _splitterCleanup = null;
  addEventListener("resize", (event) => { updateSplitters(); });
  function updateSplitters() {
    const bodyWidth = parseInt(getComputedStyle(document.body).width.slice(0,-2));
    const isSmallScreen = bodyWidth <= 834;
    const mode = isSmallScreen ? "vertical" : "horizontal";
    if (mode === _splitterMode) return;
    _splitterMode = mode;
    if (_splitterCleanup) { _splitterCleanup(); _splitterCleanup = null; }
    const min = 180;
    const cursor = isSmallScreen ? "row-resize" : "col-resize";
    const cleanups = [];
    const splitLayouts = Array.from(document.querySelectorAll(".split-layout"));
    splitLayouts.forEach((layout) => {
      const splitter = layout.querySelector('.splitter');
      const left = layout.querySelector('[data-role="left-pane"]');
      const right = layout.querySelector('[data-role="right-pane"]');
      if (!left || !right || !splitter) return;
      left.style.width = "";
      left.style.height = "";
      right.style.width = "";
      right.style.height = "";
      splitter.style.cursor = cursor;
      let dragging = false;
      const onMouseDown = (e) => {
        e.preventDefault();
        dragging = true;
        document.body.style.cursor = cursor;
      };
      const onMouseUp = () => {
        if (dragging) {
          dragging = false;
          document.body.style.cursor = "";
        }
      };
      const onMouseMove = (e) => {
        if (!dragging) return;
        if (isSmallScreen) {
          left.style.width = "";
          right.style.width = "";
          const rect = layout.getBoundingClientRect();
          const nextSize = Math.max(min, Math.min(e.clientY - rect.top, rect.height - min));
          left.style.height = `${nextSize}px`;
          right.style.height = `calc(100% - ${nextSize}px - ${splitter.offsetHeight}px)`;
        } else {
          left.style.height = "";
          right.style.height = "";
          const rect = layout.getBoundingClientRect();
          const nextSize = Math.max(min, Math.min(e.clientX - rect.left, rect.width - min));
          left.style.width = `${nextSize}px`;
          right.style.width = `calc(100% - ${nextSize}px - ${splitter.offsetWidth}px)`;
        }
      };
      splitter.addEventListener("mousedown", onMouseDown);
      window.addEventListener("mouseup", onMouseUp);
      window.addEventListener("mousemove", onMouseMove);
      cleanups.push(() => {
        splitter.removeEventListener("mousedown", onMouseDown);
        window.removeEventListener("mouseup", onMouseUp);
        window.removeEventListener("mousemove", onMouseMove);
      });
    });
    _splitterCleanup = () => cleanups.forEach(fn => fn());
  }


  function setupGlobalHooks() {
    function getConnectionsSort() {
      return state.connectionsSort;
    }

    function setConnectionsSort(sortBy) {
      state.connectionsSort = sortBy || 'name';
    }

    let currentSortPopupEl = null;

    function showSortPopup(anchorEl, options, activeKey, onSelect) {
      if (currentSortPopupEl) {
        currentSortPopupEl.remove();
        currentSortPopupEl = null;
        return;
      }

      const popup = document.createElement('div');
      popup.className = 'rules-sort-popup';
      currentSortPopupEl = popup;

      for (const option of options) {
        const item = document.createElement('div');
        item.className = 'rules-sort-popup-option';
        if (option.key === activeKey) {
          item.classList.add('is-active');
        }
        item.textContent = option.label;
        item.addEventListener('mousedown', (e) => {
          e.stopPropagation();
          onSelect(option.key);
          popup.remove();
          currentSortPopupEl = null;
        });
        popup.appendChild(item);
      }

      document.body.appendChild(popup);

      const rect = anchorEl.getBoundingClientRect();
      popup.style.top = `${rect.bottom}px`;
      const popupWidth = popup.offsetWidth;
      popup.style.left = `${Math.max(0, rect.right - popupWidth)}px`;

      const dismissOnOutsideClick = (e) => {
        if (!popup.contains(e.target)) {
          popup.remove();
          currentSortPopupEl = null;
          document.removeEventListener('mousedown', dismissOnOutsideClick);
          document.removeEventListener('keydown', dismissOnEscape);
        }
      };
      const dismissOnEscape = (e) => {
        if (e.key === 'Escape') {
          popup.remove();
          currentSortPopupEl = null;
          document.removeEventListener('mousedown', dismissOnOutsideClick);
          document.removeEventListener('keydown', dismissOnEscape);
        }
      };
      setTimeout(() => {
        document.addEventListener('mousedown', dismissOnOutsideClick);
        document.addEventListener('keydown', dismissOnEscape);
      }, 0);
    }

    window.app = {
      sendAction,
      getSelectedConnectionRowId,
      setSelectedConnectionRowId,
      getSelectedBlocklistId,
      setSelectedBlocklistId,
      getUserBlocklistId,
      getConnectionsSort,
      setConnectionsSort,
      showSortPopup,
    };
  }

  function init() {
    setupGlobalHooks();
    ws = createWebSocket();
    setupThemeToggle();
    setupFilterControl();
    setupTabs();
    setupSearch();
    setupBlocklistFilter();
    setupSortMenus();
    setupConnectionFilters();
    setupKeyboardNavigation();
    setupPauseUpdatesPing();
    updateSplitters();
    setupOutsideClickClose();
    setupAboutDialog();
    setupUndoWidget();
    setupFilterSwitch();
    setupLogoutMenu();
  }

  init();
})();

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/js/sw.js');
}
