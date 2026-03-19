// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

(() => {
  const USER_BLOCKLIST_ID = -1;

  const state = {
    activeSection: "connections",
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

    socket.addEventListener("close", () => {
      console.log("WebSocket closed — will retry in 10 s");
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
          handleClear();
          break;
        case "insertConnectionRows":
          handleInsertRows(msg.afterId, msg.rows, msg.animate);
          break;
        case "removeConnectionRows":
          handleRemoveRows(msg.startId, msg.endId);
          break;
        case "moveConnetionRows":
          handleMoveRows(msg.startId, msg.endId, msg.targetId);
          break;
        case "updateConnectionRows":
          handleUpdateRows(msg.rows);
          handleUpdateStatistics(msg.statistics);
          break;
        case "updateRuleButtons":
          handleUpdateRuleButtons(msg.rows);
          break;
        case "trafficEvents":
          handleEvents(msg.data);
          break;
        case "setInspector":
          handleSetInspector(msg);
          break;
        case "setBlocklists":
          handleSetBlocklists(msg);
          break;
        case "setRules":
          handleSetRules(msg);
          break;
        case "updateRules":
          handleUpdateRules(msg);
          break;
        case "setBlocklistDetails":
          handleSetBlocklistDetails(msg);
          break;
        case "setBlocklistEntries":
          handleSetBlocklistEntries(msg);
          break;
        case "setBlocklistEntryLocation":
          handleSetBlocklistEntryLocation(msg);
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
        default:
          console.warn("Unknown msg from server", JSON.stringify(msg));
      }
    }
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
        input.classList.toggle("is-filtered", input.value.trim().length > 0);
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
        const tempLabels = { "internet-and-localhost": "Internet + Local Host", "invalid": "(Invalid)" };
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
          opt.textContent = tempLabels[loc];
          opt.dataset.temp = "1";
          locationInput.appendChild(opt);
        }
        locationInput.value = loc;
      }
      if (visiblePeriodInput instanceof HTMLSelectElement) {
        visiblePeriodInput.value = state.connectionsFilters.visiblePeriodLimit || "none";
      }
    }
    const sortSelect = document.querySelector('[data-role="connections-sort"]');
    if (sortSelect instanceof HTMLSelectElement) {
      sortSelect.value = state.connectionsSort || "name";
    }
    const searchInput = document.querySelector('[data-role="search"][data-section="connections"]');
    if (searchInput instanceof HTMLInputElement && searchInput.value !== (state.connectionsSearchTerm || "")) {
      searchInput.value = state.connectionsSearchTerm || "";
      searchInput.classList.toggle("is-filtered", searchInput.value.trim().length > 0);
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
    window.refreshConnectionsBytes?.();
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
        const filters = readConnectionsFiltersFromControls();
        sendAction("setConnectionsFilters", { filters });
      });
    });

    const sortSelect = section.querySelector('[data-role="connections-sort"]');
    if (sortSelect instanceof HTMLSelectElement) {
      sortSelect.addEventListener("change", () => {
        sendAction("setConnectionsSort", { sortBy: sortSelect.value });
      });
    }
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

  function setupSplitters() {
    const splitLayouts = Array.from(document.querySelectorAll(".split-layout"));

    splitLayouts.forEach((layout) => {
      const left = layout.querySelector('[data-role="left-pane"]');
      const right = layout.querySelector('[data-role="right-pane"]');
      const splitter = layout.querySelector('[data-role="splitter"]');

      if (!left || !right || !splitter) {
        return;
      }

      let dragging = false;

      splitter.addEventListener("mousedown", (event) => {
        event.preventDefault();
        dragging = true;
        document.body.style.cursor = "col-resize";
      });

      window.addEventListener("mouseup", () => {
        dragging = false;
        document.body.style.cursor = "";
      });

      window.addEventListener("mousemove", (event) => {
        if (!dragging) {
          return;
        }

        const rect = layout.getBoundingClientRect();
        const min = 180;
        const max = rect.width - 180;
        let nextLeftWidth = event.clientX - rect.left;
        nextLeftWidth = Math.max(min, Math.min(nextLeftWidth, max));

        left.style.width = `${nextLeftWidth}px`;
        right.style.width = `calc(100% - ${nextLeftWidth}px - ${splitter.offsetWidth}px)`;
      });
    });
  }

  function setupGlobalHooks() {
    function getConnectionsSort() {
      return state.connectionsSort;
    }

    window.app = {
      sendAction,
      getSelectedConnectionRowId,
      setSelectedConnectionRowId,
      getSelectedBlocklistId,
      setSelectedBlocklistId,
      getUserBlocklistId,
      getConnectionsSort,
    };
  }

  function init() {
    setupGlobalHooks();
    ws = createWebSocket();
    setupTabs();
    setupSearch();
    setupSortMenus();
    setupConnectionFilters();
    setupKeyboardNavigation();
    setupPauseUpdatesPing();
    setupSplitters();
    setupOutsideClickClose();
  }

  init();
})();

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}
