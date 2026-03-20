// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

(() => {
  // Space reserved below the canvas for the uPlot legend (it is not part of the canvas).
  const LEGEND_H = 30;

  let uplot = null;
  let quantum = 1; // time_quantum in seconds, from the last SetTrafficData
  let displayMode = "total"; // "total" | "rate"
  let explicitTimeFilter = null; // { startSecs, endSecs } or null when inactive

  // DOM elements for the two filter indicators (created during initChart).
  let filterBadgeEl = null;           // badge inside the traffic chart
  let visiblePeriodReplacementEl = null; // topbar replacement for the period select

  // Columnar data arrays for uPlot: [timestamps(s), total_bytes, recv_bytes, sent_bytes, block_count]
  // Stores raw bytes per slot (0 → null to suppress zero-height bars).
  const chartData = [[], [], [], [], []];

  // Scale animation state (used by animateToScale / animFrame).
  let scaleAnim = null; // { y0, y1, b0, b1, start, dur }
  let animRaf = null;

  function fmtBytesAxis(v) {
    if (v === 0) return "0";
    if (v < 1e3) return v.toFixed(0) + "B";
    if (v < 1e6) return (v / 1e3).toPrecision(3) + "kB";
    if (v < 1e9) return (v / 1e6).toPrecision(3) + "MB";
    if (v < 1e12) return (v / 1e9).toPrecision(3) + "GB";
    return (v / 1e12).toPrecision(3) + "TB";
  }

  function fmtRateAxis(v) {
    if (v === 0) return "0";
    if (v < 1e3) return v.toFixed(0) + "B/s";
    if (v < 1e6) return (v / 1e3).toPrecision(3) + "kB/s";
    if (v < 1e9) return (v / 1e6).toPrecision(3) + "MB/s";
    if (v < 1e12) return (v / 1e9).toPrecision(3) + "GB/s";
    return (v / 1e12).toPrecision(3) + "TB/s";
  }

  // Returns the target y and blocks maxes from a display data array,
  // considering only series that are currently visible.
  function computeTargetMaxes(displayData) {
    const show = uplot ? uplot.series.map(s => s.show !== false) : [true, true, true, true, true];
    let yMax = 1, bMax = 1;
    for (let i = 0; i < displayData[0].length; i++) {
      if (show[1] && displayData[1][i] != null) yMax = Math.max(yMax, displayData[1][i]);
      if (show[2] && displayData[2][i] != null) yMax = Math.max(yMax, displayData[2][i]);
      if (show[3] && displayData[3][i] != null) yMax = Math.max(yMax, displayData[3][i]);
      if (show[4] && displayData[4][i] != null) bMax = Math.max(bMax, displayData[4][i]);
    }
    return { yMax, bMax };
  }

  function animFrame(now) {
    if (!scaleAnim || !uplot) { animRaf = null; return; }
    const t = Math.min(1, (now - scaleAnim.start) / scaleAnim.dur);
    const e = 1 - (1 - t) ** 3; // ease-out cubic
    uplot.setScale("y",      { min: 0, max: scaleAnim.y0 + (scaleAnim.y1 - scaleAnim.y0) * e });
    uplot.setScale("blocks", { min: 0, max: scaleAnim.b0 + (scaleAnim.b1 - scaleAnim.b0) * e });
    if (t < 1) animRaf = requestAnimationFrame(animFrame);
    else { scaleAnim = null; animRaf = null; }
  }

  function animateToScale(yMax, bMax) {
    const now = performance.now();
    let y0, b0;
    if (scaleAnim) {
      const t = Math.min(1, (now - scaleAnim.start) / scaleAnim.dur);
      const e = 1 - (1 - t) ** 3;
      y0 = scaleAnim.y0 + (scaleAnim.y1 - scaleAnim.y0) * e;
      b0 = scaleAnim.b0 + (scaleAnim.b1 - scaleAnim.b0) * e;
    } else {
      y0 = uplot?.scales?.y?.max ?? yMax;
      b0 = uplot?.scales?.blocks?.max ?? bMax;
    }
    scaleAnim = { y0, y1: yMax, b0, b1: bMax, start: now, dur: 400 };
    if (!animRaf) animRaf = requestAnimationFrame(animFrame);
  }

  // Set scales immediately with no animation. If an animation is in progress,
  // redirect it to the new target rather than fighting it.
  function setScaleDirect(yMax, bMax) {
    if (scaleAnim) {
      scaleAnim.y1 = yMax;
      scaleAnim.b1 = bMax;
    } else {
      uplot.setScale("y",      { min: 0, max: yMax });
      uplot.setScale("blocks", { min: 0, max: bMax });
    }
  }

  // Returns display arrays based on current displayMode.
  // chartData[1..3] contain raw bytes per slot (null for zero).
  // chartData[4] contains block count per slot (null for zero).
  function computeDisplayData() {
    const ts = chartData[0];
    const n = ts.length;

    if (displayMode === "rate") {
      // Divide each slot's bytes by quantum → bytes/second
      const total = new Array(n);
      const recv  = new Array(n);
      const sent  = new Array(n);
      for (let i = 0; i < n; i++) {
        const r = chartData[2][i], s = chartData[3][i];
        recv[i]  = r  != null ? r  / quantum : null;
        sent[i]  = s  != null ? s  / quantum : null;
        total[i] = (r != null || s != null) ? ((r || 0) + (s || 0)) / quantum : null;
      }
      return [ts, total, recv, sent, chartData[4]];
    } else {
      // Cumulative sum (integral) for bytes; block count stays raw
      const total = new Array(n);
      const recv  = new Array(n);
      const sent  = new Array(n);
      let cumT = 0, cumR = 0, cumS = 0;
      for (let i = 0; i < n; i++) {
        cumR += chartData[2][i] || 0;
        cumS += chartData[3][i] || 0;
        cumT += chartData[1][i] || 0;
        recv[i]  = cumR;
        sent[i]  = cumS;
        total[i] = cumT;
      }
      return [ts, total, recv, sent, chartData[4]];
    }
  }

  // Send SetExplicitTimeFilter action to the backend.
  // Pass null for both to clear the filter.
  function sendExplicitTimeFilterAction(startSecs, endSecs) {
    window.app?.sendAction("setExplicitTimeFilter", {
      start_secs: startSecs,
      end_inclusive_secs: endSecs,
    });
  }

  // Update visibility of the two filter indicator elements to match explicitTimeFilter state.
  function updateExplicitTimeFilterUI() {
    const active = explicitTimeFilter !== null;

    if (filterBadgeEl) {
      filterBadgeEl.hidden = !active;
    }

    const select = document.querySelector('.section[data-section="connections"] [data-role="visible-period-filter"]');
    if (select) {
      select.hidden = active;
    }
    if (visiblePeriodReplacementEl) {
      visiblePeriodReplacementEl.hidden = !active;
    }
  }

  function setExplicitTimeFilter(startSecs, endSecs) {
    explicitTimeFilter = { startSecs, endSecs };
    updateExplicitTimeFilterUI();
    sendExplicitTimeFilterAction(startSecs, endSecs);
  }

  function clearExplicitTimeFilter() {
    explicitTimeFilter = null;
    updateExplicitTimeFilterUI();
    sendExplicitTimeFilterAction(null, null);
  }

  function buildOpts(width, height) {
    const isRate = displayMode === "rate";
    const fmtY = isRate ? fmtRateAxis : fmtBytesAxis;
    const cs = getComputedStyle(document.documentElement);
    const textColor = cs.getPropertyValue("--text-muted").trim();
    const gridColor = cs.getPropertyValue("--line").trim();

    const bytesSeries = isRate
      ? { paths: uPlot.paths.bars({ size: [1, Infinity] }), points: { show: false } }
      : { paths: uPlot.paths.spline(), points: { show: false } };

    return {
      width,
      height,
      scales: {
        x: {},
        y:      { auto: false },
        blocks: { auto: false },
      },
      axes: [
        {
          stroke: textColor,
          grid:  { stroke: gridColor },
          ticks: { stroke: gridColor },
        },
        {
          scale: "y",
          values: (_self, ticks) => ticks.map(fmtY),
          size: 72,
          stroke: textColor,
          grid:  { stroke: gridColor },
          ticks: { stroke: gridColor },
        },
        {
          scale: "blocks",
          side: 1,
          label: "Blocked",
          labelSize: 14,
          values: (_self, ticks) => ticks.map(v => v > 0 ? v.toFixed(0) : "0"),
          size: 50,
          stroke: textColor,
          grid: { show: false },
          ticks: { show: false },
        },
      ],
      series: [
        {
          value: (_self, v) => {
            if (v == null) return "--";
            const d = new Date(v * 1000);
            const date = d.getFullYear()
              + "-" + String(d.getMonth() + 1).padStart(2, "0")
              + "-" + String(d.getDate()).padStart(2, "0");
            const time = String(d.getHours()).padStart(2, "0")
              + ":" + String(d.getMinutes()).padStart(2, "0");
            return date + " " + time;
          },
        },
        {
          label: "Total",
          scale: "y",
          stroke: "rgba(120,130,150,0.6)",
          fill: "rgba(120,130,150,0.15)",
          value: (_self, v) => v == null ? "--" : fmtY(v),
          ...bytesSeries,
          show: false,
        },
        {
          label: "Received",
          scale: "y",
          stroke: "rgba(74,144,217,0.8)",
          fill: "rgba(74,144,217,0.2)",
          value: (_self, v) => v == null ? "--" : fmtY(v),
          ...bytesSeries,
        },
        {
          label: "Sent",
          scale: "y",
          stroke: "rgba(142,68,173,0.8)",
          fill: "rgba(142,68,173,0.2)",
          value: (_self, v) => v == null ? "--" : fmtY(v),
          ...bytesSeries,
        },
        {
          label: "Blocked",
          scale: "blocks",
          stroke: "rgba(192,57,43,0.8)",
          fill: "rgba(192,57,43,0.35)",
          value: (_self, v) => v == null ? "--" : v.toFixed(0),
          paths: uPlot.paths.bars({ size: [1, Infinity] }),
          points: { show: false },
        },
      ],
      cursor: {
        drag: { x: true, y: false },
      },
      hooks: {
        setSeries: [() => {
          // Re-animate scale when the user toggles a series on/off in the legend.
          const display = computeDisplayData();
          const { yMax, bMax } = computeTargetMaxes(display);
          animateToScale(yMax, bMax);
        }],
        setSelect: [u => {
          // setSelect fires on mouseup after a drag; use it to capture the zoomed range.
          if (u.select.width > 5) {
            const startSecs = Math.floor(u.posToVal(u.select.left, "x"));
            const endSecs = Math.ceil(u.posToVal(u.select.left + u.select.width, "x"));
            if (endSecs > startSecs) {
              setExplicitTimeFilter(startSecs, endSecs);
            }
          }
        }],
      },
    };
  }

  function setupHSplitter(wrap) {
    const section = document.querySelector('.section[data-section="connections"]');
    const handle = section?.querySelector('[data-role="h-splitter"]');
    if (!handle) return;

    let dragging = false;
    let startY = 0;
    let startH = 0;
    const MIN_H = 80;
    const MAX_H = 600;

    handle.addEventListener("mousedown", e => {
      e.preventDefault();
      dragging = true;
      startY = e.clientY;
      startH = wrap.getBoundingClientRect().height;
      document.body.style.cursor = "row-resize";
    });

    window.addEventListener("mouseup", () => {
      if (dragging) {
        dragging = false;
        document.body.style.cursor = "";
      }
    });

    window.addEventListener("mousemove", e => {
      if (!dragging) return;
      const newH = Math.max(MIN_H, Math.min(MAX_H, startH + (startY - e.clientY)));
      wrap.style.height = newH + "px";
    });
  }

  function setupModeSelector(wrap) {
    const sel = document.createElement("select");
    sel.className = "traffic-mode-selector";
    sel.innerHTML = `
      <option value="total">Total bytes</option>
      <option value="rate">Average rate</option>
    `;
    sel.value = displayMode;
    sel.addEventListener("change", () => {
      displayMode = sel.value;
      rebuildPlot();
    });
    wrap.appendChild(sel);
    return sel;
  }

  // Create the chart-overlay filter badge and the topbar period-filter replacement.
  // Called once from initChart(); elements persist across rebuildPlot() calls.
  function setupFilterControls(wrap) {
    // Badge overlaid on the traffic chart (to the left of the mode selector).
    const badge = document.createElement("div");
    badge.className = "traffic-filter-badge";
    badge.hidden = true;
    badge.innerHTML = `Time filter <button class="traffic-filter-cancel" type="button" aria-label="Remove time filter">\u00d7</button>`;
    badge.querySelector(".traffic-filter-cancel").addEventListener("click", () => {
      clearExplicitTimeFilter();
    });
    wrap.appendChild(badge);
    filterBadgeEl = badge;

    // Topbar replacement: inserted after the visible-period-filter select and toggled in sync.
    const section = document.querySelector('.section[data-section="connections"]');
    const select = section?.querySelector('[data-role="visible-period-filter"]');
    if (select) {
      const replacement = document.createElement("div");
      replacement.className = "time-filter-indicator";
      replacement.hidden = true;
      replacement.innerHTML = `Time filter <button class="time-filter-cancel" type="button" aria-label="Remove time filter">\u00d7</button>`;
      replacement.querySelector(".time-filter-cancel").addEventListener("click", () => {
        clearExplicitTimeFilter();
      });
      select.insertAdjacentElement("afterend", replacement);
      visiblePeriodReplacementEl = replacement;
    }
  }

  function rebuildPlot() {
    const wrap = document.getElementById("traffic-chart");
    if (!wrap) return;
    if (animRaf) { cancelAnimationFrame(animRaf); animRaf = null; }
    scaleAnim = null;
    if (uplot) {
      uplot.destroy();
      uplot = null;
    }
    const w = wrap.clientWidth;
    const h = Math.max(60, wrap.clientHeight - LEGEND_H);
    const display = computeDisplayData();
    uplot = new uPlot(buildOpts(w, h), display, wrap);
    const { yMax, bMax } = computeTargetMaxes(display);
    animateToScale(yMax, bMax);
  }

  function initChart() {
    const wrap = document.getElementById("traffic-chart");
    if (!wrap || wrap.clientWidth <= 0) return;

    setupModeSelector(wrap);
    setupFilterControls(wrap);

    const w = wrap.clientWidth;
    const h = Math.max(60, wrap.clientHeight - LEGEND_H);
    uplot = new uPlot(buildOpts(w, h), computeDisplayData(), wrap);

    const ro = new ResizeObserver(entries => {
      for (const entry of entries) {
        if (!uplot) continue;
        const { width, height } = entry.contentRect;
        if (width > 10 && height > 10) {
          uplot.setSize({
            width: Math.floor(width),
            height: Math.floor(Math.max(60, height - LEGEND_H)),
          });
        }
      }
    });
    ro.observe(wrap);

    setupHSplitter(wrap);
  }

  function handleSetTrafficData(msg) {
    const d = msg.data;
    quantum = d.timeQuantum || 1;
    const n = d.bytesReceived.length;

    chartData[0].length = 0;
    chartData[1].length = 0;
    chartData[2].length = 0;
    chartData[3].length = 0;
    chartData[4].length = 0;

    for (let i = 0; i < n; i++) {
      const recv = d.bytesReceived[i];
      const sent = d.bytesSent[i];
      const total = recv + sent;
      chartData[0].push((d.startTime + i) * quantum);
      chartData[1].push(total || null);
      chartData[2].push(recv || null);
      chartData[3].push(sent || null);
      chartData[4].push(d.blockCount[i] || null);
    }

    if (!uplot) initChart();
    if (uplot) {
      const display = computeDisplayData();
      uplot.setData(display);
      const { yMax, bMax } = computeTargetMaxes(display);
      animateToScale(yMax, bMax);
    }
  }

  function handleUpdateTrafficData(msg) {
    if (!uplot) return;
    const d = msg.data;

    // Prune entries that are before the new window start
    const newStartSec = d.startTime * quantum;
    while (chartData[0].length > 0 && chartData[0][0] < newStartSec) {
      chartData[0].shift();
      chartData[1].shift();
      chartData[2].shift();
      chartData[3].shift();
      chartData[4].shift();
    }

    // Update the slot in-place if the last entry matches, otherwise append
    const updatedSec = d.updatedTime * quantum;
    const recv = d.bytesReceived;
    const sent = d.bytesSent;
    const total = recv + sent;
    const last = chartData[0].length - 1;
    if (last >= 0 && chartData[0][last] === updatedSec) {
      chartData[1][last] = total || null;
      chartData[2][last] = recv || null;
      chartData[3][last] = sent || null;
      chartData[4][last] = d.blockCount || null;
    } else {
      chartData[0].push(updatedSec);
      chartData[1].push(total || null);
      chartData[2].push(recv || null);
      chartData[3].push(sent || null);
      chartData[4].push(d.blockCount || null);
    }

    const display = computeDisplayData();
    uplot.setData(display);
    const { yMax, bMax } = computeTargetMaxes(display);
    setScaleDirect(yMax, bMax);
  }

  // Rebuild when the theme changes so axis/grid colors are re-read from CSS variables.
  new MutationObserver(() => {
    if (uplot) rebuildPlot();
  }).observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });

  window.handleSetTrafficData = handleSetTrafficData;
  window.handleUpdateTrafficData = handleUpdateTrafficData;
})();
