// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

const uPlot = require('uplot').default;

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
        if(v === 0) return "0";
        if(v < 1e3) return v.toFixed(0) + "B";
        if(v < 1e6) return (v / 1e3).toPrecision(3) + "kB";
        if(v < 1e9) return (v / 1e6).toPrecision(3) + "MB";
        if(v < 1e12) return (v / 1e9).toPrecision(3) + "GB";
        return (v / 1e12).toPrecision(3) + "TB";
    }

    function fmtRateAxis(v) {
        if(v === 0) return "0";
        if(v < 1e3) return v.toFixed(0) + "B/s";
        if(v < 1e6) return (v / 1e3).toPrecision(3) + "kB/s";
        if(v < 1e9) return (v / 1e6).toPrecision(3) + "MB/s";
        if(v < 1e12) return (v / 1e9).toPrecision(3) + "GB/s";
        return (v / 1e12).toPrecision(3) + "TB/s";
    }

    // Returns the target y and blocks maxes from a display data array,
    // considering only series that are currently visible.
    function computeTargetMaxes(displayData) {
        const show = uplot ? uplot.series.map(s => s.show !== false) : [true, true, true, true, true];
        let yMax = 1, bMax = 1;
        for(let i = 0; i < displayData[0].length; i++) {
            if(show[1] && displayData[1][i] != null) yMax = Math.max(yMax, displayData[1][i]);
            if(show[2] && displayData[2][i] != null) yMax = Math.max(yMax, displayData[2][i]);
            if(show[3] && displayData[3][i] != null) yMax = Math.max(yMax, displayData[3][i]);
            if(show[4] && displayData[4][i] != null) bMax = Math.max(bMax, displayData[4][i]);
        }
        return {yMax, bMax};
    }

    function animFrame(now) {
        if(!scaleAnim || !uplot) {
            animRaf = null;
            return;
        }
        const t = Math.min(1, (now - scaleAnim.start) / scaleAnim.dur);
        const e = 1 - (1 - t) ** 3; // ease-out cubic
        uplot.setScale("y", {min: 0, max: scaleAnim.y0 + (scaleAnim.y1 - scaleAnim.y0) * e});
        uplot.setScale("blocks", {min: 0, max: scaleAnim.b0 + (scaleAnim.b1 - scaleAnim.b0) * e});
        if(t < 1) animRaf = requestAnimationFrame(animFrame);
        else {
            scaleAnim = null;
            animRaf = null;
        }
    }

    function animateToScale(yMax, bMax) {
        const now = performance.now();
        let y0, b0;
        if(scaleAnim) {
            const t = Math.min(1, (now - scaleAnim.start) / scaleAnim.dur);
            const e = 1 - (1 - t) ** 3;
            y0 = scaleAnim.y0 + (scaleAnim.y1 - scaleAnim.y0) * e;
            b0 = scaleAnim.b0 + (scaleAnim.b1 - scaleAnim.b0) * e;
        } else {
            y0 = uplot?.scales?.y?.max ?? yMax;
            b0 = uplot?.scales?.blocks?.max ?? bMax;
        }
        scaleAnim = {y0, y1: yMax, b0, b1: bMax, start: now, dur: 400};
        if(!animRaf) animRaf = requestAnimationFrame(animFrame);
    }

    // Set scales immediately with no animation. If an animation is in progress,
    // redirect it to the new target rather than fighting it.
    function setScaleDirect(yMax, bMax) {
        if(scaleAnim) {
            scaleAnim.y1 = yMax;
            scaleAnim.b1 = bMax;
        } else {
            uplot.setScale("y", {min: 0, max: yMax});
            uplot.setScale("blocks", {min: 0, max: bMax});
        }
    }

    // Returns display arrays based on current displayMode.
    // chartData[1..3] contain raw bytes per slot (null for zero).
    // chartData[4] contains block count per slot (null for zero).
    function computeDisplayData() {
        const ts = chartData[0];
        const n = ts.length;

        if(displayMode === "rate") {
            // Divide each slot's bytes by quantum → bytes/second
            const total = new Array(n);
            const recv = new Array(n);
            const sent = new Array(n);
            for(let i = 0; i < n; i++) {
                const r = chartData[2][i], s = chartData[3][i];
                recv[i] = r != null ? r / quantum : null;
                sent[i] = s != null ? s / quantum : null;
                total[i] = (r != null || s != null) ? ((r || 0) + (s || 0)) / quantum : null;
            }
            return [ts, total, recv, sent, chartData[4]];
        } else {
            // Cumulative sum (integral) for bytes; block count stays raw
            const total = new Array(n);
            const recv = new Array(n);
            const sent = new Array(n);
            let cumT = 0, cumR = 0, cumS = 0;
            for(let i = 0; i < n; i++) {
                cumR += chartData[2][i] || 0;
                cumS += chartData[3][i] || 0;
                cumT += chartData[1][i] || 0;
                recv[i] = cumR;
                sent[i] = cumS;
                total[i] = cumT;
            }
            return [ts, total, recv, sent, chartData[4]];
        }
    }

    // Send SetExplicitTimeFilter action to the backend.
    // Pass null for both to clear the filter.
    function sendExplicitTimeFilterAction(startSecs, endSecs) {
        window.app?.sendAction("setExplicitTimeFilter", {
            startSecs: startSecs,
            endInclusiveSecs: endSecs,
        });
    }

    // Update visibility of the two filter indicator elements to match explicitTimeFilter state.
    function updateExplicitTimeFilterUI() {
        const active = explicitTimeFilter !== null;

        if(filterBadgeEl) {
            filterBadgeEl.hidden = !active;
        }

        const select = document.querySelector('.section[data-section="connections"] [data-role="visible-period-filter"]');
        if(select) {
            select.hidden = active;
        }
        if(visiblePeriodReplacementEl) {
            visiblePeriodReplacementEl.hidden = !active;
        }
    }

    function setExplicitTimeFilter(startSecs, endSecs) {
        explicitTimeFilter = {startSecs, endSecs};
        updateExplicitTimeFilterUI();
        sendExplicitTimeFilterAction(startSecs, endSecs);
    }

    function clearExplicitTimeFilter() {
        explicitTimeFilter = null;
        updateExplicitTimeFilterUI();
        sendExplicitTimeFilterAction(null, null);
    }

    // uPlot fmtDate factory — called once per template string, returns a (Date)=>string.
    // Preserves uPlot's tick-selection algorithm; only the rendering is locale-aware.
    //
    // Template tokens used by uPlot (uppercase = date, lowercase = time):
    //   {YYYY}/{YY}   year          {M}/{MM}/{MMM}  month / abbrev-name  {D}/{DD}  day
    //   {H}/{HH}      24 h hour     {h}             12 h hour
    //   {mm}          minutes       {ss}  seconds   {fff}  milliseconds
    //   {aa}/{AA}     am/pm
    //   \n            separates primary label from secondary context label
    //
    function uplotFmtDate(tpl) {
        const parts = tpl.split('\n');
        const fns = parts.map(fmtDatePart);
        return d => fns.map(fn => fn(d)).join('\n');
    }

    function fmtDatePart(part) {
        if(!part) return () => '';

        const hasYear = /\{Y/.test(part);
        const hasMonth = /\{M/.test(part);       // uppercase M
        const hasDay = /\{D/.test(part);
        const hasHour = /\{[hH]/.test(part);
        const hasMin = /\{mm\}/.test(part);    // lowercase mm = minutes
        const hasSec = /\{ss\}/.test(part);
        const hasMillis = /\{fff\}/.test(part);
        const hasMonthName = /\{MMM\}/.test(part);

        const wantsDate = hasYear || hasMonth || hasDay;
        const wantsTime = hasHour || hasMin;

        if(wantsDate && wantsTime) {
            const showSec = hasSec || hasMillis;
            return d => {
                const p = window.getDtPrefs();
                return window._fmtDate(d, p) + ' ' + window._fmtTime(d, p, showSec);
            };
        }

        if(hasMonthName && !wantsTime)
            return d => d.toLocaleDateString(undefined, {month: 'short'});

        if(wantsDate) {
            if(hasYear && !hasMonth && !hasDay)
                return d => String(d.getFullYear());
            if(!hasYear) {                             // month+day without year
                return d => {
                    const prefs = window.getDtPrefs();
                    const m = window._pad(d.getMonth() + 1);
                    const day = window._pad(d.getDate());
                    if(prefs.dateSep !== undefined)
                        return `${m}${prefs.dateSep}${day}`;  // ISO order matches _fmtDate override
                    const {order, sep} = window._getLocaleDateFmt();
                    if(order === 'DMY') return `${day}${sep}${m}`;
                    return `${m}${sep}${day}`;
                };
            }
            return d => window._fmtDate(d, window.getDtPrefs());      // full date
        }

        if(!hasHour && !hasMin && hasSec) {          // continuation label ":{ss}[.{fff}]"
            if(hasMillis)
                return d => ':' + window._pad(d.getSeconds()) + '.' + String(d.getMilliseconds()).padStart(3, '0');
            return d => ':' + window._pad(d.getSeconds());
        }

        if(wantsTime) {
            const showSec = hasSec || hasMillis;
            return d => window._fmtTime(d, window.getDtPrefs(), showSec);
        }

        return uPlot.fmtDate(part);                   // fallback for unexpected tokens
    }

    function buildOpts(width, height) {
        const isRate = displayMode === "rate";
        const fmtY = isRate ? fmtRateAxis : fmtBytesAxis;
        const cs = getComputedStyle(document.documentElement);
        const textColor = cs.getPropertyValue("--text-muted").trim();
        const gridColor = cs.getPropertyValue("--line").trim();
        const totalStroke = cs.getPropertyValue("--traffic-total-stroke").trim();
        const totalFill = cs.getPropertyValue("--traffic-total-fill").trim();
        const rxStroke = cs.getPropertyValue("--traffic-rx-stroke").trim();
        const rxFill = cs.getPropertyValue("--traffic-rx-fill").trim();
        const txStroke = cs.getPropertyValue("--traffic-tx-stroke").trim();
        const txFill = cs.getPropertyValue("--traffic-tx-fill").trim();
        const blockedStroke = cs.getPropertyValue("--traffic-blocked-stroke").trim();
        const blockedFill = cs.getPropertyValue("--traffic-blocked-fill").trim();

        const bytesSeries = isRate
            ? {paths: typeof uPlot.paths == 'undefined' ? null : uPlot.paths.bars({size: [1, Infinity]}), points: {show: false}}
            : {paths: typeof uPlot.paths == 'undefined' ? null : uPlot.paths.spline(), points: {show: false}};

        return {
            width,
            height,
            fmtDate: uplotFmtDate,
            scales: {
                x: {},
                y: {auto: false},
                blocks: {auto: false},
            },
            axes: [
                {
                    stroke: textColor,
                    grid: {stroke: gridColor},
                    ticks: {stroke: gridColor},
                },
                {
                    scale: "y",
                    values: (_self, ticks) => ticks.map(fmtY),
                    size: 72,
                    stroke: textColor,
                    grid: {stroke: gridColor},
                    ticks: {stroke: gridColor},
                },
                {
                    scale: "blocks",
                    side: 1,
                    label: window._localization.t('traffic-blocked'),
                    labelSize: 14,
                    values: (_self, ticks) => ticks.map(v => v > 0 ? v.toFixed(0) : "0"),
                    size: 50,
                    stroke: textColor,
                    grid: {show: false},
                    ticks: {show: false},
                },
            ],
            series: [
                {
                    value: (_self, v) => v == null ? "--" : formatDateTime(v, false, {hour12: false}),
                },
                {
                    label: window._localization.t('traffic-total'),
                    scale: "y",
                    stroke: totalStroke,
                    fill: totalFill,
                    value: (_self, v) => v == null ? "--" : fmtY(v),
                    ...bytesSeries,
                    show: false,
                },
                {
                    label: window._localization.t('traffic-received'),
                    scale: "y",
                    stroke: rxStroke,
                    fill: rxFill,
                    value: (_self, v) => v == null ? "--" : fmtY(v),
                    ...bytesSeries,
                },
                {
                    label: window._localization.t('traffic-sent'),
                    scale: "y",
                    stroke: txStroke,
                    fill: txFill,
                    value: (_self, v) => v == null ? "--" : fmtY(v),
                    ...bytesSeries,
                },
                {
                    label: window._localization.t('traffic-blocked'),
                    scale: "blocks",
                    stroke: blockedStroke,
                    fill: blockedFill,
                    value: (_self, v) => v == null ? "--" : v.toFixed(0),
                    paths: typeof uPlot.paths == 'undefined' ? null : uPlot.paths.bars({size: [1, Infinity]}),
                    points: {show: false},
                },
            ],
            cursor: {
                drag: {x: true, y: false},
            },
            hooks: {
                setSeries: [() => {
                    // Re-animate scale when the user toggles a series on/off in the legend.
                    const display = computeDisplayData();
                    const {yMax, bMax} = computeTargetMaxes(display);
                    animateToScale(yMax, bMax);
                }],
                setSelect: [u => {
                    // setSelect fires on mouseup after a drag; use it to capture the zoomed range.
                    if(u.select.width > 5) {
                        const startSecs = Math.floor(u.posToVal(u.select.left, "x"));
                        const endSecs = Math.ceil(u.posToVal(u.select.left + u.select.width, "x"));
                        if(endSecs > startSecs) {
                            setExplicitTimeFilter(startSecs, endSecs);
                        }
                    }
                }],
            },
        };
    }

    let _hSplitterMode = null;
    let _hSplitterCleanup = null;
    addEventListener("resize", (event) => {
        updateHSplitter(document.getElementById("traffic-chart"));
    });

    function updateHSplitter(wrap) {
        const section = document.querySelector('.section[data-section="connections"]');
        const handle = section?.querySelector('[data-role="h-splitter"]');
        if(!handle) return;
        const bodyWidth = parseInt(getComputedStyle(document.body).width.slice(0, -2));
        const isChartOnDisplay = bodyWidth >= 700;
        const isSmallScreen = bodyWidth <= 834;
        const mode = `${isChartOnDisplay}:${isSmallScreen}`;
        if(mode === _hSplitterMode) return;
        _hSplitterMode = mode;
        if(_hSplitterCleanup) {
            _hSplitterCleanup();
            _hSplitterCleanup = null;
        }

        const topPane = document.querySelector(".split-layout");
        const rect = topPane.getBoundingClientRect();
        let dragging = false;
        let startY = 0;
        let startH = 0;
        const MIN_H = 80;
        const MAX_H = 600;

        const onMouseDown = (e) => {
            e.preventDefault();
            dragging = true;
            startY = e.clientY;
            startH = wrap.getBoundingClientRect().height;
            document.body.style.cursor = "row-resize";
        };
        const onMouseUp = () => {
            if(dragging) {
                dragging = false;
                document.body.style.cursor = "";
            }
        };
        const onMouseMove = (e) => {
            if(!dragging) return;
            const newH = Math.max(MIN_H, Math.min(MAX_H, startH + (startY - e.clientY)));
            wrap.style.height = newH + "px";
            if(isChartOnDisplay && isSmallScreen) {
                let nextTopHeight = e.clientY - rect.top;
                nextTopHeight = Math.max(180, Math.min(nextTopHeight, MAX_H));
                topPane.style.height = `${nextTopHeight}px`;
            }
        };
        handle.addEventListener("mousedown", onMouseDown);
        window.addEventListener("mouseup", onMouseUp);
        window.addEventListener("mousemove", onMouseMove);
        _hSplitterCleanup = () => {
            handle.removeEventListener("mousedown", onMouseDown);
            window.removeEventListener("mouseup", onMouseUp);
            window.removeEventListener("mousemove", onMouseMove);
        };
    }

    function setupModeSelector(wrap) {
        const sel = document.createElement("select");
        sel.className = "traffic-mode-selector";
        const optTotal = document.createElement("option");
        optTotal.value = "total";
        optTotal.dataset.i18n = "traffic-mode-total";
        optTotal.textContent = window._localization.t("traffic-mode-total");
        const optRate = document.createElement("option");
        optRate.value = "rate";
        optRate.dataset.i18n = "traffic-mode-rate";
        optRate.textContent = window._localization.t("traffic-mode-rate");
        sel.append(optTotal, optRate);
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
        const badge = document.createElement("button");
        badge.type = "button";
        badge.className = "traffic-filter-badge";
        badge.hidden = true;
        badge.setAttribute("aria-label", window._localization.t("remove-time-filter"));
        badge.dataset.i18nAriaLabel = "remove-time-filter";
        const badgeText = document.createElement("span");
        badgeText.dataset.i18n = "time-filter";
        badgeText.textContent = window._localization.t("time-filter");
        const badgeX = document.createElement("span");
        badgeX.setAttribute("aria-hidden", "true");
        badgeX.textContent = "\u00d7";
        badge.append(badgeText, badgeX);
        badge.addEventListener("click", () => {
            clearExplicitTimeFilter();
        });
        wrap.appendChild(badge);
        filterBadgeEl = badge;

        // Topbar replacement: inserted after the visible-period-filter select and toggled in sync.
        const section = document.querySelector('.section[data-section="connections"]');
        const select = section?.querySelector('[data-role="visible-period-filter"]');
        if(select) {
            const replacement = document.createElement("button");
            replacement.type = "button";
            replacement.className = "filter-btn is-active time-filter-indicator";
            replacement.hidden = true;
            replacement.setAttribute("aria-label", window._localization.t("remove-time-filter"));
            replacement.dataset.i18nAriaLabel = "remove-time-filter";
            const replText = document.createElement("span");
            replText.dataset.i18n = "time-filter";
            replText.textContent = window._localization.t("time-filter");
            const replX = document.createElement("span");
            replX.setAttribute("aria-hidden", "true");
            replX.textContent = "\u00d7";
            replacement.append(replText, replX);
            replacement.addEventListener("click", () => {
                clearExplicitTimeFilter();
            });
            select.insertAdjacentElement("afterend", replacement);
            visiblePeriodReplacementEl = replacement;
        }
    }

    function chartSize(element) {
        // 1. Get the width including padding (clientWidth)
        const clientWidth = element.clientWidth;
        const clientHeight = element.clientHeight

        // 2. Get the computed CSS styles
        const style = window.getComputedStyle(element);

        // 3. Parse the padding values (they come as strings like "20px")
        const paddingLeft = parseFloat(style.paddingLeft);
        const paddingRight = parseFloat(style.paddingRight);

        const paddingTop = parseFloat(style.paddingTop);
        const paddingBottom = parseFloat(style.paddingBottom);

        // 4. Subtract them
        return {
            width: clientWidth - paddingLeft - paddingRight,
            height: Math.max(60, clientHeight - paddingTop - paddingBottom - LEGEND_H)
        }
    }

    function rebuildPlot() {
        const wrap = document.getElementById("traffic-chart");
        if(!wrap) return;
        if(animRaf) {
            cancelAnimationFrame(animRaf);
            animRaf = null;
        }
        scaleAnim = null;
        if(uplot) {
            uplot.destroy();
            uplot = null;
        }

        const {width, height} = chartSize(wrap);
        const display = computeDisplayData();
        uplot = new uPlot(buildOpts(width, height), display, wrap);
        const {yMax, bMax} = computeTargetMaxes(display);
        animateToScale(yMax, bMax);
    }

    function initChart() {
        const wrap = document.getElementById("traffic-chart");
        if(!wrap || wrap.clientWidth <= 0) return;

        setupModeSelector(wrap);
        setupFilterControls(wrap);

        const {width, height} = chartSize(wrap);
        const display = computeDisplayData();
        uplot = new uPlot(buildOpts(width, height), display, wrap);

        const ro = new ResizeObserver(entries => {
            for(const entry of entries) {
                if(!uplot) continue;
                const {width, height} = chartSize(entry.target);

                if(width > 10 && height > 10) {
                    uplot.setSize({
                        width: width,
                        height: height
                    });
                }
            }
        });
        ro.observe(wrap);

        updateHSplitter(wrap);
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

        for(let i = 0; i < n; i++) {
            const recv = d.bytesReceived[i];
            const sent = d.bytesSent[i];
            const total = recv + sent;
            chartData[0].push((d.startTime + i) * quantum);
            chartData[1].push(total || null);
            chartData[2].push(recv || null);
            chartData[3].push(sent || null);
            chartData[4].push(d.blockCount[i] || null);
        }

        if(!uplot) initChart();
        if(uplot) {
            const display = computeDisplayData();
            uplot.setData(display);
            const {yMax, bMax} = computeTargetMaxes(display);
            animateToScale(yMax, bMax);
        }
    }

    function handleUpdateTrafficData(msg) {
        if(!uplot) return;
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
        if(last >= 0 && chartData[0][last] === updatedSec) {
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
        const {yMax, bMax} = computeTargetMaxes(display);
        setScaleDirect(yMax, bMax);
    }

    // Rebuild when the theme changes so axis/grid colors are re-read from CSS variables.
    new MutationObserver(() => {
        if(uplot) rebuildPlot();
    }).observe(document.documentElement, {attributes: true, attributeFilter: ["class"]});

    window.handleSetTrafficData = handleSetTrafficData;
    window.handleUpdateTrafficData = handleUpdateTrafficData;
    window.rebuildTrafficPlot = () => {
        if(uplot) rebuildPlot();
    };
})();
