/* Log Anomaly Detector — demo replay.
 *
 * The one rule that governs this file: a window's verdict is NEVER read from
 * the feed. It is always `w.err > threshold`, computed here, every time. The
 * feed exports raw reconstruction error and an XGBoost prediction for every
 * window precisely so that lowering the threshold can admit windows the
 * calibrated run never flagged, and the page already knows what the classifier
 * would have said about them.
 */
(function () {
  'use strict';

  // ---------------------------------------------------------------- constants

  var FEED_URL = 'demo_feed.json';
  var TICK_MS = 420;            // one new flow per 420ms (§5.1)
  var CHART_WINDOWS = 60;       // ~60 windows visible (§5.3)
  var Y_MAX = 1.7;              // FIXED domain. Never auto-scale (§8).
  var SNAP_EPS = 0.005;         // snap radius around the calibrated threshold
  var QUEUE_CAP = 8;            // visible cards (§5.5)
  var QUEUE_SCAN = 400;         // how far back a rebuild looks for alerts
  var ANNOUNCE_MS = 5000;       // live-region throttle (§7.4)
  var STREAM_ROWS = 24;         // rows rendered in the viewport
  var ROW_H = 16;
  var WINDOW_ROWS = 20;

  // §5.5 specifies [1,1,1,.85,.7,.55,.4,.25]; the last two render the card text
  // illegible, which collides with §7 (and the failure cards carry real
  // information). Floored at .55 — recency still reads, nothing is unreadable.
  var DEPTH_OPACITY = [1, 1, 1, 0.92, 0.84, 0.76, 0.66, 0.58];

  // ------------------------------------------------------------------- state

  var feed = null;
  var meta = null;
  var windows = [];
  var rows = [];

  var calibrated = 0.4444;
  var threshold = 0.4444;
  var playhead = 0;
  var playing = false;
  var timer = null;
  var dragging = false;
  var reduceMotion = false;

  var queue = [];               // newest first
  var queueSeq = 0;
  var hiddenCount = 0;
  var recent = [];              // last 20 analyzed windows, newest first
  var prevVerdicts = {};        // w -> bool, to detect threshold crossings
  var crossed = {};             // w -> true, for the 160ms crossing animation
  var lastAnnounce = 0;
  var metricsCache = null;      // invalidated on threshold change
  var rafPending = false;

  // Metrics at the shipped threshold, for the delta readout.
  var baseline = null;

  var $ = function (id) { return document.getElementById(id); };

  var el = {};

  // ------------------------------------------------------------------ helpers

  function fmt(n, d) {
    if (!isFinite(n)) return '—';
    return n.toFixed(d === undefined ? 4 : d);
  }

  function comma(n) {
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function clampT(t) {
    if (isNaN(t)) return threshold;
    return Math.min(Y_MAX, Math.max(0, t));
  }

  // A window is anomalous iff its error exceeds the current threshold.
  // This is the only place the verdict is decided.
  function isAnomalous(w) { return w.err > threshold; }

  function classOf(w) {
    // Whatever XGBoost said about this window — already exported for every
    // window, including ones the calibrated threshold never flagged.
    return w.xgb;
  }

  // ------------------------------------------------------------------ metrics

  /* Precision / recall / F1 over every window in the feed at the current
     threshold. Positive class = "is an attack" (truth !== BENIGN). */
  function computeMetrics(t) {
    var tp = 0, fp = 0, fn = 0, tn = 0;
    for (var i = 0; i < windows.length; i++) {
      var w = windows[i];
      var flagged = w.err > t;
      var attack = w.truth !== 'BENIGN';
      if (flagged && attack) tp++;
      else if (flagged && !attack) fp++;
      else if (!flagged && attack) fn++;
      else tn++;
    }
    var alerts = tp + fp;
    var precision = alerts ? tp / alerts : 0;
    var recall = (tp + fn) ? tp / (tp + fn) : 0;
    var f1 = (precision + recall) ? 2 * precision * recall / (precision + recall) : 0;
    return {
      tp: tp, fp: fp, fn: fn, tn: tn,
      alerts: alerts, precision: precision, recall: recall, f1: f1,
      attacks: tp + fn
    };
  }

  function metrics() {
    if (!metricsCache) metricsCache = computeMetrics(threshold);
    return metricsCache;
  }

  /* Sweep for the F1-optimal threshold, so the page can state the gap between
     the shipped threshold and the best one on this feed rather than assert it. */
  function findBestF1() {
    var best = { f1: -1, t: 0 };
    for (var i = 0; i <= 1700; i += 2) {
      var t = i / 1000;
      var m = computeMetrics(t);
      if (m.f1 > best.f1) { best = { f1: m.f1, t: t, m: m }; }
    }
    return best;
  }

  // ------------------------------------------------------------------ chart

  var CH = { w: 1120, h: 320, l: 52, r: 74, t: 16, b: 34 };

  function chartDims() {
    var wpx = el.plot.clientWidth || 1120;
    var h = 320;
    if (wpx < 480) h = 180;
    else if (wpx < 768) h = 220;
    else if (wpx < 1120) h = 280;
    return { w: wpx, h: h };
  }

  function yScale(v, d) {
    var inner = d.h - CH.t - CH.b;
    return CH.t + inner * (1 - Math.min(v, Y_MAX) / Y_MAX);
  }

  function yInvert(py, d) {
    var inner = d.h - CH.t - CH.b;
    return clampT((1 - (py - CH.t) / inner) * Y_MAX);
  }

  function visibleWindows() {
    var end = Math.min(playhead, windows.length - 1);
    var start = Math.max(0, end - CHART_WINDOWS + 1);
    return windows.slice(start, end + 1);
  }

  function svgEl(name, attrs) {
    var n = document.createElementNS('http://www.w3.org/2000/svg', name);
    for (var k in attrs) if (attrs[k] !== null && attrs[k] !== undefined) {
      n.setAttribute(k, attrs[k]);
    }
    return n;
  }

  function trianglePath(cx, cy, size) {
    var h = size * 0.866;
    return 'M' + cx + ' ' + (cy - h * 0.62) +
           'L' + (cx + size / 2) + ' ' + (cy + h * 0.38) +
           'L' + (cx - size / 2) + ' ' + (cy + h * 0.38) + 'Z';
  }

  function diamondPath(cx, cy, size) {
    var h = size / 2;
    return 'M' + cx + ' ' + (cy - h) + 'L' + (cx + h) + ' ' + cy +
           'L' + cx + ' ' + (cy + h) + 'L' + (cx - h) + ' ' + cy + 'Z';
  }

  function drawChart() {
    var d = chartDims();
    var svg = el.chart;
    svg.setAttribute('viewBox', '0 0 ' + d.w + ' ' + d.h);
    svg.setAttribute('width', d.w);
    svg.setAttribute('height', d.h);
    svg.style.height = d.h + 'px';

    // wipe everything except <title>/<desc>
    var kids = Array.prototype.slice.call(svg.childNodes);
    for (var i = 0; i < kids.length; i++) {
      var nn = kids[i].nodeName.toLowerCase();
      if (nn !== 'title' && nn !== 'desc') svg.removeChild(kids[i]);
    }

    var plotW = d.w - CH.l - CH.r;
    var vis = visibleWindows();
    if (!vis.length) return;

    var xAt = function (idx) {
      return CH.l + (vis.length === 1 ? plotW : plotW * idx / (vis.length - 1));
    };

    var g = svgEl('g', {});
    svg.appendChild(g);

    // ---- gridlines + y labels, fixed 0..1.7 domain
    for (var v = 0; v <= Y_MAX + 0.001; v += 0.2) {
      var yy = yScale(v, d);
      g.appendChild(svgEl('line', {
        class: 'grid-line', x1: CH.l, x2: CH.l + plotW, y1: yy, y2: yy
      }));
      var lab = svgEl('text', {
        class: 'axis-label', x: CH.l - 8, y: yy + 3, 'text-anchor': 'end'
      });
      lab.textContent = v.toFixed(1);
      g.appendChild(lab);
    }

    g.appendChild(svgEl('line', {
      class: 'axis-line', x1: CH.l, x2: CH.l, y1: CH.t, y2: d.h - CH.b
    }));
    g.appendChild(svgEl('line', {
      class: 'axis-line', x1: CH.l, x2: CH.l + plotW, y1: d.h - CH.b, y2: d.h - CH.b
    }));

    var at = svgEl('text', {
      class: 'axis-title', x: CH.l, y: d.h - 10
    });
    at.textContent = 'window ' + vis[0].w + ' → ' + vis[vis.length - 1].w +
                     '   ·   reconstruction error (MAE)';
    g.appendChild(at);

    // ---- area fills split at the threshold line
    var ty = yScale(threshold, d);
    var linePts = [];
    for (var j = 0; j < vis.length; j++) linePts.push([xAt(j), yScale(vis[j].err, d)]);

    // below-threshold territory
    var belowClip = 'clip-below';
    var aboveClip = 'clip-above';
    var defs = svgEl('defs', {});
    var cb = svgEl('clipPath', { id: belowClip });
    cb.appendChild(svgEl('rect', {
      x: CH.l, y: ty, width: plotW, height: Math.max(0, (d.h - CH.b) - ty)
    }));
    var ca = svgEl('clipPath', { id: aboveClip });
    ca.appendChild(svgEl('rect', {
      x: CH.l, y: CH.t, width: plotW, height: Math.max(0, ty - CH.t)
    }));
    defs.appendChild(cb); defs.appendChild(ca);
    svg.insertBefore(defs, svg.firstChild);

    var areaD = 'M' + linePts[0][0] + ' ' + (d.h - CH.b);
    for (var k = 0; k < linePts.length; k++) areaD += 'L' + linePts[k][0] + ' ' + linePts[k][1];
    areaD += 'L' + linePts[linePts.length - 1][0] + ' ' + (d.h - CH.b) + 'Z';

    g.appendChild(svgEl('path', { class: 'fill-below', d: areaD, 'clip-path': 'url(#' + belowClip + ')' }));
    g.appendChild(svgEl('path', { class: 'fill-above', d: areaD, 'clip-path': 'url(#' + aboveClip + ')' }));

    // ---- counterfactual band: where the line would have to sit to catch
    // every attack still being missed right now.
    var lowestMissed = Infinity;
    for (var q = 0; q < vis.length; q++) {
      var vw = vis[q];
      if (vw.truth !== 'BENIGN' && vw.err <= threshold) {
        lowestMissed = Math.min(lowestMissed, vw.err);
      }
    }
    if (isFinite(lowestMissed) && lowestMissed < threshold) {
      var by = yScale(lowestMissed, d);
      g.appendChild(svgEl('rect', {
        class: 'counterfactual-band', x: CH.l, y: by,
        width: plotW, height: Math.max(1, ty - by)
      }));
      if (ty - by > 26) {
        var cfm = computeMetrics(Math.max(0, lowestMissed - 0.0005));
        var cfl = svgEl('text', {
          class: 'counterfactual-label', x: CH.l + 6, y: by + 13
        });
        cfl.textContent = 'catching these costs precision → ' + fmt(cfm.precision, 2);
        g.appendChild(cfl);
      }
    }

    // ---- the error line
    var pathD = 'M' + linePts[0][0] + ' ' + linePts[0][1];
    for (var p = 1; p < linePts.length; p++) pathD += 'L' + linePts[p][0] + ' ' + linePts[p][1];
    g.appendChild(svgEl('path', { class: 'err-line', d: pathD }));

    // ---- points: shape encodes state, never hue alone (§2.4)
    for (var n = 0; n < vis.length; n++) {
      var win = vis[n];
      var px = xAt(n), py = linePts[n][1];
      var anom = win.err > threshold;
      var attack = win.truth !== 'BENIGN';
      var node;

      if (anom && win.unknown) {
        node = svgEl('path', { class: 'pt-unknown', d: diamondPath(px, py, 8) });
      } else if (anom) {
        node = svgEl('path', { class: 'pt-anomalous', d: trianglePath(px, py, 7) });
      } else if (attack) {
        // missed detection — ghost marker, hollow dashed circle
        node = svgEl('circle', { class: 'pt-missed', cx: px, cy: py, r: 4 });
      } else {
        node = svgEl('circle', { class: 'pt-benign', cx: px, cy: py, r: 2.5 });
      }
      if (crossed[win.w] && !reduceMotion) {
        node.setAttribute('class', node.getAttribute('class') + ' pt-cross');
        node.setAttribute('transform-origin', px + 'px ' + py + 'px');
      }
      g.appendChild(node);
    }

    // ---- calibrated marker (static)
    var cy2 = yScale(calibrated, d);
    g.appendChild(svgEl('line', {
      class: 'calib-line', x1: CH.l, x2: CH.l + plotW, y1: cy2, y2: cy2
    }));
    // Anchored left and pushed clear of the threshold line: at rest the two
    // lines sit on top of each other, so a shared label position is unreadable.
    var calibBelow = Math.abs(cy2 - ty) < 14 || threshold > calibrated;
    var cl = svgEl('text', {
      class: 'calib-label', x: CH.l + 6,
      y: calibBelow ? cy2 + 13 : cy2 - 6
    });
    cl.textContent = 'calibrated · p95 benign · 0.4444';
    g.appendChild(cl);

    // ---- threshold group: hit area, line, handle
    var tg = svgEl('g', {
      class: 'threshold-grp',
      role: 'slider',
      tabindex: '0',
      'aria-label': 'Anomaly detection threshold',
      'aria-valuemin': '0',
      'aria-valuemax': String(Y_MAX),
      'aria-valuenow': threshold.toFixed(4),
      'aria-valuetext': valueText(),
      'aria-describedby': 'threshold-help'
    });
    tg.appendChild(svgEl('rect', {
      class: 'threshold-band', x: CH.l, y: ty - 12, width: plotW, height: 24
    }));
    tg.appendChild(svgEl('line', {
      class: 'threshold-line', x1: CH.l, x2: CH.l + plotW, y1: ty, y2: ty
    }));
    tg.appendChild(svgEl('line', {
      class: 'threshold-hit', x1: CH.l, x2: CH.l + plotW + CH.r, y1: ty, y2: ty
    }));

    var snapped = Math.abs(threshold - calibrated) <= SNAP_EPS;
    var hx = CH.l + plotW + 6;
    tg.appendChild(svgEl('rect', {
      class: 'focus-ring', x: hx - 3, y: ty - 15, width: 62, height: 30, rx: 999
    }));
    tg.appendChild(svgEl('rect', {
      class: 'threshold-handle', x: hx, y: ty - 12, width: 56, height: 24, rx: 999
    }));
    var ht = svgEl('text', {
      class: 'threshold-handle__text', x: hx + 28, y: ty + 4, 'text-anchor': 'middle'
    });
    ht.textContent = threshold.toFixed(4);
    tg.appendChild(ht);
    if (snapped) {
      var st = svgEl('text', {
        class: 'calib-label', x: hx + 28, y: ty + 22, 'text-anchor': 'middle'
      });
      st.textContent = '= calibrated';
      tg.appendChild(st);
    }
    g.appendChild(tg);
    el.thresholdGrp = tg;

    // 44px touch target: an invisible wide grab strip over the handle
    var grab = svgEl('rect', {
      x: hx - 4, y: ty - 22, width: 64, height: 44,
      fill: 'transparent', cursor: 'ns-resize'
    });
    tg.appendChild(grab);

    svg.querySelector('desc').textContent = chartDescription();
  }

  function chartDescription() {
    var m = metrics();
    var cur = windows[Math.min(playhead, windows.length - 1)];
    return 'Reconstruction error for windows ' +
      Math.max(0, playhead - CHART_WINDOWS + 1) + ' to ' + playhead +
      ', fixed vertical range 0 to 1.7. Threshold ' + threshold.toFixed(4) +
      '. Current window error ' + fmt(cur.err) +
      ', verdict ' + (isAnomalous(cur) ? 'anomalous' : 'benign') +
      '. Across all ' + windows.length + ' windows: precision ' + fmt(m.precision, 3) +
      ', recall ' + fmt(m.recall, 3) + ', F1 ' + fmt(m.f1, 3) +
      ', ' + comma(m.alerts) + ' alerts, ' + comma(m.fn) + ' missed attacks.';
  }

  function valueText() {
    var m = metrics();
    var snapped = Math.abs(threshold - calibrated) <= SNAP_EPS;
    return threshold.toFixed(4) + (snapped ? ', calibrated' : '') +
      '. Precision ' + fmt(m.precision, 3) + ', recall ' + fmt(m.recall, 3) +
      ', F1 ' + fmt(m.f1, 3) + '. ' + comma(m.alerts) + ' alerts, ' +
      comma(m.fn) + ' of ' + comma(m.attacks) + ' attack windows missed.';
  }

  // ------------------------------------------------------------------ stream

  function pad(s, n, right) {
    s = String(s);
    if (s.length >= n) return s.slice(0, n);
    var sp = new Array(n - s.length + 1).join(' ');
    return right ? sp + s : s + sp;
  }

  function fmtFeat(v) {
    var a = Math.abs(v);
    if (a >= 1e6) return (v / 1e6).toFixed(1) + 'M';
    if (a >= 1e4) return Math.round(v).toString();
    if (a >= 100) return v.toFixed(0);
    if (a >= 1) return v.toFixed(1);
    return v.toFixed(2);
  }

  var COL_W = 12;

  function rowText(r) {
    var out = pad('#' + r.i, 7, true);
    for (var i = 0; i < r.f.length; i++) out += pad(fmtFeat(r.f[i]), COL_W, true);
    return out;
  }

  function shortName(name) {
    return name
      .replace('Total Length of Fwd Packets', 'FwdBytes')
      .replace('Total Fwd Packets', 'FwdPkts')
      .replace('Flow Duration', 'Duration')
      .replace('Flow Bytes/s', 'Bytes/s')
      .replace('Flow Packets/s', 'Pkts/s')
      .replace('Fwd Packet Length Max', 'FwdLenMax')
      .replace('Init_Win_bytes_forward', 'InitWinFwd');
  }

  function renderStreamHeader() {
    var s = pad('ROW', 7, true);
    for (var i = 0; i < meta.display_cols.length; i++) {
      s += pad(shortName(meta.display_cols[i]), COL_W, true);
    }
    el.streamCols.textContent = s;
  }

  function renderStream() {
    // The window's newest row is end_row; show a few rows of lookahead context
    // above so the feed reads as continuous rather than truncated.
    var cur = windows[Math.min(playhead, windows.length - 1)];
    var newest = cur.end_row;
    var lead = STREAM_ROWS - WINDOW_ROWS;   // rows below the window (older? no: newer)
    var first = newest - WINDOW_ROWS + 1 - Math.floor(lead / 2);

    var html = '';
    for (var i = 0; i < STREAM_ROWS; i++) {
      var idx = first + i;
      if (idx < 0 || idx >= rows.length) { html += '<div class="log-row"></div>'; continue; }
      var inWin = idx > newest - WINDOW_ROWS && idx <= newest;
      html += '<div class="log-row' + (inWin ? ' log-row--in-window' : '') + '">' +
              rowText(rows[idx]) + '</div>';
    }
    el.rail.innerHTML = html;

    // Bracket sits over the 20 in-window rows.
    var offset = Math.floor(lead / 2) * ROW_H;
    el.bracket.style.top = offset + 'px';

    el.footWindow.textContent = '#' + cur.w;
    el.footRows.textContent = (newest - WINDOW_ROWS + 1) + '–' + newest;
    var abs = meta.absolute_rows[0];
    el.footAbs.textContent = 'absolute CSV rows ' +
      comma(abs + newest - WINDOW_ROWS + 1) + '–' + comma(abs + newest);
  }

  // ------------------------------------------------------------------ verdict

  function renderVerdict() {
    var cur = windows[Math.min(playhead, windows.length - 1)];
    var anom = isAnomalous(cur);
    el.verdict.className = 'verdict ' + (anom ? 'verdict--anomalous' : 'verdict--benign');
    el.verdictGlyph.textContent = anom ? '▲' : '·';
    el.verdictText.textContent = anom ? 'ANOMALOUS' : 'BENIGN';
    var delta = cur.err - threshold;
    el.verdictSub.innerHTML =
      'error <b>' + fmt(cur.err) + '</b> · threshold <b>' + fmt(threshold) +
      '</b> · Δ <b>' + (delta >= 0 ? '+' : '') + fmt(delta) + '</b>' +
      (anom ? ' · sent to XGBoost → <b>' + classOf(cur) + '</b>'
            : ' · not classified');
  }

  // ------------------------------------------------------------------- queue

  function cardKind(w) {
    // What kind of alert is this, given ground truth?
    if (w.unknown) return 'unknown';
    if (w.truth === 'BENIGN') return 'fp';
    if (w.xgb !== w.truth) return 'misclass';
    return 'ok';
  }

  function buildCard(item) {
    var w = item.w;
    var kind = cardKind(w);
    var li = document.createElement('li');
    li.className = 'incident-card' +
      (kind === 'unknown' ? ' incident-card--unknown' :
       kind === 'misclass' ? ' incident-card--misclass' :
       kind === 'fp' ? ' incident-card--fp' : '') +
      (!reduceMotion && item.fresh ? ' incident-card--drop' : '');

    var glyph = kind === 'unknown' ? '?' : kind === 'misclass' ? '≠' : kind === 'fp' ? '✕' : '▲';

    var cls;
    if (kind === 'unknown') {
      cls = '<s>' + w.xgb + '</s> → UNKNOWN (ground truth: ' + w.truth + ')';
    } else if (kind === 'misclass') {
      cls = w.xgb + ' <span style="opacity:.7">≠ ' + w.truth + '</span>';
    } else if (kind === 'fp') {
      cls = w.xgb + ' <span style="opacity:.7">— actually BENIGN</span>';
    } else {
      cls = w.xgb;
    }

    var note = '';
    if (kind === 'unknown') {
      note = '<p class="card-note">Not in the classifier’s label space. A softmax over four ' +
             'classes cannot output “I don’t know” — confidently wrong.</p>';
    } else if (kind === 'misclass') {
      note = '<p class="card-note">Detected, but named wrong. The analyst still gets a real ' +
             'incident, with a misleading title.</p>';
    } else if (kind === 'fp') {
      note = '<p class="card-note">False positive — benign traffic above your threshold. ' +
             'This is the cost of lowering the line.</p>';
    }

    li.innerHTML =
      '<div class="card-top">' +
        '<span class="card-glyph" aria-hidden="true">' + glyph + '</span>' +
        '<span class="card-class">' + cls + '</span>' +
        '<span class="card-err">err ' + fmt(w.err) + '</span>' +
      '</div>' +
      '<p class="card-meta">window #' + w.w + ' · rows ' +
        (w.end_row - WINDOW_ROWS + 1) + '–' + w.end_row +
        ' · Δ +' + fmt(w.err - threshold) + '</p>' +
      note;
    return li;
  }

  function renderQueue() {
    var frag = document.createDocumentFragment();
    var vis = queue.slice(0, QUEUE_CAP);
    for (var i = 0; i < vis.length; i++) {
      var card = buildCard(vis[i]);
      card.style.opacity = DEPTH_OPACITY[i] === undefined ? 0.25 : DEPTH_OPACITY[i];
      vis[i].fresh = false;
      frag.appendChild(card);
    }
    el.queue.innerHTML = '';
    if (!vis.length) {
      var empty = document.createElement('li');
      empty.className = 'queue-empty';
      empty.textContent = 'Nothing flagged in the ' + comma(Math.min(playhead + 1, QUEUE_SCAN)) +
        ' windows before the playhead at threshold ' + fmt(threshold) +
        '. Lower the line, or let the stream run.';
      el.queue.appendChild(empty);
    } else {
      el.queue.appendChild(frag);
    }
    var m = metrics();
    el.queueMore.textContent = hiddenCount > 0
      ? '+ ' + comma(hiddenCount) + ' earlier alert' + (hiddenCount === 1 ? '' : 's') +
        ' this session · ' + comma(m.alerts) + ' windows exceed ' + fmt(threshold) +
        ' across the whole feed'
      : comma(m.alerts) + ' of ' + comma(windows.length) +
        ' windows exceed ' + fmt(threshold) + ' across the whole feed';
  }

  /* Rebuild the queue from the windows already played, at the current
     threshold. Dragging the line down admits windows that were never flagged
     before — they get their exported xgb class, not a placeholder. */
  function rebuildQueue() {
    queue = [];
    var end = Math.min(playhead, windows.length - 1);
    var stop = Math.max(0, end - QUEUE_SCAN + 1);
    for (var i = end; i >= stop && queue.length < QUEUE_CAP; i--) {
      if (windows[i].err > threshold) queue.push({ w: windows[i], fresh: false });
    }
    var total = 0;
    for (var j = 0; j <= end; j++) if (windows[j].err > threshold) total++;
    hiddenCount = Math.max(0, total - queue.length);
  }

  // -------------------------------------------------------------- a11y table

  function renderA11yTable() {
    var tb = el.a11yTable.querySelector('tbody');
    var out = '';
    for (var i = 0; i < recent.length; i++) {
      var w = recent[i];
      var anom = isAnomalous(w);
      out += '<tr><td>#' + w.w + '</td><td>' + fmt(w.err) + '</td><td>' +
             (anom ? 'Anomalous' : 'Benign') + '</td><td>' +
             (anom ? w.xgb : '—') + '</td><td>' + w.truth + '</td></tr>';
    }
    tb.innerHTML = out;
  }

  // ------------------------------------------------------------ failure panel

  function renderFailures() {
    var m = metrics();
    el.failMissed.textContent = comma(m.fn) + ' / ' + comma(m.attacks);
    el.failMissedBody.innerHTML =
      'attack windows in this slice fall <b>below</b> your threshold of ' + fmt(threshold) +
      ' and are never classified. Recall ' + fmt(m.recall, 3) + '. ' +
      'They appear on the chart as hollow dashed circles — visible precisely because ' +
      'they never reach the queue.';
    el.failFp.textContent = comma(m.fp) + ' / ' + comma(m.alerts);
    el.failFpBody.innerHTML =
      'alerts are benign traffic. Precision ' + fmt(m.precision, 3) +
      ' — an analyst working this queue would discard ' +
      (m.alerts ? Math.round(100 * m.fp / m.alerts) : 0) + '% of it.';
  }

  // ------------------------------------------------------------------ metrics UI

  function renderMetrics() {
    var m = metrics();
    el.mPrec.textContent = fmt(m.precision, 3);
    el.mRec.textContent = fmt(m.recall, 3);
    el.mF1.textContent = fmt(m.f1, 3);
    el.mAlerts.textContent = comma(m.alerts);

    if (baseline && Math.abs(threshold - calibrated) > SNAP_EPS) {
      el.mPrecD.textContent = signed(m.precision - baseline.precision, 3);
      el.mRecD.textContent = signed(m.recall - baseline.recall, 3);
      el.mF1D.textContent = signed(m.f1 - baseline.f1, 3);
      el.mAlertsD.textContent = signedInt(m.alerts - baseline.alerts);
    } else {
      el.mPrecD.textContent = el.mRecD.textContent =
        el.mF1D.textContent = el.mAlertsD.textContent = '';
    }
  }

  function signed(v, d) { return (v >= 0 ? '+' : '') + v.toFixed(d); }
  function signedInt(v) { return (v >= 0 ? '+' : '') + comma(v); }

  function renderTradeoff(best) {
    var gap = best.f1 - computeMetrics(calibrated).f1;
    el.tradeoff.innerHTML =
      '<b>The shipped threshold is defensible, not optimal.</b> It was set at the 95th ' +
      'percentile of benign validation error (0.4444), before anyone looked at this slice. ' +
      'Sweeping it here, F1 peaks at <b>' + fmt(best.f1, 3) + '</b> around <b>' +
      fmt(best.t, 3) + '</b> — ' + fmt(gap, 3) + ' above the ' +
      fmt(computeMetrics(calibrated).f1, 3) + ' the calibrated value scores. ' +
      'Tuning the threshold on the data you are being judged on is how you get a number ' +
      'that does not survive deployment, so it was left where the calibration put it.';
  }

  // ------------------------------------------------------------------ render

  function renderAll() {
    drawChart();
    renderVerdict();
    renderQueue();
    renderMetrics();
    renderFailures();
    renderA11yTable();
    if (el.numInput !== document.activeElement) {
      el.numInput.value = threshold.toFixed(4);
    }
  }

  function scheduleRender() {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(function () {
      rafPending = false;
      renderAll();
    });
  }

  function setThreshold(t, opts) {
    opts = opts || {};
    t = clampT(t);
    if (opts.snap !== false && Math.abs(t - calibrated) <= SNAP_EPS) {
      t = meta.calibrated_threshold;
    }
    if (t === threshold) return;

    // Track crossings so points can animate as events, not silent recolors.
    crossed = {};
    var vis = visibleWindows();
    for (var i = 0; i < vis.length; i++) {
      var w = vis[i];
      var was = w.err > threshold, now = w.err > t;
      if (was !== now) crossed[w.w] = true;
    }

    threshold = t;
    metricsCache = null;
    rebuildQueue();
    scheduleRender();
  }

  // ------------------------------------------------------------------ playback

  function advance() {
    if (playhead >= windows.length - 1) { setPlaying(false); return; }
    playhead++;
    var w = windows[playhead];

    recent.unshift(w);
    if (recent.length > 20) recent.pop();

    // Verdict recomputed here too — never read from the feed.
    if (w.err > threshold) {
      queue.unshift({ w: w, fresh: true });
      if (queue.length > QUEUE_CAP) { queue.pop(); hiddenCount++; }
    }

    crossed = {};
    renderStream();
    scheduleRender();
    announce(w);
  }

  function announce(w) {
    var now = Date.now();
    if (now - lastAnnounce < ANNOUNCE_MS) return;
    lastAnnounce = now;
    var anom = w.err > threshold;
    el.live.textContent = 'Window ' + w.w + ' analyzed. Reconstruction error ' +
      fmt(w.err, 2) + '. ' + (anom ? 'Anomalous. Classified ' + w.xgb + '.' : 'Benign.');
  }

  function setPlaying(on) {
    playing = on;
    if (timer) { clearInterval(timer); timer = null; }
    if (on) timer = setInterval(advance, TICK_MS);
    el.btnPlay.setAttribute('aria-pressed', on ? 'false' : 'true');
    el.btnPlayLabel.textContent = on ? 'Pause' : 'Play';
    el.btnPlayGlyph.textContent = on ? '▮▮' : '▸';
  }

  // ------------------------------------------------------------------ drag

  /* Client Y -> SVG user-space Y.
     The svg is `overflow: visible`, so its bounding rect includes overflowing
     content and does NOT align with the viewBox origin. Using it as the origin
     makes the drag drift badly. getScreenCTM() is the exact mapping, so use it
     and keep a rect-based path only as a fallback. */
  function plotPointY(evt) {
    var cy = evt.touches && evt.touches.length ? evt.touches[0].clientY : evt.clientY;
    var svg = el.chart;
    if (svg.getScreenCTM) {
      var ctm = svg.getScreenCTM();
      if (ctm) {
        var pt = svg.createSVGPoint();
        pt.x = evt.touches && evt.touches.length ? evt.touches[0].clientX : evt.clientX;
        pt.y = cy;
        return pt.matrixTransform(ctm.inverse()).y;
      }
    }
    var r = el.plot.getBoundingClientRect();
    var d = chartDims();
    var scale = r.height ? d.h / r.height : 1;
    return (cy - r.top) * scale;
  }

  function onPointerDown(evt) {
    var target = evt.target;
    if (!target.closest || !target.closest('.threshold-grp')) return;
    dragging = true;
    el.plot.classList.add('is-dragging');
    if (el.thresholdGrp) el.thresholdGrp.focus();
    evt.preventDefault();
    // 1:1 with the pointer, no interpolation
    setThreshold(yInvert(plotPointY(evt), chartDims()));
  }

  function onPointerMove(evt) {
    if (!dragging) return;
    evt.preventDefault();
    setThreshold(yInvert(plotPointY(evt), chartDims()));
  }

  function onPointerUp() {
    if (!dragging) return;
    dragging = false;
    el.plot.classList.remove('is-dragging');
    scheduleRender();
  }

  function onKey(evt) {
    var t = threshold, handled = true;
    switch (evt.key) {
      case 'ArrowUp':   case 'Right': case 'ArrowRight':
        t += evt.shiftKey ? 0.05 : 0.005; break;
      case 'ArrowDown': case 'Left':  case 'ArrowLeft':
        t -= evt.shiftKey ? 0.05 : 0.005; break;
      case 'PageUp':   t += 0.1; break;
      case 'PageDown': t -= 0.1; break;
      case 'Home': t = 0; break;
      case 'End':  t = Y_MAX; break;
      case 'Enter':
        t = meta.calibrated_threshold;
        el.live.textContent = 'Snapped to calibrated threshold 0.4444.';
        lastAnnounce = Date.now();
        break;
      default: handled = false;
    }
    if (!handled) return;
    evt.preventDefault();
    setThreshold(t);
    // keep focus on the regenerated node
    requestAnimationFrame(function () {
      if (el.thresholdGrp) el.thresholdGrp.focus();
    });
  }

  // ------------------------------------------------------------------- init

  function bind() {
    el.plot = $('chart-plot');
    el.chart = $('chart');
    el.rail = $('stream-rail');
    el.bracket = $('window-bracket');
    el.streamCols = $('stream-cols');
    el.footWindow = $('foot-window');
    el.footRows = $('foot-rows');
    el.footAbs = $('foot-abs');
    el.verdict = $('verdict');
    el.verdictGlyph = $('verdict-glyph');
    el.verdictText = $('verdict-text');
    el.verdictSub = $('verdict-sub');
    el.queue = $('queue');
    el.queueMore = $('queue-more');
    el.a11yTable = $('a11y-table');
    el.mPrec = $('m-prec'); el.mPrecD = $('m-prec-d');
    el.mRec = $('m-rec');   el.mRecD = $('m-rec-d');
    el.mF1 = $('m-f1');     el.mF1D = $('m-f1-d');
    el.mAlerts = $('m-alerts'); el.mAlertsD = $('m-alerts-d');
    el.failMissed = $('fail-missed'); el.failMissedBody = $('fail-missed-body');
    el.failFp = $('fail-fp'); el.failFpBody = $('fail-fp-body');
    el.tradeoff = $('tradeoff-note');
    el.live = $('live-status');
    el.btnPlay = $('btn-play');
    el.btnPlayLabel = $('btn-play-label');
    el.btnPlayGlyph = $('btn-play-glyph');
    el.numInput = $('threshold-num');
  }

  function wire() {
    el.btnPlay.addEventListener('click', function () { setPlaying(!playing); });
    $('btn-step').addEventListener('click', function () {
      setPlaying(false);
      advance();
    });
    $('btn-calib').addEventListener('click', function () {
      setThreshold(meta.calibrated_threshold);
      el.live.textContent = 'Snapped to calibrated threshold 0.4444.';
      lastAnnounce = Date.now();
    });
    $('btn-theme').addEventListener('click', function () {
      var dark = document.documentElement.getAttribute('data-theme') === 'dark';
      document.documentElement.setAttribute('data-theme', dark ? 'light' : 'dark');
      this.setAttribute('aria-pressed', dark ? 'false' : 'true');
      $('btn-theme-label').textContent = dark ? 'Dark' : 'Light';
      scheduleRender();
    });

    // Accepts a comma decimal separator too — the field is type=text so that
    // its value is always dot-formatted regardless of browser locale.
    el.numInput.addEventListener('input', function () {
      var v = parseFloat(String(this.value).replace(',', '.'));
      if (!isNaN(v)) setThreshold(v, { snap: false });
    });
    el.numInput.addEventListener('blur', function () {
      this.value = threshold.toFixed(4);
    });
    el.numInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { this.blur(); }
    });

    // Pointer/touch drag on the threshold
    el.plot.addEventListener('mousedown', onPointerDown);
    window.addEventListener('mousemove', onPointerMove);
    window.addEventListener('mouseup', onPointerUp);
    el.plot.addEventListener('touchstart', onPointerDown, { passive: false });
    window.addEventListener('touchmove', onPointerMove, { passive: false });
    window.addEventListener('touchend', onPointerUp);

    el.chart.addEventListener('keydown', function (e) {
      if (e.target.closest && e.target.closest('.threshold-grp')) onKey(e);
    });

    // §7.4/4: autoplay stops when focus enters the demo region
    $('demo').addEventListener('focusin', function () {
      if (playing) setPlaying(false);
    });

    var rt;
    window.addEventListener('resize', function () {
      clearTimeout(rt);
      rt = setTimeout(function () { renderStream(); scheduleRender(); }, 120);
    });
  }

  function fillProvenance() {
    $('prov-source').textContent = meta.source;
    $('prov-rows').textContent = comma(meta.absolute_rows[0]) + '–' +
                                 comma(meta.absolute_rows[1]) + ' (' + comma(rows.length) + ' flows)';
    $('prov-windows').textContent = comma(windows.length);
    $('prov-shape').textContent = meta.window_size + ' × ' + meta.n_features;
    $('prov-note').textContent = meta.note;
    $('bracket-label').textContent = 'WINDOW t−' + (meta.window_size - 1) + ' → t · ' +
                                     meta.window_size + ' × ' + meta.n_features;
  }

  function start(data) {
    feed = data;
    meta = data.meta;
    windows = data.windows;
    rows = data.rows;
    calibrated = meta.calibrated_threshold;
    threshold = meta.calibrated_threshold;
    playhead = Math.min(meta.playhead, windows.length - 1);

    reduceMotion = window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    bind();
    fillProvenance();
    renderStreamHeader();

    baseline = computeMetrics(calibrated);
    renderTradeoff(findBestF1());

    // seed the recent-window table with real history
    for (var i = Math.max(0, playhead - 19); i <= playhead; i++) recent.unshift(windows[i]);
    rebuildQueue();

    renderStream();
    renderAll();
    wire();

    if (reduceMotion) {
      // Behavioral change, not just shorter durations (§6.3): start paused
      // and let the viewer step.
      setPlaying(false);
      $('controls-note').textContent =
        'Reduced motion is on, so the stream starts paused. Use “Step one window” to advance.';
    } else {
      setPlaying(true);
    }
  }

  function fail(err) {
    var d = document.getElementById('demo');
    var p = document.createElement('div');
    p.className = 'noscript-note';
    p.innerHTML = '<strong>Could not load the demo feed.</strong> ' +
      'Some browsers block <span class="mono">fetch()</span> of local files over ' +
      '<span class="mono">file://</span>. Serve this directory over HTTP instead — ' +
      'e.g. <span class="mono">python3 -m http.server</span> from the repository root — ' +
      'and reload. The measured results are stated in full further down the page. ' +
      '<span class="mono">(' + (err && err.message ? err.message : err) + ')</span>';
    d.insertBefore(p, d.firstChild);
  }

  // file:// blocks fetch() of local JSON in Chrome. Try fetch, fall back to
  // XHR, which some browsers still allow for same-directory file reads.
  function load() {
    fetch(FEED_URL).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(start).catch(function (e) {
      try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', FEED_URL, true);
        xhr.onload = function () {
          try { start(JSON.parse(xhr.responseText)); }
          catch (e2) { fail(e2); }
        };
        xhr.onerror = function () { fail(e); };
        xhr.send();
      } catch (e3) { fail(e); }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', load);
  } else {
    load();
  }
})();
