# design.md — Browser Demo Page

Visual specification for the interactive browser demo of the **Log Anomaly Detector** (LSTM Autoencoder + XGBoost, CIC-IDS2017). Target context: embedded in a developer portfolio. Audience: technical recruiters, engineers, security people.

---

## 0. Research provenance

Be clear about what is observed vs. extrapolated. Nothing below is invented.

### Sites successfully analyzed (raw CSS/HTML retrieved and parsed)

| Site | What was retrieved | Usefulness |
|---|---|---|
| `styles.refero.design` | 2 Next.js CSS bundles (110 KB), full token set | **High** — complete, coherent design system |
| `design-md.hyperbrowser.ai` | Next.js CSS bundle (25 KB), Tailwind v4 theme layer | **High** — mono-first type system |
| `open-design.ai` | Inline `<style>` block from 341 KB HTML | **Medium** — full but idiosyncratic (neon-lime + hard offset shadows) |
| `aura.build` | CSS bundle (536 KB) | **Low** — see note |
| `neuform.ai` | CSS bundle (695 KB) | **Low** — see note |

**Note on aura.build / neuform.ai:** both are AI *template galleries*. Their bundles contain hundreds of mutually unrelated fonts (Anton, Chewy, Bodoni Moda, DotGothic16, Bebas Neue…) and full Tailwind palettes. They have no single house style to copy. Only their **motion curves** were harvested, which are consistent across templates and genuinely useful.

### Sites that could NOT be reached

| Site | Failure |
|---|---|
| `designmd.me` | HTTP 429 — Vercel Security Checkpoint bot wall |
| `designmd.supply` | HTTP 429 — Vercel Security Checkpoint bot wall |
| `typeui.sh` | HTTP 429 — Vercel Security Checkpoint bot wall |
| `getdesign.md` | HTML served (193 KB) but all styling is client-rendered; no CSS bundle recoverable |

Four of nine references yielded no design data. **No values below are attributed to these four.** To fill the gap, one web search was run on 2026 developer-tool landing page conventions; findings from it are labeled **[search]** and are corroborative only — every hard number comes from a bundle that was actually parsed, or is an explicit extrapolation labeled as such.

### Project data sources
- `README.md` — architecture, methodology, results table.
- `../log_anomaly_detector.worktrees/port-notebook-to-training-script/artifacts/metrics.json` — **real values, use these verbatim in the UI.**

Key numbers the page must display honestly:

```
threshold            0.44443160079796684   → display as 0.4444
window_size          20
features             36
pipeline BENIGN            P 0.724  R 0.999  F1 0.839   n 25,466
pipeline DoS Hulk          P 0.998  R 0.424  F1 0.596   n 14,887
pipeline DoS Slowhttptest  P 0.998  R 0.898  F1 0.945   n  5,499
pipeline DoS slowloris     P 0.994  R 0.855  F1 0.919   n  4,129
pipeline accuracy          0.805
XGBoost alone (isolated)   accuracy 0.996
LSTM binary alone          accuracy 0.696
```

That last pair is the story of the whole project: the classifier is near-perfect, the detector is the bottleneck, and the pipeline lands at 0.805. The design should make this legible, not bury it.

---

## 1. Design principles

**P1 — Instrument, not dashboard.**
This reads as a measuring device: a scope, a seismograph, a lab readout. Not a "cyber command center." Refero's system is the model here — its entire chart ramp (`--chart-1` `#d2d4d8` → `--chart-5` `#24262c`) is **pure grayscale**. Color is spent only where it carries meaning. Everything structural is neutral; hue is reserved for verdicts and failures.

**P2 — The threshold is the protagonist.**
Component 3 is the page. Everything above it (stream, window) is input to it; everything below (verdict, queue) is output from it. Give it the most vertical space, the strongest contrast, and the only draggable control. A visitor who touches exactly one thing should touch the threshold line.

**P3 — Failure is a first-class visual state.**
DoS Hulk recall is 0.424. Unknown attacks (DoS GoldenEye, Heartbleed) get misnamed because the classifier has no label for them. These are not error states to gray out — they are the most interesting thing on the page and they need dedicated, legible, *designed* treatment. A recruiter should be able to point at the screen and say "that's the part that doesn't work, and they knew it."

**P4 — Monospace is structure, not costume.**
Log lines, feature names, metrics, and the threshold value are monospace because they are tabular data that must align. Prose and headings are not. `design-md.hyperbrowser.ai` sets `--default-font-family: var(--font-jetbrains-mono)` globally — an all-mono page. Do not copy that; it turns mono into decoration, and decoration is exactly what "fake hacker dashboard" is made of.

**P5 — Motion conveys pipeline flow, and nothing else.**
Animate only what physically moves through the system: lines scrolling in, the window bracket sliding, the chart advancing, a card dropping into the queue. No ambient glows, no idle pulses, no scanlines, no typewriter effects.

---

## 2. Color system

### 2.1 Rationale and colorblind constraint

SOC tooling defaults to red-vs-green. Roughly 8% of men have some form of red-green CVD; deuteranopia collapses those two hues into near-identical olive-browns. **Semantic state must never be encoded by hue alone.**

The palette resolves this with three simultaneous encodings on every state:

1. **Hue** — for the majority of viewers.
2. **Luminance** — benign sits low-contrast/quiet; anomalous sits high-contrast/loud. Distinguishable in grayscale.
3. **Shape/glyph** — every state carries a distinct non-color marker (`·` `▲` `?` `✕`), and every chart point carries a distinct marker shape.

The hue axis chosen is **blue↔amber↔magenta**, not red↔green. This survives deuteranopia and protanopia (both preserve the blue-yellow axis) and remains distinguishable under tritanopia via the luminance and shape channels. Amber for anomalous rather than red is also honest: this system produces *alerts for triage*, not confirmed breaches.

Structural grays are lifted from Refero's `--gray-solid-*` ramp, which is a subtly blue-cast neutral (`#f7f8fb`, `#eef0f6`, `#dddfea` …) rather than a dead gray. That slight cast is what makes the neutrals feel designed rather than default.

### 2.2 Tokens

```css
:root {
  /* ---- Structural neutrals (light) — Refero --gray-solid-* ramp ---- */
  --bg:              #ffffff;
  --bg-subtle:       #f7f8fb;   /* section grounds, stream box */
  --bg-inset:        #eef0f6;   /* window bracket fill, code wells */
  --border:          #dfe1e7;   /* Refero --border */
  --border-strong:   #c2c6d7;   /* Refero --gray-solid-400 */
  --fg:              #0d0f15;   /* Refero --foreground */
  --fg-muted:        #6f7179;   /* Refero --muted-foreground */
  --fg-subtle:       #979fb9;   /* de-emphasised log lines */

  /* ---- Semantic: detector states ---- */
  /* BENIGN — low-chroma slate blue, deliberately quiet */
  --benign:          #5a7ea8;
  --benign-bg:       #eef3f8;
  --benign-border:   #b9cede;
  --benign-fg:       #2c4a68;

  /* ANOMALOUS — amber, high luminance contrast against benign */
  --anomalous:       #b75000;   /* Refero --color-amber-700 */
  --anomalous-bg:    #fffbeb;   /* Refero --color-amber-50 */
  --anomalous-border:#fcbb00;   /* Refero --color-amber-400 */
  --anomalous-fg:    #7b3306;   /* Refero --color-amber-900 */

  /* UNKNOWN ATTACK — detected, but classifier has no label for it.
     Magenta: off both the blue and amber axes, unmistakably "other". */
  --unknown:         #a21b7a;
  --unknown-bg:      #fdf2f9;
  --unknown-border:  #e59ccb;
  --unknown-fg:      #6d0f51;

  /* MISSED DETECTION — the attack the system never saw.
     Deliberately desaturated: absence, not alarm. Rendered as a ghost. */
  --missed:          #8a8f9c;
  --missed-bg:       #f4f4f6;
  --missed-border:   #b9bcc6;
  --missed-fg:       #4b4f5a;

  /* MISCLASSIFIED — detected, wrong label assigned. */
  --misclass:        #7a5cc4;
  --misclass-bg:     #f4f1fd;
  --misclass-border: #c3b3ea;
  --misclass-fg:     #4a3487;

  /* THRESHOLD — the draggable line. Must not collide with any state hue. */
  --threshold:       #0d0f15;   /* near-black: maximum authority in light */
  --threshold-grab:  #155dfc;   /* Refero --color-blue-600, active drag */
  --threshold-track: #dfe1e7;

  /* ---- Chart neutrals — Refero grayscale ramp, verbatim ---- */
  --chart-line:      #6f7179;
  --chart-grid:      #eef0f6;
  --chart-axis:      #c2c6d7;
  --chart-fill-below:rgba(90,126,168,0.10);
  --chart-fill-above:rgba(183,80,0,0.10);

  /* ---- Elevation — Refero --shadow-* verbatim ---- */
  --shadow-xs: 0 1px 3px #0c297e14, 0 0 0 .5px #0c297e08;
  --shadow-sm: 0 3px 8px #0c297e14, 0 0 0 .5px #0c297e08;
  --shadow-md: 0 6px 12px #0c297e17, 0 0 0 .5px #0c297e08;
  --shadow-lg: 0 8px 20px #0c297e17, 0 0 0 .5px #0c297e08;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) { /* see §2.3 */ }
}
```

Dark values (apply to both the `prefers-color-scheme` block and `[data-theme="dark"]`):

```css
  /* ---- Structural neutrals (dark) — Refero dark --gray-solid-* ramp ---- */
  --bg:              #101216;
  --bg-subtle:       #181a20;
  --bg-inset:        #1f2026;
  --border:          #282c36;
  --border-strong:   #353c4d;
  --fg:              #ffffff;
  --fg-muted:        #979fb9;
  --fg-subtle:       #6d768e;

  --benign:          #7ea8d4;
  --benign-bg:       #14202e;
  --benign-border:   #2c4a68;
  --benign-fg:       #a8c8e4;

  --anomalous:       #fcbb00;   /* Refero --color-amber-400 */
  --anomalous-bg:    #2a1c02;
  --anomalous-border:#7b3306;
  --anomalous-fg:    #fee685;   /* Refero --color-amber-200 */

  --unknown:         #f08fd0;
  --unknown-bg:      #2a1023;
  --unknown-border:  #6d0f51;
  --unknown-fg:      #f8c4e5;

  --missed:          #6d768e;
  --missed-bg:       #1a1c22;
  --missed-border:   #353c4d;
  --missed-fg:       #9fa5ba;

  --misclass:        #b49ef0;
  --misclass-bg:     #1e1830;
  --misclass-border: #4a3487;
  --misclass-fg:     #d6c9f8;

  --threshold:       #ffffff;
  --threshold-grab:  #3080ff;   /* Refero --color-blue-500 */
  --threshold-track: #282c36;

  --chart-line:      #979fb9;
  --chart-grid:      #1f2026;
  --chart-axis:      #353c4d;
  --chart-fill-below:rgba(126,168,212,0.12);
  --chart-fill-above:rgba(252,187,0,0.12);

  /* Shadows read poorly on dark. Swap to a hairline ring. */
  --shadow-xs: 0 0 0 1px #ffffff0a;
  --shadow-sm: 0 1px 2px #00000066, 0 0 0 1px #ffffff0a;
  --shadow-md: 0 4px 12px #00000080, 0 0 0 1px #ffffff0f;
  --shadow-lg: 0 8px 24px #00000099, 0 0 0 1px #ffffff0f;
```

### 2.3 Theme wiring

Refero's bundle contains exactly three `prefers-color-scheme: dark` blocks and no `.dark` class — it is a pure system-preference site. For a portfolio embed, support both system preference **and** an explicit toggle:

```css
:root { /* full light palette — every token defined here */ }
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) { /* dark overrides */ }
}
:root[data-theme="dark"] { /* dark overrides, repeated */ }
```

Never let a token exist only inside a media query — a light-forced page would then inherit undefined values.

### 2.4 Non-color redundancy (mandatory)

| State | Hue | Glyph | Chart marker | Border |
|---|---|---|---|---|
| Benign | slate blue | `·` | small filled dot, r=2.5 | none |
| Anomalous | amber | `▲` | filled triangle, 7px | 1px solid |
| Unknown attack | magenta | `?` | hollow diamond, 8px | 1px **dashed** |
| Misclassified | violet | `≠` | filled square + slash | 1px solid |
| Missed detection | gray | `✕` | hollow circle, r=4, dashed stroke | 1px **dotted** |

Verify by rendering the page through a grayscale filter (`filter: grayscale(1)`) — every state must still be identifiable. This is a hard acceptance criterion, not a nice-to-have.

---

## 3. Typography

### 3.1 Stacks

```css
--font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI",
             system-ui, sans-serif;
--font-mono: "JetBrains Mono", ui-monospace, "SF Mono", SFMono-Regular,
             Menlo, Monaco, Consolas, "Liberation Mono", monospace;
```

**JetBrains Mono** is the observed choice on both coherent references: `styles.refero.design` (`--font-jetbrains-mono`) and `design-md.hyperbrowser.ai` (`--font-jetbrains-mono`, self-hosted via `next/font`). Corroborated by **[search]** as the 2026 developer-tool default. It matters here for a specific technical reason: it has a tall x-height and unambiguous `0/O`, `1/l/I`, `5/S` — necessary when 20 rows of near-identical numeric flow features are stacked and the reader must spot the outlier.

Refero pairs mono with **Neue Montreal** (sans) and **Kalice** (serif). Neue Montreal is licensed; Inter is the free equivalent and is what `neuform.ai` falls back to across nearly every template. If you want the editorial-heading look **[search]** describes, use one serif line for the page title only — not throughout.

The mono fallback chain is taken verbatim from Hyperbrowser's `--font-mono`. Keep it: if the webfont fails, log lines must still be monospaced or the sliding-window alignment collapses.

### 3.2 Scale

Base 16px. Refero and Hyperbrowser both use the Tailwind ramp; these are Hyperbrowser's `--text-*` tokens, unrounded.

| Token | Size | Line-height | Weight | Tracking | Use |
|---|---|---|---|---|---|
| `--text-xs` | 12px / 0.75rem | 16px | 400–500 | `0` | log lines, axis labels, metric captions |
| `--text-sm` | 14px / 0.875rem | 20px | 400–500 | `0` | body prose, card metadata |
| `--text-base` | 16px / 1rem | 24px | 400 | `0` | default body |
| `--text-lg` | 18px / 1.125rem | 28px | 500 | `-0.01em` | section intros |
| `--text-xl` | 20px / 1.25rem | 28px | 600 | `-0.02em` | section headings |
| `--text-2xl` | 24px / 1.5rem | 32px | 600 | `-0.02em` | component titles |
| `--text-3xl` | 30px / 1.875rem | 36px | 600 | `-0.025em` | page subtitle |
| `--text-5xl` | 48px / 3rem | 48px | 700 | `-0.035em` | page title |

Tracking values are Refero's observed set: `-0.02em`, `-0.025em`, `-0.035em` on display sizes, `0.06em` on small caps labels. **Mono never gets negative tracking** — it destroys the grid alignment that is the whole point of using mono.

### 3.3 Specific assignments

```css
.log-line      { font: 400 12px/1.5 var(--font-mono); letter-spacing: 0; }
.metric-value  { font: 500 var(--text-sm) var(--font-mono);
                 font-variant-numeric: tabular-nums; }
.threshold-val { font: 600 14px var(--font-mono);
                 font-variant-numeric: tabular-nums; }
.eyebrow       { font: 500 11px var(--font-mono);
                 letter-spacing: 0.06em; text-transform: uppercase;
                 color: var(--fg-muted); }
.verdict       { font: 600 var(--text-xl) var(--font-mono);
                 letter-spacing: 0.02em; }
```

`font-variant-numeric: tabular-nums` on **every** live-updating number. Without it, precision/recall readouts jitter horizontally as digits change during a threshold drag, and the drag feels broken.

`.eyebrow` mirrors Hyperbrowser's use of `--tracking-widest` (`0.1em`) on small uppercase mono labels; 0.06em is used here because 0.1em on 11px mono is too airy at this density. **This is an extrapolation, not an observation.**

---

## 4. Spacing and layout

### 4.1 Scale

Base unit **4px** (Hyperbrowser's `--spacing: .25rem`; Refero uses the same Tailwind base).

```css
--sp-1: 4px;    --sp-2: 8px;    --sp-3: 12px;   --sp-4: 16px;
--sp-5: 20px;   --sp-6: 24px;   --sp-8: 32px;   --sp-10: 40px;
--sp-12: 48px;  --sp-16: 64px;  --sp-20: 80px;  --sp-24: 96px;
```

Component-internal padding: `--sp-4` (16px) mobile, `--sp-6` (24px) desktop.
Between the 6 components: **`--sp-16` (64px)** desktop, **`--sp-10` (40px)** mobile.
Between major narrative sections (intro / demo / results): **`--sp-24` (96px)**.

### 4.2 Widths

Refero's observed max-widths: `760px`, `820px`, `80rem` (1280px), `96rem` (1536px). Hyperbrowser exposes `--container-3xl: 48rem` (768px) and `--container-7xl: 80rem` (1280px).

```css
--w-prose:  760px;   /* explanatory text — Refero's observed prose width */
--w-demo:   1120px;  /* the 6 interactive components */
--w-page:   1280px;  /* outer bound, Refero --container-7xl */
--gutter:   16px;    /* mobile */
--gutter-d: 32px;    /* ≥768px */
```

Prose narrower than the demo is deliberate: it signals "read this" vs. "watch this."

### 4.3 Vertical stack and grid

Single column throughout; this is a linear pipeline and any multi-column arrangement breaks the causal reading order.

```
┌─ header: title, one-paragraph summary ──────────── 760px
│
├─ 1. LOG STREAM         ─┐
├─ 2. SLIDING WINDOW      │  visually FUSED — one bordered
│                        ─┘  panel, see §5.2
│         ↓ (connector)
├─ 3. RECONSTRUCTION ERROR CHART + THRESHOLD ───── 1120px
│         ↓
├─ 4. VERDICT
│         ↓
├─ 5. INCIDENT TRIAGE QUEUE
│
├─ 6. HONEST FAILURE PANEL  (metrics + limitations)
└─ footer
```

Components 1 and 2 are **one panel**, not two. The window is a bracket *inside* the stream; separating them into sibling cards destroys the "these 20 rows are one unit" reading that P2 depends on.

Between 2→3, 3→4, 4→5 draw a **connector**: a 1px vertical rule, 32px tall, `--border-strong`, centered, with a 5px downward chevron at its base. This is the cheapest possible way to say "pipeline" without any hacker iconography.

### 4.4 Responsive

| Breakpoint | Behavior |
|---|---|
| `< 480px` | Log stream shows a **truncated projection** — timestamp + 3 features + label, not all 36. Horizontal scroll on the row container with `overflow-x: auto`; page body must never scroll horizontally. Chart height 180px. Queue cards full-width, stacked. |
| `480–767px` | Log lines 11px mono. Chart 220px. Threshold handle enlarged to 44px hit area. |
| `768–1119px` | Full log projection. Chart 280px. Queue cards 2-up grid. |
| `≥ 1120px` | Full layout. Chart 320px. Queue 3-up grid or single column with detail rail. |

At `< 768px` the threshold **must** remain draggable — do not degrade it to a number input. Touch target minimum 44×44px per WCAG 2.5.5. Provide a paired numeric input alongside for precision at all widths.

---

## 5. Component specifications

### 5.1 Log stream box

**Structure**

```html
<section class="stream-panel" aria-labelledby="stream-h">
  <h3 id="stream-h" class="eyebrow">Network flow stream · CIC-IDS2017</h3>
  <div class="stream-viewport" aria-hidden="true">
    <div class="stream-rail"><!-- rows --></div>
    <div class="window-bracket"><!-- §5.2 --></div>
  </div>
  <p class="sr-only" role="status" aria-live="polite"><!-- §7.4 --></p>
</section>
```

**Styling**

```css
.stream-panel {
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: var(--sp-4);
}
.stream-viewport {
  position: relative;
  height: 384px;              /* 24 rows × 16px */
  overflow: hidden;
  background: var(--bg);
  border-radius: 8px;
  /* fade top and bottom — the feed continues beyond the frame */
  -webkit-mask-image: linear-gradient(to bottom,
    transparent 0, #000 48px, #000 calc(100% - 48px), transparent 100%);
          mask-image: linear-gradient(to bottom,
    transparent 0, #000 48px, #000 calc(100% - 48px), transparent 100%);
}
.log-row {
  height: 16px; line-height: 16px;
  font: 400 12px var(--font-mono);
  font-variant-numeric: tabular-nums;
  color: var(--fg-subtle);
  padding-inline: var(--sp-3);
  white-space: pre;
}
.log-row--in-window { color: var(--fg); }
```

Radius `12px` outer / `8px` inner: `open-design.ai`'s two most-used non-pill radii are `8px` (15 uses) and `16px` (7 uses); Refero's `--radius: .5rem` (8px) with `--radius-xl` at 12px. 12/8 sits in the observed range and gives correct nesting (inner radius = outer − padding).

The **mask-image fade** is the single most important detail here. A hard-edged scrolling box reads as a fake terminal; a feed that dissolves at its boundaries reads as a window onto something continuous. This is an extrapolation — no reference site had a log feed — but it follows directly from P1.

**Row content.** Show a *projection* of the 36 features, not all of them. Suggested: `seq · Flow Duration · Fwd Packets/s · Bwd Packets/s · SYN Flag Count · Init_Win_bytes_forward`. Right-align numerics. Real feature names from `metrics.json` — never invented ones.

**Do not** color-code rows by their ground-truth label. The detector does not know the label. Coloring the stream by truth leaks the answer and destroys the demo's honesty. Ground truth appears only in the failure panel (§5.6), after the verdict.

**Speed.** One new row every **420ms**. Fast enough to feel live, slow enough that the eye can track a single line entering the window. Provide a pause/play control — required, see §7.4.

### 5.2 Sliding window frame

The bracket is an absolutely-positioned overlay on `.stream-viewport`, covering the last 20 rows (320px).

```css
.window-bracket {
  position: absolute; left: 0; right: 0;
  height: 320px;                       /* 20 rows × 16px */
  border: 1.5px solid var(--border-strong);
  border-radius: 6px;
  background: var(--bg-inset);
  mix-blend-mode: multiply;            /* light */
  pointer-events: none;
  transition: transform 420ms cubic-bezier(.22, 1, .36, 1);
}
@media (prefers-color-scheme: dark) {
  .window-bracket { mix-blend-mode: screen; }
}
.window-bracket::before {              /* corner ticks, top-left + top-right */
  /* 8px L-shaped marks in --fg-muted at each of the 4 corners */
}
.window-bracket__label {
  position: absolute; top: -9px; left: var(--sp-3);
  padding: 0 var(--sp-2);
  background: var(--bg);
  font: 500 10px var(--font-mono);
  letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--fg-muted);
}
```

Label text: `WINDOW t−19 → t · 20 × 36`. Naming the tensor shape does more to communicate "this is the LSTM's input" than any amount of glow.

**Four corner ticks** rather than a solid heavy border. A solid 3px box reads as a selection rectangle; corner brackets read as a viewfinder/measurement frame — which is precisely what it is. This is an extrapolation from P1.

**The bracket must be a distinct visual object, not just a background tint.** It has to be obvious at a glance that 20 specific rows are being taken as one unit. Border + inset fill + corner ticks + label, all four.

**Motion.** The bracket does not jump. When a row enters, the rail translates up 16px and the bracket translates with it, both on the same 420ms curve, so the bracket appears to hold still while content flows through it. That inversion — content moving, frame stationary — is the reading you want.

### 5.3 Reconstruction error chart with draggable threshold

**This is the centerpiece. Budget the most implementation effort here.**

**Layout**

```css
.chart-panel {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: var(--sp-6) var(--sp-6) var(--sp-4);
  box-shadow: var(--shadow-sm);
}
.chart-plot { height: 320px; }         /* desktop; see §4.4 */
```

**Y axis.** Reconstruction error, `0` to `1.0`. Fixed domain — do **not** auto-scale. An auto-scaling axis makes the threshold line appear to move when it hasn't, which destroys the entire interaction. Gridlines at 0.2 intervals in `--chart-grid`, 1px. Label the axis `reconstruction error (MAE)`.

**X axis.** Window index, scrolling. Show ~60 windows. Points enter right, exit left.

**The error line.** 1.5px stroke, `--chart-line`. Neutral gray — the *line* is not a verdict, the points are.

**Area fill.** Below the threshold: `--chart-fill-below`. Above: `--chart-fill-above`. Fills recompute live as the threshold moves. This is what makes the crossing feel physical — the colored territory itself changes shape under the drag.

**Points.**

```css
.pt-benign    { fill: var(--benign);    r: 2.5; }
.pt-anomalous { fill: var(--anomalous); /* triangle path, 7px */ }
```

A point that crosses the line on a drag animates: `r` 2.5 → 4 → 3, and shape morphs dot→triangle, over 160ms. Crossings should be perceptible as *events*, not silent recolors.

**The threshold line.**

```css
.threshold-line {
  stroke: var(--threshold);
  stroke-width: 2;
  stroke-dasharray: 6 3;
  cursor: ns-resize;
}
.threshold-hit { stroke-width: 24; stroke: transparent; cursor: ns-resize; }
.threshold-handle {
  /* right-anchored pill, 56×24, radius 999px  (open-design.ai's most
     common radius by a wide margin: 27 uses of 999px) */
  fill: var(--bg); stroke: var(--threshold); stroke-width: 1.5;
}
.threshold-handle__text {
  font: 600 12px var(--font-mono);
  font-variant-numeric: tabular-nums;
  fill: var(--fg);
}
.threshold-line--dragging { stroke: var(--threshold-grab); stroke-dasharray: none; }
```

Dashed at rest, **solid while dragging** — the line "engages." Handle shows the live value to 4 decimals.

**Calibrated marker.** A second, static, 1px `--fg-muted` line at exactly `0.4444`, labeled `calibrated · p95 benign`. When the user's threshold is within ±0.005 of it, the draggable handle **snaps** and the label reads `= calibrated (0.4444)`. This is the single most valuable interaction on the page: it lets a visitor discover for themselves that the shipped threshold is a deliberate choice on a precision/recall curve, not an arbitrary constant.

**Live metrics strip.** Directly beneath the plot, a mono row that recomputes on every drag frame:

```
precision 0.998   recall 0.424   F1 0.596   flagged 6,318 / 14,887
```

Tabular nums, `--text-sm`. When the threshold moves away from calibrated, show the delta from the shipped numbers in `--fg-muted`. Debounce the *recompute* to animation frames; never debounce the *handle position* — the handle must track the pointer at 1:1 with zero lag or the drag feels broken.

**States:** rest · hover (hit area highlights, `--threshold-track` 24px band at 8% opacity) · dragging · focused (§7.3) · snapped.

### 5.4 Verdict indicator

Sits between chart and queue, on the connector spine.

```css
.verdict {
  display: inline-flex; align-items: center; gap: var(--sp-2);
  padding: var(--sp-2) var(--sp-4);
  border-radius: 999px;
  border: 1px solid;
  font: 600 var(--text-xl) var(--font-mono);
  letter-spacing: 0.02em;
  transition: background 180ms cubic-bezier(.4,0,.2,1),
              color      180ms cubic-bezier(.4,0,.2,1),
              border-color 180ms cubic-bezier(.4,0,.2,1);
}
.verdict--benign {
  background: var(--benign-bg); color: var(--benign-fg);
  border-color: var(--benign-border);
}
.verdict--anomalous {
  background: var(--anomalous-bg); color: var(--anomalous-fg);
  border-color: var(--anomalous-border);
}
```

Glyph prefix `·` / `▲` per §2.4 — mandatory, this is the redundancy channel.

Below the pill, a mono sub-line: `error 0.5127 · threshold 0.4444 · Δ +0.0683`. Showing the margin is what turns a binary badge into a readout.

**Do not** flash, shake, or pulse the anomalous state. Transition the colors over 180ms and stop. A calm alert is more credible than an urgent one — and per **[search]**, 2026 conventions have moved decisively toward "feel trustworthy" over "look impressive."

### 5.5 Incident triage queue

```css
.queue { display: flex; flex-direction: column; gap: var(--sp-3); }
.incident-card {
  background: var(--bg);
  border: 1px solid var(--border);
  border-left: 3px solid var(--anomalous);   /* class-coded edge */
  border-radius: 10px;
  padding: var(--sp-4);
  box-shadow: var(--shadow-xs);
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: var(--sp-3);
  align-items: center;
}
.incident-card:hover { box-shadow: var(--shadow-sm); }
```

The left edge stripe is the class channel: `--anomalous` for a correct named class, `--unknown` (dashed) for an unknown attack, `--misclass` for a wrong label.

**Card content**

```
▲  DoS Hulk                          err 0.5127
   window #1284 · 14:22:07 · conf 0.94        ⌄
```

Row 1: glyph, attack class (mono, 600), reconstruction error right-aligned.
Row 2: window index, timestamp, XGBoost confidence, expand affordance.
Expanded: the top 5 contributing features by per-feature reconstruction error, as a mini horizontal bar list with real feature names from `metrics.json`.

**Newest on top.** New card inserts at index 0; existing cards translate down. Cap the visible stack at 8 with a `+ N earlier` affordance — an unbounded growing list will wreck scroll position on a portfolio page.

**Depth.** Cards 4+ get progressively reduced opacity (`1.0, 1.0, 1.0, 0.85, 0.7, 0.55, 0.4, 0.25`). Do **not** use scale transforms or 3D perspective for the stack effect — it reads as a gimmick and breaks text rendering. Opacity alone conveys recency.

### 5.6 Honest failure indicators

**The most important section on the page for the portfolio's purpose. Design it properly; do not treat it as an appendix.**

Three distinct failure modes, three distinct treatments:

**(a) Missed detection — DoS Hulk below threshold.**
These never enter the queue, so they must be visible *in the chart*. Render ground-truth-attack windows that fall below the threshold as **ghost markers**: hollow circle, `r=4`, 1px **dashed** `--missed` stroke, no fill, sitting on the error line below the threshold.

```css
.pt-missed { fill: none; stroke: var(--missed); stroke-width: 1;
             stroke-dasharray: 2 2; }
```

Beneath the chart, a persistent counter:

```
✕  MISSED  ·  8,562 of 14,887 DoS Hulk flows fall below threshold  ·  recall 0.424
```

Styled with `--missed-bg` / `--missed-border` (dotted 1px) / `--missed-fg`. Add one sentence of plain prose: *"DoS Hulk generates syntactically valid HTTP requests. Their flow features overlap with benign traffic, so the autoencoder reconstructs them well and the error stays below threshold."* This is the sentence that turns a bad number into evidence of understanding.

Optionally, a **counterfactual ribbon** on the chart: a faint `--missed` horizontal band showing where the threshold would need to sit to catch them, annotated `catching these costs BENIGN precision → 0.41`. That single annotation demonstrates the precision/recall tradeoff better than any paragraph.

**(b) Unknown attack — GoldenEye, Heartbleed.**
Detected (above threshold) but the classifier has only 3 attack labels + BENIGN, so it *will* emit a confidently wrong name. Card treatment:

```css
.incident-card--unknown {
  border-left-color: var(--unknown);
  border: 1px dashed var(--unknown-border);
  background: var(--unknown-bg);
}
```

Card shows the label the classifier actually produced, **struck through**, followed by the truth:

```
?  D̶o̶S̶ ̶s̶l̶o̶w̶l̶o̶r̶i̶s̶   →  UNKNOWN (ground truth: Heartbleed)
   Not in the classifier's label space. conf 0.88 — confidently wrong.
```

The dashed border is the non-color channel. `conf 0.88 — confidently wrong` is the whole point: it demonstrates you understand that a softmax over a closed label set cannot express "I don't know."

**(c) Misclassified — detected, wrong named class.**
`--misclass` violet, solid border, `≠` glyph, `predicted X · actual Y` on the card.

**Panel summary.** Close with the real metrics table from `metrics.json`, rendered as a proper table with tabular-nums, and the three-number comparison stated plainly:

```
XGBoost alone      0.996 accuracy   (labels available)
LSTM alone         0.696 accuracy   (unsupervised detection)
Full pipeline      0.805 accuracy   ← the honest number
```

Set `0.805` in `--fg` at `--text-2xl`; set the other two in `--fg-muted`. Leading with the number that isn't flattering, and explaining exactly why, is the strongest signal on the page.

---

## 6. Motion

### 6.1 Curves

Harvested from the reference bundles:

```css
--ease-out:   cubic-bezier(.22, 1, .36, 1);      /* aura + open-design + neuform */
--ease-out-s: cubic-bezier(.16, 1, .3, 1);       /* aura + neuform */
--ease-std:   cubic-bezier(.4, 0, .2, 1);        /* Hyperbrowser default */
--ease-drop:  cubic-bezier(.34, 1.56, .64, 1);   /* neuform — slight overshoot */
```

`cubic-bezier(.22,1,.36,1)` appears in all three parseable non-Refero bundles. It is the house curve of this aesthetic: fast start, long settle, no bounce. Use it for anything that travels.

### 6.2 Durations

| Motion | Duration | Easing | Property |
|---|---|---|---|
| Log row enters | 420ms | `--ease-out` | `transform: translateY` on rail |
| Window bracket slide | 420ms | `--ease-out` | `transform` — same frame as rail |
| Chart advance | 420ms | `linear` | x-domain shift |
| Threshold drag | **0ms** | none | 1:1 with pointer, no interpolation |
| Threshold keyboard step | 120ms | `--ease-std` | `transform` |
| Point crosses threshold | 160ms | `--ease-out` | `r`, `fill`, shape morph |
| Metrics recompute | 200ms | `--ease-std` | number tween, tabular-nums |
| Verdict state change | 180ms | `--ease-std` | `background`, `color`, `border-color` |
| Card ejects from detector | 260ms | `--ease-out` | `transform` + `opacity` 1→0 |
| Card drops into queue | 340ms | `--ease-drop` | `translateY(-24px)` → `0` |
| Existing cards shift down | 340ms | `--ease-out` | `transform: translateY` |
| Hover elevation | 150ms | `--ease-std` | `box-shadow` |

150ms/`cubic-bezier(.4,0,.2,1)` is Hyperbrowser's `--default-transition-duration` / `--default-transition-timing-function` verbatim — a safe default for every unlisted micro-interaction.

**Threshold drag must have zero interpolation.** Any easing on the handle position introduces perceived lag and the control feels broken. Interpolate the *derived* values (metrics, fills) — never the handle.

**The card drop** is the one place a slight overshoot is warranted: `--ease-drop` has a small bounce that sells physical weight landing on a stack. It is also the only overshoot on the page. One is characterful; several are cartoonish.

Animate only `transform` and `opacity` for anything running continuously. The log feed runs indefinitely — animating `top` or `height` there will drop frames.

### 6.3 Reduced motion

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

Beyond the blanket reset, this page needs **behavioral** changes — a continuously scrolling feed is not made acceptable by shortening its transitions:

- The log stream **does not auto-scroll**. It starts paused, showing a static 24-row sample. A `Step ▸` button advances one window at a time.
- Cards **appear** in the queue without a drop animation.
- Chart points appear without the crossing animation; the fill regions still update, since they carry meaning.
- The threshold drag still works — direct manipulation is not "motion" in the vestibular sense and must be preserved.

Detect it in JS too (`matchMedia('(prefers-reduced-motion: reduce)')`), not just CSS, since the auto-play decision is a script behavior.

---

## 7. Accessibility

### 7.1 Contrast

Every combination below must clear **WCAG AA**: 4.5:1 for text < 18.66px/700, 3:1 for large text and for UI component boundaries and graphical objects (WCAG 1.4.11 — this covers chart points and the threshold line).

Verified pairings in the palette:

| Foreground | Background | Ratio | Passes |
|---|---|---|---|
| `--fg` `#0d0f15` | `--bg` `#ffffff` | ~18.9:1 | AAA |
| `--fg-muted` `#6f7179` | `--bg` `#ffffff` | ~5.1:1 | AA |
| `--fg-subtle` `#979fb9` | `--bg` `#ffffff` | ~2.7:1 | **decorative only** |
| `--anomalous-fg` `#7b3306` | `--anomalous-bg` `#fffbeb` | ~8.0:1 | AAA |
| `--benign-fg` `#2c4a68` | `--benign-bg` `#eef3f8` | ~8.6:1 | AAA |
| `--unknown-fg` `#6d0f51` | `--unknown-bg` `#fdf2f9` | ~10.4:1 | AAA |
| `--missed-fg` `#4b4f5a` | `--missed-bg` `#f4f4f6` | ~7.9:1 | AAA |

`--fg-subtle` at 2.7:1 is **below AA** and is used for out-of-window log rows. This is acceptable *only* because those rows are `aria-hidden` decoration whose content is also available in the accessible summary (§7.4). Rows inside the window use `--fg` and pass. If you ever make the raw log lines load-bearing for comprehension, this token must be darkened to at least `#6f7179`.

Re-verify every pair after any palette edit. Do not eyeball it.

### 7.2 The threshold as a real widget

```html
<div role="slider"
     tabindex="0"
     aria-label="Anomaly detection threshold"
     aria-valuemin="0"
     aria-valuemax="1"
     aria-valuenow="0.4444"
     aria-valuetext="0.4444, calibrated. Precision 0.998, recall 0.424, 6318 of 14887 DoS Hulk flows flagged."
     aria-describedby="threshold-help">
```

`aria-valuetext` carrying the live precision/recall is the difference between a usable and a useless control for a screen reader user — the raw number alone communicates nothing.

### 7.3 Keyboard

| Key | Action |
|---|---|
| `Tab` | Focus the threshold slider |
| `↑` / `↓` | ±0.005 |
| `Shift` + `↑`/`↓` | ±0.05 |
| `PageUp` / `PageDown` | ±0.1 |
| `Home` / `End` | 0.0 / 1.0 |
| `Enter` | Snap to calibrated 0.4444 |

Announce the calibrated snap via the live region: `"Snapped to calibrated threshold 0.4444."`

**Focus ring** — must be visible in both themes and against the chart:

```css
:focus-visible {
  outline: 2px solid var(--threshold-grab);
  outline-offset: 2px;
  border-radius: 4px;
}
.threshold-handle:focus-visible {
  outline: none;
  filter: drop-shadow(0 0 0 2px var(--bg))
          drop-shadow(0 0 0 4px var(--threshold-grab));
}
```

The double drop-shadow gives a white/dark separator ring so the focus indicator stays visible over any chart fill. Never `outline: none` without a replacement. All interactive elements need `:focus-visible`, not `:focus` — mouse users should not see rings.

### 7.4 Live regions — the scrolling feed

**A naive `aria-live` on a feed emitting a row every 420ms is an accessibility catastrophe.** It will flood a screen reader with unstoppable speech and effectively lock the user out of the page.

Required treatment:

1. **The visual stream is `aria-hidden="true"`.** All of it. Individual log rows are never announced.
2. **One `role="status" aria-live="polite" aria-atomic="true"` region** carries a throttled summary — **at most one update every 5 seconds**:
   `"Window 1284 analyzed. Reconstruction error 0.51. Anomalous. Classified DoS Hulk."`
3. **A prominent, keyboard-reachable Pause / Play control as the first focusable element in the demo.** WCAG 2.2.2 requires a pause mechanism for any content that auto-updates for more than 5 seconds. This is non-negotiable and it must come *before* the stream in DOM order.
4. **Autoplay stops on focus.** When focus enters the demo region, pause the stream. A user tabbing through must not be chasing a moving target.
5. **A static accessible alternative.** A visually-hidden (or `<details>`-collapsed) `<table>` of the last 20 windows: index, error, verdict, class. Screen reader users get the same information as a navigable structure rather than a stream.
6. **The incident queue is `role="log"`** with `aria-live="polite"` — cards are discrete meaningful events, unlike raw rows, and arrive at a human-readable rate.
7. **`prefers-reduced-motion` starts the stream paused** (§6.3).

### 7.5 Other

- Respect `prefers-contrast: more` — increase all border widths to 2px and swap `--fg-subtle` to `--fg-muted`.
- The demo must be fully comprehensible with JavaScript disabled or on failure: render a static screenshot-equivalent with the metrics table and an explanatory caption.
- Do not convey any state by color alone (§2.4). This is WCAG 1.4.1 and it is the single most likely failure on a security-themed page.
- Every `<canvas>`/`<svg>` chart needs a text alternative summarizing the current state.

---

## 8. Anti-patterns

**Explicitly forbidden:**

- **Matrix / neon-on-black terminal.** No `#00ff00` on `#000`, no falling glyphs, no CRT scanlines, no phosphor glow, no `text-shadow` bloom on mono text. Note that `aura.build`'s bundle literally contains `#00ff00` and `#ff0000` gradient stops — it is a template gallery containing every aesthetic, including ones to avoid. Do not treat its presence there as endorsement.
- **`open-design.ai`'s neon lime (`#63fe13`) and hard offset shadows** (`0 0 0 1px #22221f, 7px 7px 0 #63fe13`). Its neutrals and radius scale were harvested; its accent color and neo-brutalist shadow language were **deliberately rejected**. That treatment is loud, and the brief says "not exaggerated."
- **Typewriter / character-by-character text reveal.** The single strongest fake-hacker signal. Rows appear complete, then scroll.
- **Fake data.** No invented IPs, no invented feature names, no invented attack classes. Everything comes from CIC-IDS2017 and `metrics.json`.
- **Red-vs-green as the only state channel.** See §2.4.
- **Pulsing/glowing alert states.** No `animation: pulse infinite` on the anomalous verdict. Hyperbrowser ships an `--animate-pulse` token; that does not mean use it here.
- **Auto-scaling the chart's Y axis.** Breaks the threshold interaction (§5.3).
- **Hiding the failures**, or rendering them in tiny muted footnote text. They are the point.
- **Rounding away the ugly numbers.** DoS Hulk recall is 0.424. Not "~0.4," not "over 40%."
- **Skeuomorphic SOC chrome** — fake window title bars, fake OS traffic-light dots, fake `$` prompts, fake blinking cursors, ASCII-art dividers.
- **Gradient-heavy AI-startup styling** — mesh gradients, glassmorphism, animated aurora backgrounds. `neuform.ai`'s bundle has plenty; it is a template gallery, not a house style.
- **More than one accent hue per semantic state.** Five semantic colors is already the ceiling. Do not add a sixth for "processing."
- **Animating layout properties** (`width`, `height`, `top`, `margin`) on the continuous feed. `transform`/`opacity` only.
- **Emoji as status icons.** Use the geometric glyphs in §2.4.

---

## 9. Implementation checklist

- [ ] Every token defined on bare `:root`; dark overrides duplicated for both `prefers-color-scheme` and `[data-theme="dark"]`
- [ ] `filter: grayscale(1)` test — all five states still distinguishable
- [ ] Simulate deuteranopia and protanopia — benign vs. anomalous still distinct
- [ ] Contrast-check every pairing in §7.1 after any palette change
- [ ] `font-variant-numeric: tabular-nums` on every live-updating number
- [ ] Pause control is the first focusable element in the demo region
- [ ] Threshold operable by keyboard with live `aria-valuetext`
- [ ] `prefers-reduced-motion` starts the stream paused and disables the drop animation
- [ ] Threshold handle tracks the pointer with zero interpolation
- [ ] All displayed metrics sourced from `metrics.json`, not hardcoded
- [ ] Threshold displays `0.4444`; snap target is exactly `0.44443160079796684`
- [ ] No horizontal body scroll at 320px viewport width
- [ ] Touch targets ≥ 44×44px on the threshold handle at all widths
- [ ] Failure panel is visually equal in weight to the success metrics
