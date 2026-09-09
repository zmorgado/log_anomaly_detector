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
  var bestF1 = null;      // F1 sweep result, retained so a language switch re-renders it

  var $ = function (id) { return document.getElementById(id); };

  var el = {};

  // ------------------------------------------------------------------- i18n

  /* Spanish is the primary language; English is the alternate. Strings live
     here rather than in translation files so the page stays a single
     self-contained directory openable over file://.

     Spanish here is Argentine (rioplatense): voseo for second-person verbs
     ("arrastrá", "fijás"), and rioplatense vocabulary throughout.

     Attack class names (BENIGN, DoS Hulk, DoS Slowhttptest, DoS slowloris) are
     dataset labels and are never translated. These technical terms also stay in
     English by request, because they are what practitioners actually say:
     recall, accuracy, precision, deploy, labels, scaler, autoencoder. */
  var I18N = {
    'doc.title': {
      es: 'Detector de anomalías en logs — demo interactiva',
      en: 'Log Anomaly Detector — interactive demo'
    },
    'doc.desc': {
      es: 'Reproducción interactiva de un detector de intrusiones de dos etapas ' +
          '(autoencoder LSTM + XGBoost) sobre CIC-IDS2017. Arrastrá el umbral de anomalía ' +
          'y mirá cómo se recalculan precision, recall y la cola de alertas.',
      en: 'Interactive replay of a two-stage LSTM autoencoder + XGBoost network intrusion ' +
          'detector on CIC-IDS2017. Drag the anomaly threshold and watch precision, recall ' +
          'and the alert queue recompute.'
    },

    // ---- project intro
    'intro.eyebrow': {
      es: 'Proyecto final · Curso Intensivo en Inteligencia Artificial (CEI Sevilla)',
      en: 'Final project · Curso Intensivo en Inteligencia Artificial (CEI Seville)'
    },
    'intro.title': {
      es: 'Detector de anomalías en tráfico de red',
      en: 'Network traffic anomaly detector'
    },
    'intro.p1': {
      es: 'Un sistema híbrido de dos etapas: un <b>autoencoder LSTM no supervisado</b>, ' +
          'entrenado solo con tráfico benigno, marca los flujos que no logra reconstruir; un ' +
          '<b>clasificador XGBoost</b> le pone nombre a la amenaza en los que quedaron marcados.',
      en: 'A hybrid two-stage system: an <b>unsupervised LSTM autoencoder</b>, trained only on ' +
          'benign traffic, flags the flows it cannot reconstruct; an <b>XGBoost classifier</b> ' +
          'names the threat for the ones that were flagged.'
    },
    /* Why the project exists — the one thing here no chart or table on this
       page shows. The paragraph that used to follow this one restated the
       metrics table and the failure panel, so it is gone. */
    'intro.p2': {
      es: 'Los equipos de un SOC reciben más alertas de las que pueden revisar. La idea es ' +
          'automatizar el triaje de los ataques conocidos; al no ser supervisada, la primera ' +
          'etapa además puede marcar ataques que nunca vio.',
      en: 'SOC teams receive more alerts than they can review. The idea is to automate triage ' +
          'for the known attacks; being unsupervised, the first stage can also flag attacks it ' +
          'has never seen.'
    },
    'intro.repo': { es: 'Código y documentación', en: 'Code and documentation' },
    'intro.repoAria': {
      es: 'Repositorio del proyecto en GitHub (se abre en una solapa nueva)',
      en: 'Project repository on GitHub (opens in a new tab)'
    },

    // ---- demo header (secondary)
    'demo.eyebrow': { es: 'Demo interactiva', en: 'Interactive demo' },
    'demo.title':   { es: 'El umbral es todo el sistema', en: 'The threshold is the whole system' },
    /* One sentence of orientation. The drawings below say the rest. */
    'demo.lede': {
      es: '<strong>Todo lo que sigue se recalcula en tu navegador a partir de un solo ' +
          'número</strong>: arrastrá el umbral y mirá qué se mueve.',
      en: '<strong>Everything below is recomputed in your browser from a single ' +
          'number</strong> — drag the threshold and watch what moves.'
    },

    /* ---- language switcher
       The portfolio's, verbatim: the button prints the code of the language it
       switches TO, and the accessible label is written in that same target
       language. Both are what santiagomorgado.dev says, so the control reads
       identically on either side of the subdomain. */
    'lang.code':     { es: 'en', en: 'es' },
    'lang.switchTo': { es: 'Read this in English', en: 'Ver en español' },
    'lang.changed':  { es: 'Idioma cambiado a español.', en: 'Language changed to English.' },

    // ---- provenance
    'prov.source':  { es: 'Fuente', en: 'Source' },
    'prov.rows':    { es: 'Filas', en: 'Rows' },
    'prov.windows': { es: 'ventanas', en: 'windows' },
    'prov.tensor':  { es: 'tensor', en: 'tensor' },
    'prov.flows':   { es: 'flujos', en: 'flows' },
    'prov.noteEs': {
      es: 'Segmento no visto: fuera del rango 40k–90k del miércoles usado para ajustar ' +
          'XGBoost, y el scaler se ajustó solo con tráfico benigno del lunes.',
      en: null   // null = use the feed's own English note verbatim
    },

    // ---- noscript
    'noscript.strong': { es: 'JavaScript está desactivado.', en: 'JavaScript is disabled.' },
    'noscript.body': {
      es: 'La reproducción interactiva lo necesita. Los resultados medidos no cambian: el ' +
          'pipeline completo obtiene <b>0.805 de accuracy</b> contra el 0.996 de XGBoost por ' +
          'separado, y el recall en DoS Hulk es de <b>0.424</b>.',
      en: 'The interactive replay needs it. The measured results are unchanged: the full ' +
          'pipeline scores <b>0.805 accuracy</b> against XGBoost\'s 0.996 on its own, and DoS ' +
          'Hulk recall is <b>0.424</b>.'
    },

    // ---- playback controls
    'ctrl.eyebrow': { es: 'Reproducción', en: 'Playback' },
    /* Legends, not prose: they annotate the controls beside them. */
    'ctrl.note': {
      es: '1 flujo / 420&nbsp;ms',
      en: '1 flow / 420&nbsp;ms'
    },
    'ctrl.noteReduced': {
      es: 'movimiento reducido · arranca en pausa',
      en: 'reduced motion · starts paused'
    },
    'ctrl.pause': { es: 'Pausar', en: 'Pause' },
    'ctrl.play':  { es: 'Reproducir', en: 'Play' },
    'ctrl.step':  { es: 'Avanzar una ventana', en: 'Step one window' },
    'ctrl.dark':  { es: 'Oscuro', en: 'Dark' },
    'ctrl.light': { es: 'Claro', en: 'Light' },

    // ---- stream section
    'stream.eyebrow': { es: '1 · Flujo de red · CIC-IDS2017', en: '1 · Network flow stream · CIC-IDS2017' },
    'stream.title':   { es: 'Los flujos llegan de 20 en 20', en: 'Raw flows arrive, 20 at a time' },
    'stream.note': {
      es: 'Siete de las 36 características que lee el modelo; las filas <em>no</em> se colorean ' +
          'por su label real, porque el detector todavía no lo conoce.',
      en: 'Seven of the 36 features the model reads; rows are <em>not</em> coloured by their ' +
          'true label, because the detector does not know it yet.'
    },
    'stream.window': { es: 'ventana', en: 'window' },
    'stream.rows':   { es: 'filas', en: 'rows' },
    'stream.absRows':{ es: 'filas absolutas del CSV', en: 'absolute CSV rows' },
    'stream.bracket':{ es: 'VENTANA t−19 → t · 20 × 36', en: 'WINDOW t−19 → t · 20 × 36' },

    // ---- chart section
    'chart.eyebrow': { es: '2 · Detección · autoencoder LSTM', en: '2 · Detection · LSTM autoencoder' },
    'chart.title':   { es: 'Error de reconstrucción frente al umbral', en: 'Reconstruction error vs. threshold' },
    /* No note: the axis, the legend, the handle and the keyboard legend say
       everything the deleted paragraph said. */
    'chart.svgTitle': {
      es: 'Error de reconstrucción por ventana con umbral de anomalía arrastrable',
      en: 'Reconstruction error per window with draggable anomaly threshold'
    },
    'chart.axis':    { es: 'error de reconstrucción (MAE)', en: 'reconstruction error (MAE)' },
    'chart.window':  { es: 'ventana', en: 'window' },
    'chart.calib':   { es: 'calibrado · p95 benigno · 0.4444', en: 'calibrated · p95 benign · 0.4444' },
    'chart.eqCalib': { es: '= calibrado', en: '= calibrated' },
    'chart.cfCost':  { es: 'capturarlos cuesta precision → ', en: 'catching these costs precision → ' },

    'legend.benign':  { es: '· benigno (por debajo)', en: '· benign (below)' },
    'legend.anom':    { es: '▲ marcado como anómalo', en: '▲ flagged anomalous' },
    /* Each glyph is the mark the chart actually draws for that state. */
    'legend.missed':  { es: '○ ataque no detectado (por debajo)', en: '○ missed attack (below)' },
    'legend.unknown': { es: '◇ clase desconocida', en: '◇ unknown class' },
    'legend.calib':   { es: '— — calibrado 0.4444', en: '— — calibrated 0.4444' },

    'thr.label':  { es: 'Umbral', en: 'Threshold' },
    'thr.aria':   { es: 'Umbral de detección de anomalías, entrada numérica',
                    en: 'Anomaly detection threshold, numeric entry' },
    'thr.reset':  { es: 'Volver al calibrado', en: 'Reset to calibrated' },
    /* A legend for the control it sits beside, not a sentence about it. Still
       the accessible description for the slider, so it stays in words a screen
       reader can read aloud rather than in arrow glyphs. */
    'thr.help': {
      es: 'flechas ±0.005 · mayús ±0.05 · av/re pág ±0.1 · inicio/fin · enter → 0.4444',
      en: 'arrows ±0.005 · shift ±0.05 · pgup/pgdn ±0.1 · home/end · enter → 0.4444'
    },
    'thr.sliderAria': { es: 'Umbral de detección de anomalías', en: 'Anomaly detection threshold' },

    'm.precision': { es: 'precision', en: 'precision' },
    'm.recall':    { es: 'recall', en: 'recall' },
    'm.f1':        { es: 'F1', en: 'F1' },
    'm.alerts':    { es: 'alertas', en: 'alerts' },

    // ---- verdict
    'verdict.eyebrow':   { es: '3 · Veredicto para la ventana actual', en: '3 · Verdict for the current window' },
    'verdict.benign':    { es: 'BENIGNO', en: 'BENIGN' },
    'verdict.anomalous': { es: 'ANÓMALO', en: 'ANOMALOUS' },
    'verdict.error':     { es: 'error', en: 'error' },
    'verdict.threshold': { es: 'umbral', en: 'threshold' },
    'verdict.sentTo':    { es: ' · enviado a XGBoost → ', en: ' · sent to XGBoost → ' },
    'verdict.disagree':  { es: '(las etapas no coinciden)', en: '(stages disagree)' },
    'verdict.notClassified': { es: ' · no clasificado', en: ' · not classified' },

    // ---- queue
    'queue.eyebrow': { es: '4 · Clasificación · XGBoost', en: '4 · Classification · XGBoost' },
    'queue.title':   { es: 'Cola de triaje de incidentes', en: 'Incident triage queue' },
    'queue.note': {
      es: 'El espacio de labels de XGBoost está cerrado, así que va a nombrar algo incluso ' +
          'cuando no debería.',
      en: 'XGBoost’s label space is closed, so it will name something even when it should not.'
    },
    'queue.aria':   { es: 'Cola de triaje de incidentes', en: 'Incident triage queue' },
    'queue.err':    { es: 'err', en: 'err' },
    'queue.window': { es: 'ventana', en: 'window' },
    'queue.rows':   { es: 'filas', en: 'rows' },
    'queue.empty': {
      es: function (n, t) {
        return 'Nada marcado en las ' + n + ' ventanas anteriores al cabezal con el umbral ' +
               t + '. Bajá la línea o dejá correr el flujo.';
      },
      en: function (n, t) {
        return 'Nothing flagged in the ' + n + ' windows before the playhead at threshold ' +
               t + '. Lower the line, or let the stream run.';
      }
    },
    'queue.moreHidden': {
      es: function (h, a, t) {
        return '+ ' + h + ' alerta' + (h === '1' ? '' : 's') + ' anterior' +
               (h === '1' ? '' : 'es') + ' en esta sesión · ' + a +
               ' ventanas superan ' + t + ' en todo el feed';
      },
      en: function (h, a, t) {
        return '+ ' + h + ' earlier alert' + (h === '1' ? '' : 's') + ' this session · ' + a +
               ' windows exceed ' + t + ' across the whole feed';
      }
    },
    'queue.moreTotal': {
      es: function (a, n, t) { return a + ' de ' + n + ' ventanas superan ' + t + ' en todo el feed'; },
      en: function (a, n, t) { return a + ' of ' + n + ' windows exceed ' + t + ' across the whole feed'; }
    },

    // ---- cards
    'card.unknownTruth': { es: ' → DESCONOCIDO (label real: ', en: ' → UNKNOWN (ground truth: ' },
    'card.noClass':      { es: 'SIN CLASE', en: 'NO CLASS' },
    'card.xgbSaysBenign':{ es: ' — XGBoost dice BENIGN', en: ' — XGBoost says BENIGN' },
    'card.truthIs':      { es: ', label real ', en: ', truth ' },
    'card.actuallyBenign': { es: ' — en realidad BENIGN', en: ' — actually BENIGN' },
    'card.noteUnknown': {
      es: 'No está en el espacio de labels del clasificador. Un softmax sobre cuatro clases ' +
          'no puede responder «no sé»: se equivoca con seguridad.',
      en: 'Not in the classifier’s label space. A softmax over four classes cannot output ' +
          '“I don’t know” — confidently wrong.'
    },
    'card.noteMisclass': {
      es: 'Detectado, pero mal nombrado. El analista recibe un incidente real con un título engañoso.',
      en: 'Detected, but named wrong. The analyst still gets a real incident, with a misleading title.'
    },
    'card.noteDisagreeRight': {
      es: 'El detector marcó esta ventana; el clasificador respondió BENIGN. Las dos etapas ' +
          'no coinciden y el pipeline no tiene forma de desempatar, así que el analista recibe ' +
          'una alerta sin nombre de ataque — acá el clasificador tenía razón.',
      en: 'The detector flagged this window; the classifier answered BENIGN. The two stages ' +
          'disagree and the pipeline has no tie-breaker, so the analyst gets an alert with no ' +
          'attack name — here the classifier was right.'
    },
    'card.noteDisagreeWrong': {
      es: 'El detector marcó esta ventana; el clasificador respondió BENIGN. Las dos etapas ' +
          'no coinciden y el pipeline no tiene forma de desempatar, así que el analista recibe ' +
          'una alerta sin nombre de ataque — y acá el clasificador se equivocaba.',
      en: 'The detector flagged this window; the classifier answered BENIGN. The two stages ' +
          'disagree and the pipeline has no tie-breaker, so the analyst gets an alert with no ' +
          'attack name — and here the classifier was wrong.'
    },
    'card.noteFp': {
      es: 'Falso positivo: tráfico benigno por encima de tu umbral. Este es el costo de bajar la línea.',
      en: 'False positive — benign traffic above your threshold. This is the cost of lowering the line.'
    },

    // ---- accessible table
    'a11y.summary': { es: 'Alternativa en texto — últimas 20 ventanas analizadas',
                      en: 'Text alternative — last 20 windows analyzed' },
    'a11y.caption': { es: 'Ventanas más recientes: índice, error de reconstrucción, veredicto y clase',
                      en: 'Most recent windows: index, reconstruction error, verdict, class' },
    'a11y.thWindow':  { es: 'Ventana', en: 'Window' },
    'a11y.thError':   { es: 'Error', en: 'Error' },
    'a11y.thVerdict': { es: 'Veredicto', en: 'Verdict' },
    'a11y.thClass':   { es: 'Clase', en: 'Class' },
    'a11y.thTruth':   { es: 'Label real', en: 'Ground truth' },
    'a11y.anomalous': { es: 'Anómalo', en: 'Anomalous' },
    'a11y.benign':    { es: 'Benigno', en: 'Benign' },

    // ---- failure panel
    'fail.eyebrow': { es: '5 · Lo que el sistema hace mal', en: '5 · What this system gets wrong' },
    'fail.title':   { es: 'Las fallas, a tamaño real', en: 'The failures, at full size' },
    /* No note: the two numbers below move in opposite directions as the
       threshold moves, which is the whole of what the deleted paragraph said. */
    'fail.missedHead': { es: 'Ataques no detectados', en: 'Missed attacks' },
    'fail.fpHead':     { es: 'Falsos positivos', en: 'False positives' },
    'fail.missedBody': {
      es: function (t, r) {
        return 'ventanas de ataque quedan <b>por debajo</b> de ' + t +
               ' y nunca se clasifican. Recall ' + r + '.';
      },
      en: function (t, r) {
        return 'attack windows fall <b>below</b> ' + t + ' and are never classified. Recall ' +
               r + '.';
      }
    },
    'fail.fpBody': {
      es: function (p, pct) {
        return 'alertas son tráfico benigno. Precision ' + p + ' — un analista descartaría el ' +
               pct + '% de esta cola.';
      },
      en: function (p, pct) {
        return 'alerts are benign traffic. Precision ' + p + ' — an analyst would discard ' +
               pct + '% of this queue.';
      }
    },
    /* The Limitation, in its own voice. zmorgado/portfolio ADR-0006 records
       that dropping the per-project pages cost that site the ability to make
       this argument properly — it survives there as one line on a grid cell.
       This page is now the only place it gets made in full, so it stays even
       as the prose around it is cut. */
    'fail.hulkNote': {
      es: '<b>DoS Hulk: recall 0.424.</b> Genera pedidos HTTP sintácticamente válidos cuyas ' +
          'características de flujo se superponen con el tráfico benigno, así que el ' +
          'autoencoder los reconstruye bien y su error queda por debajo del umbral: unos 8.600 ' +
          'de 14.887 flujos de ataque nunca llegan al clasificador. Es lo más grave que tiene ' +
          'el sistema, y ningún umbral que fijes acá lo va a mostrar, porque este segmento no ' +
          'contiene DoS Hulk.',
      en: '<b>DoS Hulk: recall 0.424.</b> It generates syntactically valid HTTP requests whose ' +
          'flow features overlap with benign traffic, so the autoencoder reconstructs them well ' +
          'and their error stays below the threshold: roughly 8,600 of 14,887 attack flows ' +
          'never reach the classifier. It is the worst thing wrong with the system, and no ' +
          'threshold you set here will show it, because this slice contains no DoS Hulk.'
    },
    'fail.unknownNote': {
      es: '<b>Ataques desconocidos.</b> Ante un flujo de GoldenEye o Heartbleed el clasificador ' +
          'no puede responder «no sé» —un softmax sobre cuatro labels no tiene esa salida—, ' +
          'así que devuelve un nombre incorrecto con seguridad. Este segmento no contiene ' +
          'tráfico así, que es una propiedad de la muestra y no una solución.',
      en: '<b>Unknown attacks.</b> Faced with a GoldenEye or Heartbleed flow the classifier ' +
          'cannot answer "I don\'t know" — a softmax over four labels has no such output — so ' +
          'it returns a confident wrong name. This slice contains no such traffic, which is a ' +
          'property of the sample and not a solution.'
    },
    'fail.disagreeNote': {
      es: function (d, a, wrong) {
        return '<b>' + d + '</b> de ' + a + ' alertas son ventanas que el autoencoder marcó y ' +
               'XGBoost etiquetó como BENIGN. El pipeline no tiene árbitro: la alerta llega al ' +
               'analista sin nombre de ataque. ' +
               (wrong
                 ? 'En ' + wrong + ' de ellas el que se equivocaba era el clasificador.'
                 : 'Acá el clasificador acierta siempre que no coincide.');
      },
      en: function (d, a, wrong) {
        return '<b>' + d + '</b> of ' + a + ' alerts are windows the autoencoder flagged and ' +
               'XGBoost labelled BENIGN. The pipeline has no arbiter: the alert reaches the ' +
               'analyst with no attack name. ' +
               (wrong
                 ? 'In ' + wrong + ' of them the classifier was the one that was wrong.'
                 : 'On this slice the classifier is right every time it disagrees.');
      }
    },
    'fail.tableCaption': {
      es: 'Pipeline completo, conjunto de evaluación completo (artifacts/metrics.json)',
      en: 'Full pipeline, complete evaluation set (artifacts/metrics.json)'
    },
    'fail.thClass':     { es: 'Clase', en: 'Class' },
    'fail.thPrecision': { es: 'Precision', en: 'Precision' },
    'fail.thRecall':    { es: 'Recall', en: 'Recall' },
    'fail.thF1':        { es: 'F1', en: 'F1' },
    'fail.thSupport':   { es: 'Soporte', en: 'Support' },

    'cmp.xgb':       { es: 'XGBoost por separado', en: 'XGBoost alone' },
    'cmp.xgbNote':   { es: '— con labels disponibles', en: '— labels available' },
    'cmp.lstm':      { es: 'Detector LSTM por separado', en: 'LSTM detector alone' },
    'cmp.lstmNote':  { es: '— no supervisado, binario', en: '— unsupervised, binary' },
    'cmp.pipeline':  { es: 'Pipeline completo', en: 'Full pipeline' },
    'cmp.pipeNote':  { es: '— el número honesto', en: '— the honest number' },
    'cmp.accuracy':  { es: 'de accuracy', en: 'accuracy' },
    /* The one sentence the table will not say for itself. */
    'fail.closing': {
      es: 'El pipeline completo obtiene <b>0.805</b> donde XGBoost por separado obtiene ' +
          '<b>0.996</b>: esos diecinueve puntos son lo que cuesta encadenarlo a un detector que ' +
          'se pierde ataques, y dar solo el 0.996 sería el número más favorable y el menos cierto.',
      en: 'The full pipeline scores <b>0.805</b> where XGBoost alone scores <b>0.996</b> — those ' +
          'nineteen points are what chaining it to a detector that misses attacks costs, and ' +
          'reporting the 0.996 alone would be the more flattering number and the less true one.'
    },

    'tradeoff': {
      es: function (bf1, bt, gap, cal) {
        return '<b>El umbral es defendible, no óptimo.</b> Se fijó en el percentil 95 del error ' +
               'de validación benigno antes de mirar este segmento; acá F1 alcanza <b>' + bf1 +
               '</b> en <b>' + bt + '</b>, ' + gap + ' por encima del ' + cal + ' del calibrado. ' +
               'Ajustarlo sobre los datos con los que te evalúan es cómo se consigue un número ' +
               'que no sobrevive al deploy.';
      },
      en: function (bf1, bt, gap, cal) {
        return '<b>The shipped threshold is defensible, not optimal.</b> It was set at the 95th ' +
               'percentile of benign validation error before anyone looked at this slice; here ' +
               'F1 peaks at <b>' + bf1 + '</b> around <b>' + bt + '</b>, ' + gap + ' above the ' +
               cal + ' the calibrated value scores. Tuning it on the data you are judged on is ' +
               'how you get a number that does not survive deployment.';
      }
    },

    // ---- live region / screen-reader announcements
    'live.analyzed': {
      es: function (w, e, v) { return 'Ventana ' + w + ' analizada. Error de reconstrucción ' + e + '. ' + v; },
      en: function (w, e, v) { return 'Window ' + w + ' analyzed. Reconstruction error ' + e + '. ' + v; }
    },
    'live.benign':    { es: 'Benigna.', en: 'Benign.' },
    'live.disagree':  { es: 'Marcada como anómala, pero el clasificador respondió benigna. Las dos etapas no coinciden.',
                        en: 'Flagged anomalous, but the classifier answered benign. The two stages disagree.' },
    'live.anomalous': { es: function (c) { return 'Anómala. Clasificada como ' + c + '.'; },
                        en: function (c) { return 'Anomalous. Classified ' + c + '.'; } },
    'live.snapped':   { es: 'Fijado al umbral calibrado 0.4444.', en: 'Snapped to calibrated threshold 0.4444.' },

    'valuetext': {
      es: function (t, cal, p, r, f, a, fn, at) {
        return t + (cal ? ', calibrado' : '') + '. Precision ' + p + ', recall ' + r +
               ', F1 ' + f + '. ' + a + ' alertas, ' + fn + ' de ' + at +
               ' ventanas de ataque no detectadas.';
      },
      en: function (t, cal, p, r, f, a, fn, at) {
        return t + (cal ? ', calibrated' : '') + '. Precision ' + p + ', recall ' + r + ', F1 ' +
               f + '. ' + a + ' alerts, ' + fn + ' of ' + at + ' attack windows missed.';
      }
    },
    'chartDesc': {
      es: function (a, b, t, e, v, n, p, r, f, al, fn) {
        return 'Error de reconstrucción para las ventanas ' + a + ' a ' + b +
               ', rango vertical fijo de 0 a 1.7. Umbral ' + t + '. Error de la ventana actual ' +
               e + ', veredicto ' + v + '. En las ' + n + ' ventanas: precision ' + p +
               ', recall ' + r + ', F1 ' + f + ', ' + al + ' alertas, ' + fn +
               ' ataques no detectados.';
      },
      en: function (a, b, t, e, v, n, p, r, f, al, fn) {
        return 'Reconstruction error for windows ' + a + ' to ' + b +
               ', fixed vertical range 0 to 1.7. Threshold ' + t + '. Current window error ' + e +
               ', verdict ' + v + '. Across all ' + n + ' windows: precision ' + p + ', recall ' +
               r + ', F1 ' + f + ', ' + al + ' alerts, ' + fn + ' missed attacks.';
      }
    },
    'desc.anomalous': { es: 'anómalo', en: 'anomalous' },
    'desc.benign':    { es: 'benigno', en: 'benign' },

    // ---- footer
    'footer.p1': {
      es: 'Proyecto final del <em>Curso Intensivo en Inteligencia Artificial</em> (CEI Sevilla). ' +
          'Dataset: CIC-IDS2017 (MachineLearningCVE), Canadian Institute for ' +
          'Cybersecurity, University of New Brunswick.',
      en: 'Final project, <em>Curso Intensivo en Inteligencia Artificial</em> (CEI Seville). ' +
          'Dataset: CIC-IDS2017 (MachineLearningCVE), Canadian Institute for Cybersecurity, ' +
          'University of New Brunswick.'
    },
    'footer.p2': {
      es: 'Toda la inferencia se ejecutó sin conexión; esta página reproduce un feed precalculado ' +
          'y solo recalcula la decisión del umbral. Métricas tomadas de artifacts/metrics.json.',
      en: 'All inference ran offline; this page replays a precomputed feed and recomputes only ' +
          'the threshold decision. Metrics quoted from artifacts/metrics.json.'
    },

    // ---- load failure
    'load.failStrong': { es: 'No se ha podido cargar el feed de la demo.', en: 'Could not load the demo feed.' },
    'load.failBody': {
      es: 'Algunos navegadores bloquean <span class="mono">fetch()</span> de archivos locales ' +
          'sobre <span class="mono">file://</span>. Serví este directorio por HTTP —por ejemplo ' +
          '<span class="mono">python3 -m http.server</span> desde la raíz del repositorio— y ' +
          'recargá. Los resultados medidos se indican completos más abajo.',
      en: 'Some browsers block <span class="mono">fetch()</span> of local files over ' +
          '<span class="mono">file://</span>. Serve this directory over HTTP instead — e.g. ' +
          '<span class="mono">python3 -m http.server</span> from the repository root — and ' +
          'reload. The measured results are stated in full further down the page.'
    }
  };

  var lang = 'es';

  function t(key) {
    var entry = I18N[key];
    if (!entry) return key;
    var v = entry[lang];
    if (v === null || v === undefined) v = entry.en;
    return v;
  }

  /* Formatted strings take arguments; t() returns the function for those keys. */
  function tf(key) {
    var fn = t(key);
    if (typeof fn !== 'function') return fn;
    return fn.apply(null, Array.prototype.slice.call(arguments, 1));
  }

  // ------------------------------------------------- theme + language storage

  /* Both preferences live in a cookie scoped to the parent domain as well as in
     localStorage. localStorage is per-origin, so a visitor who chose dark and
     English on santiagomorgado.dev would otherwise arrive at this subdomain and
     get system defaults again — a visible seam in what is meant to read as one
     site. The cookie is what carries the choice across; the inline script in
     index.html reads it before first paint so the page never flashes the wrong
     theme.

     The two names differ on purpose. The cookie is shared with the portfolio,
     so it takes the portfolio's names — `theme` and `lang`. localStorage is
     this origin's alone and keeps the keys this page has always written, so a
     visitor who chose a language here before the two sites shared anything
     still gets it back.

     Anywhere that is not santiagomorgado.dev — a preview URL, localhost,
     file:// — the cookie is set without a domain and is simply host-only.

     Two limits worth knowing. Safari's ITP caps the lifetime of a cookie set
     from script at seven days regardless of the max-age below, so for a Safari
     visitor the two origins fall back to their own localStorage after a week;
     lifting that needs a Set-Cookie header, which static hosting does not give
     us. And when the cookie is gone but localStorage is not, the last choice
     made on THIS origin wins — deliberately, because forgetting it would be
     worse than the rare case where the other origin has since moved on. */
  var PREF_DOMAIN = '.santiagomorgado.dev';
  var THEME_KEY = 'lad-theme';
  var LANG_KEY = 'lad-lang';

  /* First *valid* value wins, not first value present: a cookie holding
     something this page does not understand — stale, truncated, or written by
     something else on the domain — must fall through to localStorage rather
     than mask a real choice made here. */
  function readPref(cookieName, storageKey, valid) {
    var v = null;
    try {
      var m = (document.cookie || '').match('(?:^|; *)' + cookieName + '=([^;]*)');
      if (m) v = decodeURIComponent(m[1]);
    } catch (e) { /* cookies disabled; fall through to localStorage */ }
    if (valid(v)) return v;
    try { v = localStorage.getItem(storageKey); } catch (e) { v = null; }
    return valid(v) ? v : null;
  }

  function isLang(v) { return v === 'es' || v === 'en'; }
  function isTheme(v) { return v === 'dark' || v === 'light'; }

  function savePref(cookieName, storageKey, value) {
    try { localStorage.setItem(storageKey, value); } catch (e) { /* non-fatal */ }
    try {
      var host = location.hostname || '';
      var shared = host === PREF_DOMAIN.slice(1) ||
                   host.slice(-PREF_DOMAIN.length) === PREF_DOMAIN;
      document.cookie = cookieName + '=' + encodeURIComponent(value) +
        '; path=/; max-age=31536000; samesite=lax' +
        (shared ? '; domain=' + PREF_DOMAIN : '') +
        (location.protocol === 'https:' ? '; secure' : '');
    } catch (e) { /* file://, or cookies disabled */ }
  }

  function storedLang() { return readPref('lang', LANG_KEY, isLang); }

  function storeLang(v) { savePref('lang', LANG_KEY, v); }

  // ------------------------------------------------------------------- theme

  /* The toggle used to read the current theme straight off the data-theme
     attribute of <html>. Nothing wrote that attribute until the first click,
     so on a page rendering dark from `prefers-color-scheme` the read came back
     null, the handler took that for "not dark", and wrote data-theme="dark" —
     the theme already on screen. Nothing changed and the click looked lost;
     the second click wrote "light" and worked. Hence: resolve the theme once
     at startup so the attribute always holds a real value, and route every
     read through currentTheme() and every write through applyTheme(). */

  /* The viewer's explicit choice, held here as well as in the cookie and
     localStorage. chooseTheme() swallows their failures, so in a browser that
     blocks both the choice would otherwise be invisible to the
     system-preference listener below, which would then undo it the next time
     the OS switched appearance. */
  var chosenTheme = null;

  function storedTheme() { return readPref('theme', THEME_KEY, isTheme); }

  function chooseTheme(v) {
    chosenTheme = v;
    savePref('theme', THEME_KEY, v);
  }

  function darkMedia() {
    return window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  }

  // An explicit choice outranks the system preference. Pure, so the startup
  // decision is testable without a DOM.
  function resolveTheme(stored, prefersDark) {
    if (stored === 'dark' || stored === 'light') return stored;
    return prefersDark ? 'dark' : 'light';
  }

  function otherTheme(theme) { return theme === 'dark' ? 'light' : 'dark'; }

  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    var btn = $('btn-theme');
    if (btn) btn.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
    var label = $('btn-theme-label');
    if (label) label.textContent = t(theme === 'dark' ? 'ctrl.light' : 'ctrl.dark');
    syncThemeColor(theme);
  }

  /* The browser paints its own chrome from <meta name="theme-color">, and the
     two in the head answer the system preference only. The page resolves its
     theme itself and persists the answer, so a system-light phone showing a
     dark page would otherwise sit under a light bar. Narrowing the two media
     queries to the theme actually on screen is what keeps the bar above the
     viewport in step with the ground below it. */
  function syncThemeColor(theme) {
    var light = $('theme-color-light');
    var night = $('theme-color-dark');
    if (!light || !night) return;
    var dark = theme === 'dark';
    light.setAttribute('media', dark ? 'not all' : 'all');
    night.setAttribute('media', dark ? 'all' : 'not all');
  }

  /* Numbers follow the locale: Spanish uses '.' as thousands separator. */
  function comma(n) {
    var s = String(n).replace(/\B(?=(\d{3})+(?!\d))/g, lang === 'es' ? '.' : ',');
    return s;
  }

  // ------------------------------------------------------------------ helpers

  function fmt(n, d) {
    if (!isFinite(n)) return '—';
    return n.toFixed(d === undefined ? 4 : d);
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

    // On a narrow plot the full label runs past the right edge and is clipped
    // by the page rather than wrapping, so the window range — which <desc>
    // states in full for a screen reader either way — is dropped and the axis
    // keeps its name.
    var at = svgEl('text', {
      class: 'axis-title', x: CH.l, y: d.h - 10
    });
    at.textContent = d.w < 560
      ? t('chart.axis')
      : t('chart.window') + ' ' + vis[0].w + ' → ' + vis[vis.length - 1].w +
        '   ·   ' + t('chart.axis');
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
        cfl.textContent = t('chart.cfCost') + fmt(cfm.precision, 2);
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
    // Only while the threshold has been moved away. At rest the two lines sit
    // on top of each other and the handle already prints "= calibrado", so this
    // label is a second name for the same line — and it lands on the error
    // trace, which reads as a struck-through word rather than as a label.
    var snapped = Math.abs(threshold - calibrated) <= SNAP_EPS;
    if (!snapped) {
      var calibBelow = Math.abs(cy2 - ty) < 14 || threshold > calibrated;
      var cl = svgEl('text', {
        class: 'calib-label', x: CH.l + 6,
        y: calibBelow ? cy2 + 13 : cy2 - 6
      });
      cl.textContent = t('chart.calib');
      g.appendChild(cl);
    }

    // ---- threshold group: hit area, line, handle
    var tg = svgEl('g', {
      class: 'threshold-grp',
      role: 'slider',
      tabindex: '0',
      'aria-label': t('thr.sliderAria'),
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

    var hx = CH.l + plotW + 6;
    // rx 2, like every other corner on the page: the drawings have no
    // rounder one, so neither does the handle (ADR 0005).
    tg.appendChild(svgEl('rect', {
      class: 'focus-ring', x: hx - 3, y: ty - 15, width: 62, height: 30, rx: 2
    }));
    tg.appendChild(svgEl('rect', {
      class: 'threshold-handle', x: hx, y: ty - 12, width: 56, height: 24, rx: 2
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
      st.textContent = t('chart.eqCalib');
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
    return tf('chartDesc',
      Math.max(0, playhead - CHART_WINDOWS + 1), playhead, threshold.toFixed(4),
      fmt(cur.err), t(isAnomalous(cur) ? 'desc.anomalous' : 'desc.benign'),
      windows.length, fmt(m.precision, 3), fmt(m.recall, 3), fmt(m.f1, 3),
      comma(m.alerts), comma(m.fn));
  }

  function valueText() {
    var m = metrics();
    var snapped = Math.abs(threshold - calibrated) <= SNAP_EPS;
    return tf('valuetext', threshold.toFixed(4), snapped,
      fmt(m.precision, 3), fmt(m.recall, 3), fmt(m.f1, 3),
      comma(m.alerts), comma(m.fn), comma(m.attacks));
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
    el.footAbs.textContent = t('stream.absRows') + ' ' +
      comma(abs + newest - WINDOW_ROWS + 1) + '–' + comma(abs + newest);
  }

  // ------------------------------------------------------------------ verdict

  function renderVerdict() {
    var cur = windows[Math.min(playhead, windows.length - 1)];
    var anom = isAnomalous(cur);
    el.verdict.className = 'verdict ' + (anom ? 'verdict--anomalous' : 'verdict--benign');
    el.verdictGlyph.textContent = anom ? '▲' : '·';
    el.verdictText.textContent = t(anom ? 'verdict.anomalous' : 'verdict.benign');
    var delta = cur.err - threshold;
    el.verdictSub.innerHTML =
      t('verdict.error') + ' <b>' + fmt(cur.err) + '</b> · ' + t('verdict.threshold') +
      ' <b>' + fmt(threshold) +
      '</b> · Δ <b>' + (delta >= 0 ? '+' : '') + fmt(delta) + '</b>' +
      (anom ? t('verdict.sentTo') + '<b>' + classOf(cur) + '</b>' +
              (classOf(cur) === 'BENIGN'
                ? ' <span style="opacity:.75">' + t('verdict.disagree') + '</span>' : '')
            : t('verdict.notClassified'));
  }

  // ------------------------------------------------------------------- queue

  /* What kind of alert is this?
     'disagree' is its own case and a common one: the autoencoder flags the
     window, XGBoost looks at it and answers BENIGN. The pipeline has no
     arbiter for that, so the alert reaches the analyst with no attack name.
     Reporting it as a plain false positive would hide the disagreement. */
  function cardKind(w) {
    if (w.unknown) return 'unknown';
    if (w.xgb === 'BENIGN') return 'disagree';
    if (w.truth === 'BENIGN') return 'fp';
    if (w.xgb !== w.truth) return 'misclass';
    return 'ok';
  }

  /* `explain` is false for every card after the first of its kind in the
     queue. The note says why a kind of alert looks the way it does, which is
     worth a paragraph once; eight identical copies of it say nothing new seven
     times, and the queue is where that reads worst — a run of one kind fills
     the section with the same four lines. */
  function buildCard(item, explain) {
    var w = item.w;
    var kind = cardKind(w);
    var li = document.createElement('li');
    li.className = 'incident-card' +
      (kind === 'unknown' ? ' incident-card--unknown' :
       kind === 'misclass' ? ' incident-card--misclass' :
       (kind === 'fp' || kind === 'disagree') ? ' incident-card--fp' : '') +
      (!reduceMotion && item.fresh ? ' incident-card--drop' : '');

    var glyph = kind === 'unknown' ? '?' :
                kind === 'misclass' ? '≠' :
                kind === 'disagree' ? '⁄' :
                kind === 'fp' ? '✕' : '▲';

    var cls;
    if (kind === 'unknown') {
      cls = '<s>' + w.xgb + '</s>' + t('card.unknownTruth') + w.truth + ')';
    } else if (kind === 'misclass') {
      cls = w.xgb + ' <span style="opacity:.7">≠ ' + w.truth + '</span>';
    } else if (kind === 'disagree') {
      cls = t('card.noClass') + ' <span style="opacity:.7">' + t('card.xgbSaysBenign') +
            (w.truth === 'BENIGN' ? '' : t('card.truthIs') + w.truth) + '</span>';
    } else if (kind === 'fp') {
      cls = w.xgb + ' <span style="opacity:.7">' + t('card.actuallyBenign') + '</span>';
    } else {
      cls = w.xgb;
    }

    var note = '';
    if (!explain) {
      /* nothing: the first card of this kind already carries the note */
    } else if (kind === 'unknown') {
      note = '<p class="card-note">' + t('card.noteUnknown') + '</p>';
    } else if (kind === 'misclass') {
      note = '<p class="card-note">' + t('card.noteMisclass') + '</p>';
    } else if (kind === 'disagree') {
      note = '<p class="card-note">' +
             t(w.truth === 'BENIGN' ? 'card.noteDisagreeRight' : 'card.noteDisagreeWrong') +
             '</p>';
    } else if (kind === 'fp') {
      note = '<p class="card-note">' + t('card.noteFp') + '</p>';
    }

    li.innerHTML =
      '<div class="card-top">' +
        '<span class="card-glyph" aria-hidden="true">' + glyph + '</span>' +
        '<span class="card-class">' + cls + '</span>' +
        '<span class="card-err">' + t('queue.err') + ' ' + fmt(w.err) + '</span>' +
      '</div>' +
      '<p class="card-meta">' + t('queue.window') + ' #' + w.w + ' · ' + t('queue.rows') + ' ' +
        (w.end_row - WINDOW_ROWS + 1) + '–' + w.end_row +
        ' · Δ +' + fmt(w.err - threshold) + '</p>' +
      note;
    return li;
  }

  function renderQueue() {
    var frag = document.createDocumentFragment();
    var vis = queue.slice(0, QUEUE_CAP);
    var explained = {};
    for (var i = 0; i < vis.length; i++) {
      var kind = cardKind(vis[i].w);
      var card = buildCard(vis[i], !explained[kind]);
      explained[kind] = true;
      card.style.opacity = DEPTH_OPACITY[i] === undefined ? 0.25 : DEPTH_OPACITY[i];
      vis[i].fresh = false;
      frag.appendChild(card);
    }
    el.queue.innerHTML = '';
    if (!vis.length) {
      var empty = document.createElement('li');
      empty.className = 'queue-empty';
      empty.textContent = tf('queue.empty',
        comma(Math.min(playhead + 1, QUEUE_SCAN)), fmt(threshold));
      el.queue.appendChild(empty);
    } else {
      el.queue.appendChild(frag);
    }
    var m = metrics();
    el.queueMore.textContent = hiddenCount > 0
      ? tf('queue.moreHidden', comma(hiddenCount), comma(m.alerts), fmt(threshold))
      : tf('queue.moreTotal', comma(m.alerts), comma(windows.length), fmt(threshold));
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
             t(anom ? 'a11y.anomalous' : 'a11y.benign') + '</td><td>' +
             (anom ? w.xgb : '—') + '</td><td>' + w.truth + '</td></tr>';
    }
    tb.innerHTML = out;
  }

  // ------------------------------------------------------------ failure panel

  function renderFailures() {
    var m = metrics();
    el.failMissed.textContent = comma(m.fn) + ' / ' + comma(m.attacks);
    el.failMissedBody.innerHTML = tf('fail.missedBody', fmt(threshold), fmt(m.recall, 3));
    // Alerts the classifier refuses to name — the two stages disagreeing.
    var disagree = 0, disagreeWrong = 0;
    for (var i = 0; i < windows.length; i++) {
      var w = windows[i];
      if (w.err > threshold && w.xgb === 'BENIGN') {
        disagree++;
        if (w.truth !== 'BENIGN') disagreeWrong++;
      }
    }
    el.disagreeNote.innerHTML = tf('fail.disagreeNote',
      comma(disagree), comma(m.alerts), disagreeWrong ? comma(disagreeWrong) : 0);

    el.failFp.textContent = comma(m.fp) + ' / ' + comma(m.alerts);
    el.failFpBody.innerHTML = tf('fail.fpBody', fmt(m.precision, 3),
      m.alerts ? Math.round(100 * m.fp / m.alerts) : 0);
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
    bestF1 = best;   // kept so a language switch can re-render this note
    el.tradeoff.innerHTML = tf('tradeoff', fmt(best.f1, 3), fmt(best.t, 3), fmt(gap, 3),
      fmt(computeMetrics(calibrated).f1, 3));
  }

  // --------------------------------------------------------------- apply lang

  /* Walk the static markup and swap in the active language. Elements opt in via
     data-i18n (text), data-i18n-html (markup), or data-i18n-<attr> for
     attributes such as aria-label. Everything dynamic is re-rendered after. */
  function applyLang() {
    // `lang` is what a screen reader and a translator read; `data-lang` is the
    // hook the portfolio's stylesheet uses, kept in step so the two documents
    // are stamped the same way.
    document.documentElement.setAttribute('lang', lang);
    document.documentElement.setAttribute('data-lang', lang);

    var nodes = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].textContent = t(nodes[i].getAttribute('data-i18n'));
    }
    var html = document.querySelectorAll('[data-i18n-html]');
    for (var j = 0; j < html.length; j++) {
      html[j].innerHTML = t(html[j].getAttribute('data-i18n-html'));
    }
    var labelled = document.querySelectorAll('[data-i18n-aria-label]');
    for (var k = 0; k < labelled.length; k++) {
      labelled[k].setAttribute('aria-label', t(labelled[k].getAttribute('data-i18n-aria-label')));
    }
    var titled = document.querySelectorAll('[data-i18n-title]');
    for (var m = 0; m < titled.length; m++) {
      titled[m].textContent = t(titled[m].getAttribute('data-i18n-title'));
    }

    // Static support counts in the metrics table follow the locale separator
    // too, so the table does not disagree with the live numbers above it.
    var sup = document.querySelectorAll('.num-support');
    for (var q = 0; q < sup.length; q++) {
      sup[q].textContent = comma(sup[q].getAttribute('data-num'));
    }

    document.title = t('doc.title');
    var meta = document.querySelector('meta[name="description"]');
    if (meta) meta.setAttribute('content', t('doc.desc'));

    // Controls whose label depends on current state, not just language.
    if (el.btnPlayLabel) el.btnPlayLabel.textContent = t(playing ? 'ctrl.pause' : 'ctrl.play');
    // Re-labels the toggle in the new language; applyTheme() owns it otherwise.
    applyTheme(currentTheme());
    var sw = $('btn-lang');
    if (sw) {
      // Two letters carry no verb, so the accessible label states the action.
      sw.textContent = t('lang.code');
      sw.setAttribute('aria-label', t('lang.switchTo'));
    }
    if (reduceMotion && $('controls-note')) {
      $('controls-note').innerHTML = t('ctrl.noteReduced');
    }
  }

  function setLang(next, announce) {
    if (next !== 'es' && next !== 'en') return;
    lang = next;
    storeLang(next);
    applyLang();
    if (feed) {
      fillProvenance();
      renderStreamHeader();
      renderStream();
      if (bestF1) renderTradeoff(bestF1);
      renderAll();
    }
    var liveEl = el.live || document.getElementById('live-status');
    if (announce && liveEl) {
      liveEl.textContent = t('lang.changed');
      lastAnnounce = Date.now();
    }
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
    var verdictSpeech;
    if (!anom) verdictSpeech = t('live.benign');
    else if (w.xgb === 'BENIGN') verdictSpeech = t('live.disagree');
    else verdictSpeech = tf('live.anomalous', w.xgb);
    el.live.textContent = tf('live.analyzed', w.w, fmt(w.err, 2), verdictSpeech);
  }

  /* §7.4/4 stops autoplay when focus enters the demo region — but the playback
     controls are inside that region, and a mouse press focuses the button and
     fires focusin *before* click. So the stop ran inside the very gesture meant
     to press the button: it set playing=false, then Play/Pause's own click read
     that fresh value and set it back to true. The press cancelled itself out
     and looked dead. It only happened when the button was not already focused,
     which is why a second click always worked and why the keyboard — which
     activates a button that already has focus — never reproduced it.

     The split that fixes it without giving up §7.4/4 is the one the browser
     already draws for us: :focus-visible. Keyboard and assistive-tech focus is
     "visible" (it is what earns a focus ring here, §7.3), and that still stops
     the stream on every control — a user tabbing in is exactly who §7.4/4 is
     for. Focus incidental to a pointer press is not visible, and must not run
     inside the gesture that is pressing the button. Everywhere else in the
     demo the stop is unconditional, as before. */
  function isPlaybackControl(node) {
    return !!(node && node.closest && node.closest('#playback-controls'));
  }

  // null when the browser does not know the selector, so the caller can choose
  // its own fallback rather than silently getting `false`.
  function focusIsVisible(node) {
    try { return !!(node && node.matches && node.matches(':focus-visible')); }
    catch (e) { return null; }
  }

  function shouldStopForFocus(playing, target, visible) {
    if (!playing) return false;
    if (!isPlaybackControl(target)) return true;
    // On the controls: only keyboard/AT focus. Where :focus-visible is
    // unsupported (visible === null) we keep the press working, because a
    // Play button that cannot be pressed is the worse failure.
    return visible === true;
  }

  function setPlaying(on) {
    playing = on;
    if (timer) { clearInterval(timer); timer = null; }
    if (on) timer = setInterval(advance, TICK_MS);
    el.btnPlay.setAttribute('aria-pressed', on ? 'false' : 'true');
    el.btnPlayLabel.textContent = t(on ? 'ctrl.pause' : 'ctrl.play');
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
        el.live.textContent = t('live.snapped');
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
    el.disagreeNote = $('disagree-note');
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
      el.live.textContent = t('live.snapped');
      lastAnnounce = Date.now();
    });
    /* The chart is inline SVG and takes every stroke and fill from demo.css,
       so a theme change reaches it the way it reaches the rest of the page —
       there is nothing to redraw. Hardcoded hex in a canvas call would not
       have that property; this is why the chart is not a canvas. */
    $('btn-theme').addEventListener('click', function () {
      var next = otherTheme(currentTheme());
      applyTheme(next);
      chooseTheme(next);       // has to survive a reload, and reach the portfolio
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

    // §7.4/4: autoplay stops when focus enters the demo region — see
    // shouldStopForFocus for what the playback controls do differently.
    $('demo').addEventListener('focusin', function (evt) {
      if (shouldStopForFocus(playing, evt.target, focusIsVisible(evt.target))) setPlaying(false);
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
                                 comma(meta.absolute_rows[1]) + ' (' + comma(rows.length) +
                                 ' ' + t('prov.flows') + ')';
    $('prov-windows').textContent = comma(windows.length);
    $('prov-shape').textContent = meta.window_size + ' × ' + meta.n_features;
    $('prov-note').textContent = lang === 'es' ? t('prov.noteEs') : meta.note;
    $('bracket-label').textContent = (lang === 'es' ? 'VENTANA t−' : 'WINDOW t−') +
                                     (meta.window_size - 1) + ' → t · ' +
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
    applyLang();   // re-apply now that state-dependent controls exist
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
      $('controls-note').innerHTML = t('ctrl.noteReduced');
    } else {
      setPlaying(true);
    }
  }

  function fail(err) {
    var d = document.getElementById('demo');
    var p = document.createElement('div');
    p.className = 'noscript-note';
    p.innerHTML = '<strong>' + t('load.failStrong') + '</strong> ' + t('load.failBody') +
      ' <span class="mono">(' + (err && err.message ? err.message : err) + ')</span>';
    d.insertBefore(p, d.firstChild);
  }

  // file:// blocks fetch() of local JSON in Chrome. Try fetch, fall back to
  // XHR, which some browsers still allow for same-directory file reads.
  function load() {
    // Resolve language first: a feed that fails to load must still render the
    // static page in the right language.
    lang = storedLang() || 'es';

    /* index.html stamps data-theme in <head> so the first paint is already the
       right theme; recomputing it from the same two inputs here is a no-op,
       and keeps demo.js correct on its own if that inline script ever goes. */
    var mq = darkMedia();
    chosenTheme = storedTheme();
    applyTheme(resolveTheme(chosenTheme, !!(mq && mq.matches)));

    // Follow the system preference only while the viewer has made no choice of
    // their own, so the listener and the toggle can never fight over the theme.
    if (mq) {
      var onScheme = function () {
        if (chosenTheme) return;
        applyTheme(resolveTheme(null, mq.matches));
        if (feed) scheduleRender();
      };
      if (mq.addEventListener) mq.addEventListener('change', onScheme);
      else if (mq.addListener) mq.addListener(onScheme);   // Safari < 14
    }

    applyLang();
    var langBtn = document.getElementById('btn-lang');
    if (langBtn) langBtn.addEventListener('click', function () {
      setLang(lang === 'es' ? 'en' : 'es', true);
    });
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

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', load);
    } else {
      load();
    }
  }

  /* The decisions behind issue #5 are pure, so they are checked by
     `node --test web/tests/demo.test.js`. In a browser `module` is undefined
     and this tail does nothing; the page stays one plain script with no build
     step and no imports, so the directory still opens over file://. */
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      resolveTheme: resolveTheme,
      otherTheme: otherTheme,
      isPlaybackControl: isPlaybackControl,
      shouldStopForFocus: shouldStopForFocus,
      THEME_KEY: THEME_KEY,
      LANG_KEY: LANG_KEY
    };
  }
})();
