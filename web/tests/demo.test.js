/* Regression tests for issue #5 — "Play/Pause, Step and the theme toggle
 * sometimes need a second click".
 *
 * Two separate bugs sat behind that report, and both live in a decision that
 * can be stated without a DOM. demo.js exports those decisions under
 * `module.exports` when it is required from Node (in the browser `module` is
 * undefined and the export tail is skipped), so these run with no toolchain:
 *
 *     node --test web/tests/demo.test.js
 */
'use strict';

var test = require('node:test');
var assert = require('node:assert');

var demo = require('../demo.js');

// A stand-in for an element, matching only the selectors it is told to match.
function node(matches) {
  return {
    closest: function (sel) { return matches.indexOf(sel) === -1 ? null : { sel: sel }; }
  };
}

var CONTROL = node(['#playback-controls']);
var CHART = node(['.threshold-grp']);

// ---------------------------------------------------------------- playback

test('a pointer press on the playback controls does not stop playback', function () {
  // The bug: focusin fires on the mouse press that focuses Play/Pause, before
  // click. Stopping playback there let the button's own click handler read the
  // freshly-cleared flag and set it straight back — the gesture cancelled
  // itself out and the click looked lost. Pointer focus is not :focus-visible.
  assert.strictEqual(demo.shouldStopForFocus(true, CONTROL, false), false);
});

test('tabbing onto the playback controls still stops playback (§7.4/4)', function () {
  // Keyboard and assistive tech are exactly who the focus stop is for, and
  // they never hit the bug: activating a button requires focus already on it.
  assert.strictEqual(demo.shouldStopForFocus(true, CONTROL, true), true);
});

test('focus entering the rest of the demo stops playback however it arrived', function () {
  assert.strictEqual(demo.shouldStopForFocus(true, CHART, true), true);
  assert.strictEqual(demo.shouldStopForFocus(true, CHART, false), true);
  assert.strictEqual(demo.shouldStopForFocus(true, CHART, null), true);
});

test('focus entering the demo while already paused is a no-op', function () {
  assert.strictEqual(demo.shouldStopForFocus(false, CHART, true), false);
  assert.strictEqual(demo.shouldStopForFocus(false, CONTROL, true), false);
});

test('an unclassifiable focus target keeps the accessibility stop', function () {
  // Only the controls bar gets the narrower rule. Anything we cannot place —
  // no element, no closest() — falls back to stopping, so a target we fail to
  // recognise loses autoplay rather than silently losing §7.4/4.
  assert.strictEqual(demo.shouldStopForFocus(true, null, false), true);
  assert.strictEqual(demo.shouldStopForFocus(true, {}, false), true);
});

test('a browser without :focus-visible keeps the controls pressable', function () {
  // focusIsVisible() reports null when it cannot answer. A Play button that
  // cannot be pressed is a worse failure than a stream that keeps running.
  assert.strictEqual(demo.shouldStopForFocus(true, CONTROL, null), false);
});

// ------------------------------------------------------------------- theme

test('with no stored choice the system preference decides', function () {
  assert.strictEqual(demo.resolveTheme(null, true), 'dark');
  assert.strictEqual(demo.resolveTheme(null, false), 'light');
});

test('a stored choice survives a reload and outranks the system preference', function () {
  assert.strictEqual(demo.resolveTheme('light', true), 'light');
  assert.strictEqual(demo.resolveTheme('dark', false), 'dark');
});

test('junk in storage falls back to the system preference', function () {
  assert.strictEqual(demo.resolveTheme('', true), 'dark');
  assert.strictEqual(demo.resolveTheme('DARK', false), 'light');
  assert.strictEqual(demo.resolveTheme(undefined, true), 'dark');
});

test('one toggle always changes the theme, from every starting point', function () {
  // The bug: the toggle read data-theme off <html>, which nothing had written
  // yet. On a page rendering dark from prefers-color-scheme that read as
  // "not dark", so the first click wrote the theme already on screen and did
  // nothing visible. Resolving the theme up front makes every start point real.
  [null, 'light', 'dark'].forEach(function (stored) {
    [true, false].forEach(function (prefersDark) {
      var current = demo.resolveTheme(stored, prefersDark);
      assert.ok(current === 'light' || current === 'dark');
      assert.notStrictEqual(demo.otherTheme(current), current);
    });
  });
});

test('two toggles return to where they started', function () {
  assert.strictEqual(demo.otherTheme(demo.otherTheme('dark')), 'dark');
  assert.strictEqual(demo.otherTheme(demo.otherTheme('light')), 'light');
});

// ------------------------------------------------- index.html's <head> copy

/* The theme has to be stamped before first paint, so index.html carries its
   own copy of the resolution in an inline <head> script — demo.js loads at the
   end of <body>, far too late. Two copies of one rule drift silently: the head
   script would paint one theme and load() would repaint the other, which is
   the exact flash the inline script exists to prevent. So run that copy here,
   against stubs, and hold it to resolveTheme()'s answer for every input. */

function runHeadScript(stored, prefersDark, storageThrows) {
  var html = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'index.html'), 'utf8');
  var m = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(m, 'index.html should carry an inline head script');

  var stamped = null;
  var stubs = {
    localStorage: {
      getItem: function (k) {
        if (storageThrows) throw new Error('storage blocked');
        return k === demo.THEME_KEY ? stored : null;
      }
    },
    matchMedia: function (q) { return { matches: q.indexOf('dark') !== -1 && prefersDark }; },
    document: {
      documentElement: {
        setAttribute: function (k, v) { if (k === 'data-theme') stamped = v; }
      }
    }
  };
  stubs.window = stubs;
  new Function('window', 'document', 'localStorage',
    m[1])(stubs, stubs.document, stubs.localStorage);
  return stamped;
}

test("index.html's head script agrees with resolveTheme on every input", function () {
  [null, 'light', 'dark', '', 'DARK', 'sepia'].forEach(function (stored) {
    [true, false].forEach(function (prefersDark) {
      assert.strictEqual(
        runHeadScript(stored, prefersDark, false),
        demo.resolveTheme(stored, prefersDark),
        'stored=' + JSON.stringify(stored) + ' prefersDark=' + prefersDark);
    });
  });
});

test("index.html's head script survives blocked storage", function () {
  // Privacy modes throw on localStorage access. The page must still paint.
  assert.strictEqual(runHeadScript(null, true, true), 'dark');
  assert.strictEqual(runHeadScript(null, false, true), 'light');
});

test('the head script reads the key demo.js writes', function () {
  var html = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'index.html'), 'utf8');
  assert.ok(html.indexOf("'" + demo.THEME_KEY + "'") !== -1,
    'the inline script should use THEME_KEY (' + demo.THEME_KEY + ')');
});
