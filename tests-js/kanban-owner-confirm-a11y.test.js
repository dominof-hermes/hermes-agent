import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const bundle = readFileSync(
  resolve(import.meta.dirname, "../plugins/kanban/dashboard/dist/index.js"),
  "utf8",
);
const start = bundle.indexOf("function trapDialogTabKey(");
const end = bundle.indexOf("\n\n  function OwnerDecisionDialog", start);
if (start < 0 || end < 0) throw new Error("trapDialogTabKey not found");
const source = bundle.slice(start, end).trim();

function extractFunction(name, nextMarker) {
  const functionStart = bundle.indexOf(`function ${name}(`);
  const functionEnd = bundle.indexOf(nextMarker, functionStart);
  if (functionStart < 0 || functionEnd < 0) throw new Error(`${name} not found`);
  return bundle.slice(functionStart, functionEnd).trim();
}

function harness(activeElement, nodes) {
  const document = { activeElement };
  const trap = new Function("document", `${source}; return trapDialogTabKey;`)(document);
  const dialog = {
    focused: false,
    focus() { this.focused = true; },
    querySelectorAll() { return nodes; },
  };
  return { trap, dialog };
}

function node() {
  return {
    offsetParent: {},
    focused: false,
    focus() { this.focused = true; },
  };
}

function tabEvent(shiftKey = false) {
  return {
    key: "Tab",
    shiftKey,
    prevented: false,
    preventDefault() { this.prevented = true; },
  };
}

describe("Owner Confirm decision modal focus trap", () => {
  it("wraps Tab from the last control to the first", () => {
    const first = node();
    const last = node();
    const { trap, dialog } = harness(last, [first, last]);
    const event = tabEvent(false);

    assert.equal(trap(dialog, event), true);
    assert.equal(event.prevented, true);
    assert.equal(first.focused, true);
  });

  it("wraps Shift+Tab from the first control to the last", () => {
    const first = node();
    const last = node();
    const { trap, dialog } = harness(first, [first, last]);
    const event = tabEvent(true);

    assert.equal(trap(dialog, event), true);
    assert.equal(event.prevented, true);
    assert.equal(last.focused, true);
  });

  it("keeps focus in an empty dialog", () => {
    const { trap, dialog } = harness({}, []);
    const event = tabEvent(false);

    assert.equal(trap(dialog, event), true);
    assert.equal(event.prevented, true);
    assert.equal(dialog.focused, true);
  });
});

describe("Owner Confirm failure announcement", () => {
  it("returns live-region text without interpreting hostile markup", () => {
    const parseSource = extractFunction(
      "parseApiErrorMessage",
      "\n\n  function ownerDecisionFailureAnnouncement",
    );
    const failureSource = extractFunction(
      "ownerDecisionFailureAnnouncement",
      "\n\n  // Order matches",
    );
    const announce = new Function(
      `${parseSource}; ${failureSource}; return ownerDecisionFailureAnnouncement;`,
    )();
    const hostile = '<img src=x onerror="globalThis.pwned=true">';

    const message = announce(new Error(`500: {"detail":${JSON.stringify(hostile)}}`));

    assert.equal(message, `대표 승인 결정 실패: ${hostile}`);
    assert.equal(typeof message, "string");
    assert.equal(globalThis.pwned, undefined);
    assert.match(bundle, /setOwnerDecisionAnnouncement\(failureAnnouncement\)/);
    assert.match(bundle, /setTimeout\(function \(\) \{[\s\S]*?\}, 6000\);/);
    assert.match(bundle, /\}, ownerDecisionAnnouncement\)/);
  });
});
