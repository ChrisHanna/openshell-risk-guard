const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const htmlPath = path.join(__dirname, "..", "src", "operator_ui.html");
const html = fs.readFileSync(htmlPath, "utf8");
assert.ok(html.includes('id="adp-toggle-auto"'), "Missing #adp-toggle-auto button in operator_ui.html");
assert.ok(html.includes("bound by ${binding.principal_kind}:${binding.principal_subject}"), "The Runs table must show who bound each sandbox");
assert.ok(!(/\r\n/.test(html) && /[^\r]\n/.test(html)), "operator_ui.html must not mix CRLF and LF line endings");

const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "Missing embedded <script> in operator_ui.html");
assert.doesNotThrow(() => new vm.Script(scriptMatch[1], { filename: "operator_ui.html" }), "Embedded JS failed syntax check");
execFileSync(process.execPath, ["--check"], { input: scriptMatch[1] });

const start = html.indexOf("function validateAdaptiveView(");
const end = html.indexOf("\nfunction adaptiveContexts(", start);
assert.ok(start >= 0 && end > start);
const constants = ["adaptiveScopes", "adaptiveMinimumKeys"].map(name => {
  const match = html.match(new RegExp(`const ${name} = [^;]+;`));
  assert.ok(match);
  return match[0];
}).join("\n");
const context = vm.createContext({});
vm.runInContext(constants + "\n" + html.slice(start, end), context);

const view = {
  agent_id: "native-ui-contract",
  guardrails_revision: 0,
  coverage: "network_metadata_only",
  minimums: {
    training_runs: 20, training_requests: 200,
    holdout_runs: 5, holdout_requests: 50,
    shadow_runs: 5, shadow_requests: 50,
  },
  runs: [{
    run_id: "fresh", context_id: "context", agent_revision: "v1",
    task_profile: "review", ended_at_ms: null, bound_sandboxes: 1,
    capture_eligible: true, capture_blocker: null,
  }],
  sessions: [], models: [], audit: [],
};
const validate = value => context.validateAdaptiveView(value, view.agent_id);
assert.doesNotThrow(() => validate(view));
assert.doesNotThrow(() => validate({ ...view, auto_shadow_learning: true }));
assert.doesNotThrow(() => validate({ ...view, auto_shadow_learning: false }));
for (const invalidAuto of ["yes", 1, 0, null, {}, []]) {
  assert.throws(() => validate({ ...view, auto_shadow_learning: invalidAuto }), /incomplete, unsupported/);
}
for (const count of [0, 2]) {
  assert.doesNotThrow(() => validate({
    ...view, runs: [{ ...view.runs[0], bound_sandboxes: count, capture_eligible: false }],
  }));
}
for (const invalid of [[], ["sandbox"], -1, 1.5, null, "1"]) {
  assert.throws(() => validate({
    ...view, runs: [{ ...view.runs[0], bound_sandboxes: invalid }],
  }), /incomplete, unsupported/);
}
console.log("Adaptive UI native binding-count and auto-shadow-learning contract passed.");
assert.ok(html.includes('id="detections-restrictions-card"'), "Missing #detections-restrictions-card in operator_ui.html");
assert.ok(html.includes('id="cfg-restrictions-card"'), "Missing #cfg-restrictions-card in operator_ui.html");
assert.ok(html.includes("/restrictions/clear"), "Missing restriction clear endpoint wiring in operator_ui.html");

