// Deliberate defect: evaluating a name built by concatenation. semgrep reports
// this as code injection.
export function dispatch(name) {
  return eval("handler_" + name)();
}
