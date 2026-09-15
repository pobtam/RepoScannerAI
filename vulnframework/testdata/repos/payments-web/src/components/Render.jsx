import React from "react";

// Deliberate defect: rendering caller-supplied HTML. semgrep reports this as a
// cross-site scripting risk.
export default function Render(props) {
  return (
    <div className="body">
      <div dangerouslySetInnerHTML={{ __html: props.body }} />
    </div>
  );
}
