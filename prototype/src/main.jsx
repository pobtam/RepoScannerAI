import React from "react";
import { createRoot } from "react-dom/client";
import App from "../report-browser-prototype.jsx";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
