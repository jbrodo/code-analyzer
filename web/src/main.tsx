import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/app.css";

const root = document.getElementById("root");
if (root === null) {
  throw new Error("elemento #root assente");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
