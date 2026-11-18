import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { applyCspNonce } from "./csp";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/app.css";

applyCspNonce(document); // prima di ogni render: gli stili che le librerie iniettano portano il nonce

const root = document.getElementById("root");
if (root === null) {
  throw new Error("elemento #root assente");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
