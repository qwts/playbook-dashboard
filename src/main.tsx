import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./fonts.css";
import { registerAuthServiceWorker } from "./lib/auth";
import "./styles.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("Missing #root");
}

void registerAuthServiceWorker();

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
