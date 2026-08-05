import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import "./lib/i18n";
import { setAuthTokenGetter } from "@workspace/api-client-react";
import { getOrCreateToken } from "@/lib/auth-token";

setAuthTokenGetter(getOrCreateToken);

createRoot(document.getElementById("root")!).render(<App />);
