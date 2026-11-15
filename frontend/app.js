(() => {
  "use strict";

  const MAX_LEN = 8000;
  const TIMEOUT_MS = 30000;

  const DEV_BACKEND = "http://127.0.0.1:8000";

  const form = document.getElementById("check-form");
  const input = document.getElementById("text");
  const count = document.getElementById("count");
  const submitBtn = document.getElementById("submit");
  const clearBtn = document.getElementById("clear");
  const result = document.getElementById("result");
  const verdictEl = document.getElementById("verdict");
  const detailEl = document.getElementById("detail");

  
  const VIEW = {
    "scam": {
      state: "scam",
      title: "Scam",
      detail: "Do not click links, reply, or send money, codes or personal details.",
    },
    "not scam": {
      state: "safe",
      title: "Not scam",
      detail: "No scam detected. Still be careful with unexpected requests for money or information.",
    },
  };

  
  function apiUrl(path) {
    const { protocol, hostname, port } = window.location;
    if (protocol === "file:") return null;
    const isLocal = hostname === "localhost" || hostname === "127.0.0.1";
    if (isLocal && port !== "8000") return DEV_BACKEND + path;
    return path;
  }

  function render(state, title, detail) {
    result.hidden = false;
    result.dataset.state = state;
    verdictEl.textContent = title;
    detailEl.textContent = detail;
  }

  function setBusy(busy) {
    submitBtn.disabled = busy;
    clearBtn.disabled = busy;
    submitBtn.textContent = busy ? "Checking…" : "Check";
  }

  function updateCount() {
    count.textContent = input.value.length + " / " + MAX_LEN;
  }

  input.addEventListener("input", updateCount);

  clearBtn.addEventListener("click", () => {
    input.value = "";
    result.hidden = true;
    updateCount();
    input.focus();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const text = input.value.trim();
    if (!text) {
      render("error", "Nothing to check", "Paste some text first.");
      return;
    }
    if (text.length > MAX_LEN) {
      render("error", "Too long", "Keep it under " + MAX_LEN + " characters.");
      return;
    }

    const url = apiUrl("/classify");
    if (!url) {
      render(
        "error",
        "Open it through the server",
        "Start the backend and go to " + DEV_BACKEND + " instead of opening this file directly."
      );
      return;
    }

    setBusy(true);
    result.hidden = true;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ text }),
        signal: controller.signal,
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });

      if (res.status === 429) {
        render("error", "Too many requests", "Wait a minute and try again.");
        return;
      }
      if (res.status === 413 || res.status === 422) {
        render("error", "Invalid input", "The text was empty or too long.");
        return;
      }
      if (!res.ok) {
        console.error("Backend returned", res.status);
        render("error", "Could not check", "The server had a problem. Try again later.");
        return;
      }

      const data = await res.json();
      const view = Object.prototype.hasOwnProperty.call(VIEW, data.verdict)
        ? VIEW[data.verdict]
        : null;

      if (!view) {
        render("error", "Unexpected response", "Try again.");
        return;
      }
      render(view.state, view.title, view.detail);
    } catch (err) {
      console.error("Request failed:", err);
      const timedOut = err && err.name === "AbortError";
      render(
        "error",
        timedOut ? "Timed out" : "Cannot reach the server",
        timedOut
          ? "The request took too long. Try again."
          : "Server Loading issue"
      );
    } finally {
      clearTimeout(timer);
      setBusy(false);
    }
  });

  updateCount();
})();