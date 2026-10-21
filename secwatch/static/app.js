// "Analyze with Claude" button. Kept in a file: the dashboard's CSP forbids inline scripts.
(function () {
  const box = document.getElementById("claude");
  if (!box) return;
  const run = document.getElementById("claude-run");
  const again = document.getElementById("claude-again");
  const status = document.getElementById("claude-status");
  const out = document.getElementById("claude-out");
  const promptBox = document.getElementById("claude-prompt");

  function showPrompt(text) {
    promptBox.value = text;
    promptBox.hidden = false;
    promptBox.select();
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject())
      .then(() => { status.textContent = box.dataset.copied; })
      .catch(() => { status.textContent = ""; });
  }

  async function analyze(force) {
    run.disabled = true;
    if (again) again.disabled = true;
    status.textContent = box.dataset.mode === "api" ? box.dataset.working : "";
    try {
      // From location.origin: a page opened as http://user:pass@host/ cannot fetch a relative URL.
      const url = location.origin + "/api/analyze?day=" + encodeURIComponent(box.dataset.day) + (force ? "&force=1" : "");
      const res = await fetch(url, { method: "POST", headers: { "X-Secwatch": "1" }, credentials: "same-origin" });
      const data = await res.json();
      if (data.mode === "prompt") {
        showPrompt(data.prompt);
      } else if (data.mode === "api") {
        out.textContent = data.text;  // plain text: model output is never inserted as HTML
        out.hidden = false;
        status.textContent = data.cached ? box.dataset.cached + " " + data.created : data.model;
        if (again) again.hidden = false;
      } else {
        status.textContent = (data.error || box.dataset.failed);
        if (data.prompt) showPrompt(data.prompt);
      }
    } catch (e) {
      status.textContent = box.dataset.failed;
    } finally {
      run.disabled = false;
      if (again) again.disabled = false;
    }
  }

  run.addEventListener("click", () => analyze(false));
  if (again) again.addEventListener("click", () => analyze(true));
})();
