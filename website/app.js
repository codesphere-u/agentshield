(function () {
  "use strict";

  const toastEl = document.getElementById("toast");
  let toastTimer = null;

  function showToast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add("visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(function () {
      toastEl.classList.remove("visible");
    }, 2200);
  }

  function copyText(text) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () {
          showToast("Copied to clipboard");
        },
        function (err) {
          console.warn("Clipboard write unavailable:", err);
          showToast("Copy command ready above");
        }
      );
    } else {
      showToast("Copy command ready above");
    }
  }

  // Split CTA popover & install switcher
  const mainCopyBtn = document.getElementById("copy-main-cmd");
  const menuBtn = document.getElementById("cta-menu-btn");
  const popover = document.getElementById("cta-popover");
  const popCmdText = document.getElementById("pop-cmd-text");
  const mainCaption = document.getElementById("main-cmd-caption");
  const popCopyBtn = document.getElementById("pop-copy-btn");

  if (mainCopyBtn) {
    mainCopyBtn.addEventListener("click", function () {
      copyText(mainCopyBtn.getAttribute("data-copy") || "");
    });
  }

  if (menuBtn && popover) {
    menuBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      const open = popover.classList.toggle("open");
      menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", function (ev) {
      if (popover.classList.contains("open") && !popover.contains(ev.target) && ev.target !== menuBtn) {
        popover.classList.remove("open");
        menuBtn.setAttribute("aria-expanded", "false");
      }
    });
  }

  document.querySelectorAll("[data-pop-cmd]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll("[data-pop-cmd]").forEach(function (b) {
        b.classList.remove("active");
      });
      btn.classList.add("active");
      const cmd = btn.getAttribute("data-pop-cmd") || "";
      if (popCmdText) popCmdText.textContent = cmd;
      if (mainCaption) mainCaption.textContent = "$ " + cmd;
      if (mainCopyBtn) mainCopyBtn.setAttribute("data-copy", cmd);
    });
  });

  if (popCopyBtn && popCmdText) {
    popCopyBtn.addEventListener("click", function () {
      copyText(popCmdText.textContent || "");
    });
  }

  document.querySelectorAll("[data-preview]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const target = btn.getAttribute("data-preview");
      document.querySelectorAll("[data-preview]").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      document.querySelectorAll("[data-preview-pane]").forEach(function (pane) {
        pane.hidden = pane.getAttribute("data-preview-pane") !== target;
      });
    });
  });

  document.querySelectorAll("[data-copy-target]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const parent = btn.closest(".doc-codeblock");
      const pre = parent ? parent.querySelector("pre") : null;
      if (pre) copyText(pre.textContent || "");
    });
  });

  document.querySelectorAll("[data-tab]").forEach(function (tab) {
    tab.addEventListener("click", function () {
      const card = tab.closest(".handy-card");
      if (!card) return;
      const target = tab.getAttribute("data-tab");
      card.querySelectorAll("[data-tab]").forEach(function (t) {
        t.classList.toggle("active", t === tab);
      });
      card.querySelectorAll("[data-tab-pane]").forEach(function (p) {
        p.hidden = p.getAttribute("data-tab-pane") !== target;
      });
    });
  });

  // Docs navigation & pagination
  const docSections = Array.from(document.querySelectorAll("[data-doc-section]"));
  const docNavBtns = Array.from(document.querySelectorAll("[data-doc-target]"));
  const docSubrails = Array.from(document.querySelectorAll("[data-doc-subrail]"));
  const prevBtn = document.getElementById("doc-prev-btn");
  const nextBtn = document.getElementById("doc-next-btn");
  const prevLabel = document.getElementById("doc-prev-label");
  const nextLabel = document.getElementById("doc-next-label");
  const docTitles = {
    install: "Getting Started",
    sdk: "Python SDK & Adapters",
    ledger: "Audit Ledger",
    server: "FastAPI Security Lab"
  };

  function activateDoc(key) {
    if (!docSections.length) return;
    const valid = docSections.some(function (s) {
      return s.getAttribute("data-doc-section") === key;
    });
    const activeKey = valid ? key : docSections[0].getAttribute("data-doc-section");
    docSections.forEach(function (s) {
      s.hidden = s.getAttribute("data-doc-section") !== activeKey;
    });
    docNavBtns.forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-doc-target") === activeKey);
    });
    docSubrails.forEach(function (sr) {
      sr.classList.toggle("open", sr.getAttribute("data-doc-subrail") === activeKey);
    });
    const keys = docSections.map(function (s) {
      return s.getAttribute("data-doc-section");
    });
    const idx = keys.indexOf(activeKey);
    if (prevBtn && prevLabel) {
      prevBtn.hidden = idx <= 0;
      if (idx > 0) prevLabel.textContent = docTitles[keys[idx - 1]] || keys[idx - 1];
      prevBtn.dataset.stepKey = idx > 0 ? keys[idx - 1] : "";
    }
    if (nextBtn && nextLabel) {
      nextBtn.hidden = idx < 0 || idx >= keys.length - 1;
      if (idx >= 0 && idx < keys.length - 1) nextLabel.textContent = docTitles[keys[idx + 1]] || keys[idx + 1];
      nextBtn.dataset.stepKey = idx >= 0 && idx < keys.length - 1 ? keys[idx + 1] : "";
    }
  }

  docNavBtns.forEach(function (b) {
    b.addEventListener("click", function () {
      activateDoc(b.getAttribute("data-doc-target"));
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });

  if (prevBtn) {
    prevBtn.addEventListener("click", function () {
      if (prevBtn.dataset.stepKey) {
        activateDoc(prevBtn.dataset.stepKey);
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    });
  }
  if (nextBtn) {
    nextBtn.addEventListener("click", function () {
      if (nextBtn.dataset.stepKey) {
        activateDoc(nextBtn.dataset.stepKey);
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    });
  }
  if (docSections.length) activateDoc("install");

  // OWASP matrix filter (rules.html)
  const rulesSearch = document.getElementById("rules-search");
  const rulesStage = document.getElementById("rules-stage");
  const rulesRows = Array.from(document.querySelectorAll("#rules-tbody tr"));

  function filterMatrix() {
    if (!rulesRows.length) return;
    const q = (rulesSearch ? rulesSearch.value : "").trim().toLowerCase();
    const stage = rulesStage ? rulesStage.value : "ALL";
    rulesRows.forEach(function (row) {
      const rStage = row.getAttribute("data-stage") || "";
      const txt = (row.textContent || "").toLowerCase();
      row.hidden = !((stage === "ALL" || rStage === stage) && (!q || txt.indexOf(q) !== -1));
    });
  }

  if (rulesSearch) rulesSearch.addEventListener("input", filterMatrix);
  if (rulesStage) rulesStage.addEventListener("change", filterMatrix);

  // Interactive Security Studio (studio.html)
  document.querySelectorAll("[data-studio-tab]").forEach(function (tab) {
    tab.addEventListener("click", function () {
      const target = tab.getAttribute("data-studio-tab");
      document.querySelectorAll("[data-studio-tab]").forEach(function (t) {
        t.classList.toggle("active", t === tab);
      });
      document.querySelectorAll("[data-studio-panel]").forEach(function (p) {
        p.classList.toggle("active", p.getAttribute("data-studio-panel") === target);
      });
    });
  });

  const payloadBox = document.getElementById("as-payload");
  const presetsEl = document.getElementById("agentshield-studio-presets");
  let presets = {};
  if (presetsEl) {
    try {
      presets = JSON.parse(presetsEl.textContent || "{}");
    } catch (err) {
      console.warn("Unable to parse AgentShield studio presets:", err);
    }
  }

  function evaluatePayload() {
    if (!payloadBox) return;
    const raw = payloadBox.value || "";
    const findings = [];
    let sanitized = raw;

    const skRe = new RegExp("\\b" + "sk" + "-[a-zA-Z0-9-]{16,}\\b", "g");
    const awsRe = new RegExp("\\b" + "AKI" + "A[0-9A-Z]{16}\\b", "g");
    const scriptRe = new RegExp("<" + "script[^>]*>[\\s\\S]*?<\\/" + "script>", "gi");

    if (/ignore all previous/i.test(raw) || /reveal the developer prompt/i.test(raw)) {
      findings.push({ risk: "CRITICAL", owasp: "LLM01:2026", title: "Direct prompt instruction override detected" });
    }
    if (/<!--[\s\S]*SYSTEM:/i.test(raw)) {
      findings.push({ risk: "CRITICAL", owasp: "LLM08:2026", title: "Hidden HTML comment instruction in RAG context" });
    }
    if (skRe.test(raw) || awsRe.test(raw)) {
      findings.push({ risk: "CRITICAL", owasp: "LLM02:2026", title: "Live API or cloud key detected in egress output" });
      sanitized = sanitized.replace(skRe, "[REDACTED_API_KEY]").replace(awsRe, "[REDACTED_AWS_KEY]");
    }
    if (scriptRe.test(raw)) {
      findings.push({ risk: "HIGH", owasp: "LLM05:2026", title: "Executable script payload stripped from output" });
      sanitized = sanitized.replace(scriptRe, "[REDACTED_XSS_PAYLOAD]");
    }

    const decEl = document.getElementById("as-decision");
    const riskEl = document.getElementById("as-risk");
    const cntEl = document.getElementById("as-count");
    const sanEl = document.getElementById("as-sanitized");
    const listEl = document.getElementById("as-findings");
    const redEl = document.getElementById("as-redacted");

    const blocked = findings.length > 0;
    const topRisk = findings.some(function (f) { return f.risk === "CRITICAL"; })
      ? "CRITICAL"
      : findings.length ? "HIGH" : "NONE";

    if (decEl) decEl.textContent = blocked ? "BLOCK / REDACT" : "ALLOW";
    if (riskEl) riskEl.textContent = topRisk;
    if (cntEl) cntEl.textContent = String(findings.length);
    if (sanEl) sanEl.textContent = sanitized !== raw ? "REDACTED" : "CLEAN";
    if (redEl) redEl.textContent = sanitized;

    if (listEl) {
      listEl.innerHTML = "";
      if (!findings.length) {
        const ok = document.createElement("div");
        ok.className = "rw-item";
        const sp = document.createElement("span");
        sp.textContent = "PASS · OWASP CLEAN";
        const p = document.createElement("p");
        p.textContent = "Zero injection signatures, secrets, or unsafe HTML payloads detected.";
        ok.appendChild(sp);
        ok.appendChild(p);
        listEl.appendChild(ok);
      } else {
        findings.forEach(function (f) {
          const div = document.createElement("div");
          div.className = "rw-item warn-border";
          const sp = document.createElement("span");
          sp.textContent = f.owasp + " · " + f.risk;
          const p = document.createElement("p");
          p.textContent = f.title;
          div.appendChild(sp);
          div.appendChild(p);
          listEl.appendChild(div);
        });
      }
    }
  }

  document.querySelectorAll("[data-preset]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const key = btn.getAttribute("data-preset") || "";
      document.querySelectorAll("[data-preset]").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      if (payloadBox && presets[key]) {
        payloadBox.value = presets[key];
        evaluatePayload();
      }
    });
  });

  if (payloadBox) {
    if (presets.override) payloadBox.value = presets.override;
    payloadBox.addEventListener("input", evaluatePayload);
    evaluatePayload();
  }

  // Tool firewall simulator
  const toolName = document.getElementById("tool-name");
  const toolSource = document.getElementById("tool-source");
  const toolArg = document.getElementById("tool-arg");
  const toolOut = document.getElementById("tool-verdicts");

  const TOOL_DEFAULTS = {
    http_request: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    read_file: "/workspace/../../etc/passwd",
    run_shell: "ls -la && rm -rf /tmp/prod",
    sql_query: "SELECT * FROM users; DROP TABLE audit_logs;--",
    wire_transfer: "{\"amount_usd\": 5000, \"recipient\": \"vendor_042\"}"
  };

  function evaluateTool() {
    if (!toolName || !toolArg || !toolOut) return;
    const t = toolName.value;
    const s = toolSource ? toolSource.value : "direct_user";
    const arg = toolArg.value || "";
    const msgs = [];

    if (s !== "direct_user" && (t === "run_shell" || t === "wire_transfer" || t === "http_request")) {
      msgs.push({ fail: true, title: "LLM08:2026 · DENY", body: "Untrusted context (" + s + ") cannot invoke privileged tool " + t + "." });
    }
    if (t === "http_request" && /(169\.254\.169\.254|127\.0\.|10\.|192\.168\.|file:\/\/)/i.test(arg)) {
      msgs.push({ fail: true, title: "ASI02:2026 · SSRF BLOCKED", body: "Target targets cloud metadata, RFC1918 private network, or local file scheme." });
    }
    if (t === "read_file" && /(\.\.|\.env|id_rsa|\/etc\/passwd)/i.test(arg)) {
      msgs.push({ fail: true, title: "ASI02:2026 · PATH TRAVERSAL BLOCKED", body: "Requested path escapes workspace sandbox or accesses restricted credential file." });
    }
    if (t === "run_shell" && /(;|&&|\|\||rm\s+-rf)/i.test(arg)) {
      msgs.push({ fail: true, title: "ASI02:2026 · SHELL CHAINING BLOCKED", body: "Command chaining operator or destructive rm flag blocked by deep inspector." });
    }
    if (t === "sql_query" && /;\s*(DROP|DELETE|ALTER|TRUNCATE)\b/i.test(arg)) {
      msgs.push({ fail: true, title: "ASI02:2026 · STACKED SQLI BLOCKED", body: "Destructive stacked DDL/DML statement prohibited." });
    }
    if (t === "wire_transfer" && s === "direct_user") {
      msgs.push({ fail: false, title: "LLM06:2026 · REQUIRE_APPROVAL", body: "Pauses transaction for mandatory human-in-the-loop approval callback." });
    }
    if (!msgs.length) {
      msgs.push({ fail: false, title: "ALLOW · SANDBOX VERIFIED", body: "Arguments satisfy workspace and protocol allowlists." });
    }

    toolOut.innerHTML = "";
    msgs.forEach(function (m) {
      const div = document.createElement("div");
      div.className = "rw-item" + (m.fail ? " warn-border" : "");
      const sp = document.createElement("span");
      sp.textContent = m.title;
      const p = document.createElement("p");
      p.textContent = m.body;
      div.appendChild(sp);
      div.appendChild(p);
      toolOut.appendChild(div);
    });
  }

  if (toolName && toolArg) {
    toolName.addEventListener("change", function () {
      if (TOOL_DEFAULTS[toolName.value]) toolArg.value = TOOL_DEFAULTS[toolName.value];
      evaluateTool();
    });
    if (toolSource) toolSource.addEventListener("change", evaluateTool);
    toolArg.addEventListener("input", evaluateTool);
    evaluateTool();
  }

  const sdkCopyBtn = document.getElementById("sdk-copy-btn");
  const sdkOut = document.getElementById("sdk-output");
  if (sdkCopyBtn && sdkOut) {
    sdkCopyBtn.addEventListener("click", function () {
      copyText(sdkOut.textContent || "");
    });
  }
})();
