const $ = (id) => document.getElementById(id);

const TRUSTED_DOMAINS = [
  "edu",
  "k12",
  "jordandistrict.org",
  "schooldistrict",
  "gandt.jordandistrict.org",
  "cogat.com"
];
const analyzeBtn = $("analyzeBtn");
const status = $("status");
const hint = $("hint");
const errorBox = $("error");

const verdictPill = $("verdictPill");
const reason1 = $("reason1");
const reason2 = $("reason2");

const providerEl = $("provider");
const senderDomainEl = $("senderDomain");
const linkDomainsEl = $("linkDomains");

const emlFile = document.getElementById("emlFile");

function parseEmlBasic(raw) {
  // Separar headers y body
  const parts = raw.split(/\r?\n\r?\n/);
  const headersRaw = parts[0] || "";
  const bodyRaw = parts.slice(1).join("\n\n");

  // Extraer headers básicos
  const subject = (headersRaw.match(/^Subject:\s*(.*)$/gmi)?.[0] || "").replace(/^Subject:\s*/i, "");
  const from = (headersRaw.match(/^From:\s*(.*)$/gmi)?.[0] || "").replace(/^From:\s*/i, "");

  // Body: MVP (sin MIME completo)
  const bodyExcerpt = bodyRaw.replace(/\r?\n/g, "\n").slice(0, 2000);

  // Links: extraer urls en texto plano
  const urlRegex = /https?:\/\/[^\s"'<>()]+/gi;
  const urls = bodyRaw.match(urlRegex) || [];
  const links = urls.slice(0, 50).map(u => ({ href: u, text: u }));

  return {
    provider: "eml",
    senderAddress: from.trim(),
    subject: subject.trim(),
    bodyExcerpt,
    links
  };
}

if (emlFile) {
  emlFile.addEventListener("change", () => {
    const file = emlFile.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      const raw = String(reader.result || "");
      const email = parseEmlBasic(raw);
      const result = analyzeLocally(email);
      renderResult(email, result);
    };
    reader.readAsText(file);
  });
}



function showError(msg) {
  errorBox.textContent = msg;
  errorBox.classList.remove("hidden");
}

function clearError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

function setPill(level, label) {
  verdictPill.className = "pill " + level;
  verdictPill.textContent = label;
}

function uniq(arr) {
  return [...new Set(arr)];
}

function getDomain(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.hostname.toLowerCase();
  } catch {
    return "";
  }
}

function extractDomainsFromText(text) {
  const regex = /([a-z0-9-]+\.)+[a-z]{2,}/gi;
  return [...new Set((text || "").match(regex) || [])];
}

function looksLikeIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function isShortener(host) {
  const shorteners = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly"
  ]);
  return shorteners.has(host);
}

function hasPunycode(host) {
  return host.includes("xn--");
}

function textDomainMismatch(linkText, href) {
  const m = (linkText || "").toLowerCase().match(/([a-z0-9-]+\.)+[a-z]{2,}/);
  if (!m) return false;
  const textDomain = m[0];
  const realDomain = getDomain(href);
  if (!realDomain) return false;
  if (realDomain === textDomain) return false;
  if (realDomain.endsWith("." + textDomain)) return false;
  if (textDomain.endsWith("." + realDomain)) return false;
  return true;
}

function analyzeLocally(email) {
  const findings = [];
  let score = 0;

  const subject = (email.subject || "").toLowerCase();
  const body = (email.bodyExcerpt || "").toLowerCase();
  const textDomains = extractDomainsFromText(email.bodyExcerpt);
  const links = Array.isArray(email.links) ? email.links : [];

  const urgency = /(urgente|inmediatamente|act(ú|u)a ahora|cuenta (suspendida|bloqueada)|última oportunidad|pago pendiente|verifica tu cuenta|verify|suspended|urgent|immediately)/i;
  const asksSecrets = /(contrase(ñ|n)a|password|c(ó|o)digo|otp|token|transferencia|wire|gift card|tarjeta regalo)/i;

  const linkHosts = links.map(l => getDomain(l.href)).filter(Boolean);
  const uniqueHosts = uniq(linkHosts);

  for (const l of links) {
    const host = getDomain(l.href);
    if (!host) continue;

    if (looksLikeIpHost(host)) {
      score += 40;
      findings.push({ level: "red", msg: "Hay un enlace que apunta a una dirección IP (muy sospechoso)." });
    }
    if (isShortener(host)) {
      score += 25;
      findings.push({ level: "red", msg: "Hay un enlace acortado (puede ocultar el destino real)." });
    }
    if (hasPunycode(host)) {
      score += 30;
      findings.push({ level: "red", msg: "Hay un enlace con dominio extraño (posible suplantación)." });
    }
if (textDomainMismatch(l.text || "", l.href)) {
  const host = getDomain(l.href);

  const looksInstitutional =
    TRUSTED_DOMAINS.some(d => host.endsWith(d)) ||
    host.includes(".edu") ||
    host.includes(".k12");

  if (!looksInstitutional) {
    score += 25;
    findings.push({
      level: "red",
      msg: "El texto del enlace no coincide con el sitio real al que lleva."
    });
  } else {
    score += 5;
    findings.push({
      level: "yellow",
      msg: "El enlace apunta a un sitio institucional distinto al texto."
    });
  }
}

  }

  if (urgency.test(subject) || urgency.test(body)) {
    if (links.length > 0) {
      score += 25;
      findings.push({ level: "red", msg: "Lenguaje de urgencia junto a enlaces (patrón típico de phishing)." });
    } else {
      score += 10;
      findings.push({ level: "yellow", msg: "Lenguaje de urgencia (precaución)." });
    }
  }

  if (asksSecrets.test(subject) || asksSecrets.test(body)) {
    score += 25;
    findings.push({ level: "red", msg: "El mensaje sugiere pedir claves/códigos o dinero (alto riesgo)." });
  }

  if (links.length >= 5) {
    score += 10;
    findings.push({ level: "yellow", msg: "Contiene muchos enlaces (revisa antes de hacer clic)." });
  }

  const veryShort = (email.bodyExcerpt || "").trim().length > 0 && (email.bodyExcerpt || "").trim().length < 60;
  if (veryShort && links.length > 0) {
    score += 10;
    findings.push({ level: "yellow", msg: "Mensaje muy corto con enlace (patrón común de engaños)." });
  }

  const senderDomain = (() => {
    const addr = (email.senderAddress || "").toLowerCase();
    const at = addr.lastIndexOf("@");
    return at >= 0 ? addr.slice(at + 1) : "";
  })();

const impersonationWords = /(microsoft|outlook|hotmail|live)/i;
const accountThreats = /(suspendida|confirmar|verifica|cerrar|bloqueada|account|confirmación)/i;

if (
  impersonationWords.test(body) &&
  accountThreats.test(body)
) {
  for (const d of textDomains) {
    if (
      !d.endsWith("microsoft.com") &&
      !d.endsWith("live.com") &&
      !d.endsWith("outlook.com")
    ) {
      score += 50;
      findings.push({
        level: "red",
        msg: "El correo se hace pasar por Microsoft pero dirige a un sitio externo."
      });
      break;
    }
  }
}

  score = Math.min(100, score);

  let verdict = "SAFE";
  let level = "green";

  if (score >= 60) { verdict = "MALICIOUS"; level = "red"; }
  else if (score >= 25) { verdict = "SUSPICIOUS"; level = "yellow"; }

  const ordered = findings
    .sort((a, b) => (a.level === b.level ? 0 : a.level === "red" ? -1 : 1))
    .map(f => f.msg);

  const reasons = uniq(ordered).slice(0, 2);
  if (reasons.length === 0) {
    reasons.push("No se detectaron señales claras de riesgo en lo visible.");
  }

  return {
    score,
    verdict,
    level,
    reasons,
    senderDomain,
    linkDomains: uniqueHosts
  };
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function requestExtractionFromPage(tabId) {
  return await chrome.tabs.sendMessage(tabId, { type: "MAILSAFE_EXTRACT" });
}

function renderResult(email, result) {
  hint.classList.add("hidden");
  status.classList.remove("hidden");

  const label =
    result.level === "red" ? "🔴 Riesgo alto" :
    result.level === "yellow" ? "🟡 Precaución" :
    "🟢 Se ve normal";

  setPill(result.level, label);

  reason1.textContent = result.reasons[0] || "";
  reason2.textContent = result.reasons[1] || "";

  providerEl.textContent = email.provider || "—";
  senderDomainEl.textContent = result.senderDomain || "—";
  linkDomainsEl.textContent = (result.linkDomains && result.linkDomains.length)
    ? result.linkDomains.join(", ")
    : "—";
}

analyzeBtn.addEventListener("click", async () => {
  clearError();
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "Analizando...";

  try {
    const tab = await getActiveTab();
    if (!tab || !tab.id || !tab.url) {
      throw new Error("No se pudo acceder a la pestaña activa.");
    }

    const isAllowed =
      tab.url.startsWith("https://mail.google.com/") ||
      tab.url.startsWith("https://outlook.live.com/") ||
      tab.url.startsWith("https://outlook.office.com/");

    if (!isAllowed) {
      throw new Error("Abre un correo en Gmail u Outlook Web para analizar.");
    }

    const email = await requestExtractionFromPage(tab.id);
    if (!email || !email.ok) {
      throw new Error(email?.error || "No pude extraer el correo. Abre un correo (no la lista) e intenta de nuevo.");
    }

    const result = analyzeLocally(email.data);
    renderResult(email.data, result);
  } catch (e) {
    showError(e?.message || String(e));
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analizar este correo";
  }
});
