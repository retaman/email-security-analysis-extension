function safeText(el) {
  if (!el) return "";
  return (el.innerText || el.textContent || "").trim();
}

function limit(str, n) {
  const s = (str || "").trim();
  return s.length > n ? s.slice(0, n) : s;
}

function getProvider() {
  const host = location.host;
  if (host === "mail.google.com") return "gmail";
  if (host === "outlook.live.com" || host === "outlook.office.com") return "outlook";
  return "unknown";
}

function extractGmail() {
  const senderEl = document.querySelector("span[email]");
  const senderAddress = senderEl?.getAttribute("email") || "";

  const subjectEl =
    document.querySelector("h2") ||
    document.querySelector('div[role="main"] h2') ||
    document.querySelector('div[role="main"] div[role="heading"]');
  const subject = safeText(subjectEl);

  const main = document.querySelector('div[role="main"]');
  if (!main) return null;

  const bodyText = safeText(main);

  const links = Array.from(main.querySelectorAll("a"))
    .map((a) => ({ href: a.href, text: (a.innerText || "").trim() }))
    .filter((l) => l.href && /^https?:\/\//i.test(l.href));

  const bodyExcerpt = limit(bodyText, 2000);
  if (!subject && bodyExcerpt.length < 30 && links.length === 0 && !senderAddress) return null;

  return {
    provider: "gmail",
    senderAddress,
    subject: limit(subject, 300),
    bodyExcerpt,
    links
  };
}

function extractOutlook() {
  const main =
    document.querySelector('div[role="main"]') ||
    document.querySelector('div[aria-label*="Reading pane" i]') ||
    document.querySelector('div[aria-label*="Panel de lectura" i]');
  if (!main) return null;

  const mailto = main.querySelector('a[href^="mailto:"]');
  const senderAddress = mailto
    ? (mailto.getAttribute("href") || "").replace(/^mailto:/i, "").split("?")[0]
    : "";

  const subjectEl =
    main.querySelector('h1, h2, div[role="heading"]') ||
    document.querySelector('h1, h2, div[role="heading"]');
  const subject = safeText(subjectEl);

  const bodyText = safeText(main);

  const links = Array.from(main.querySelectorAll("a"))
    .map((a) => ({ href: a.href, text: (a.innerText || "").trim() }))
    .filter((l) => l.href && /^https?:\/\//i.test(l.href));

  const bodyExcerpt = limit(bodyText, 2000);
  if (!subject && bodyExcerpt.length < 30 && links.length === 0 && !senderAddress) return null;

  return {
    provider: "outlook",
    senderAddress,
    subject: limit(subject, 300),
    bodyExcerpt,
    links
  };
}

function extractEmailData() {
  const provider = getProvider();
  if (provider === "gmail") return extractGmail();
  if (provider === "outlook") return extractOutlook();
  return null;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "MAILSAFE_EXTRACT") return;

  try {
    const data = extractEmailData();
    if (!data) {
      sendResponse({ ok: false, error: "No detecté un correo abierto. Abre el correo y vuelve a intentar." });
      return;
    }

    data.bodyExcerpt = (data.bodyExcerpt || "").slice(0, 2000);
    if (Array.isArray(data.links)) data.links = data.links.slice(0, 50);

    sendResponse({ ok: true, data });
  } catch (e) {
    sendResponse({ ok: false, error: e?.message || String(e) });
  }
  return true;
});
