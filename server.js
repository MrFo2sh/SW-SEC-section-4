#!/usr/bin/env node
/*
 * XSS Lab — a DELIBERATELY VULNERABLE app for teaching Cross-Site Scripting.
 * Run:  npm install && npm start   ->  http://localhost:4000
 *
 * ⚠️  Every "vulnerable" route below renders user input WITHOUT escaping on
 *     purpose. Never deploy this. Run it locally / on an isolated lab network.
 *
 * Demos:
 *   /reflected        Reflected XSS  — payload in the request, echoed back now.
 *   /guestbook        Stored  XSS    — payload saved, runs for every visitor.
 *   /contact + /admin Blind   XSS    — payload saved; fires later in the
 *                                      ADMIN's browser, where the attacker
 *                                      can't see it (classic blind XSS).
 *
 * The one place we DO escape is the contact confirmation page — that is what
 * makes the Contact Us vuln "blind": the attacker gets a clean page back and
 * sees nothing; the script only executes when staff open the admin panel.
 */
const express = require("express");
const crypto = require("crypto");
const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.urlencoded({ extended: false }));

/* Give every visitor (logged in or not) a session id cookie, so the
 * cookie-theft payloads have something to steal via document.cookie.
 * NOTE: intentionally NOT HttpOnly — in a real app you'd set HttpOnly so
 * JavaScript (and therefore XSS) can't read it. That's part of the lesson. */
app.use((req, res, next) => {
  const hasSid = (req.headers.cookie || "")
    .split(";")
    .some((c) => c.trim().startsWith("sid="));
  if (!hasSid) {
    const sid = crypto.randomBytes(16).toString("hex");
    res.setHeader("Set-Cookie", `sid=${sid}; Path=/; SameSite=Lax`);
  }
  next();
});

/* in-memory stores (reset on restart, or hit /reset) */
let guestbook = [
  { name: "ACME Team", message: "Welcome to our guestbook! 👋" },
];
let messages = []; // contact-us submissions, viewed by "admin"
let adminSessions = new Set(); // valid admin session tokens

/* read a single cookie value from the request */
const getCookie = (req, name) => {
  const hit = (req.headers.cookie || "")
    .split(";").map((c) => c.trim())
    .find((c) => c.startsWith(name + "="));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : undefined;
};

/* The ONLY escaping helper in the app. Used deliberately-sparingly. */
const esc = (s = "") =>
  String(s).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );

/* ------------------------------------------------------------------ layout */
function layout(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} — XSS Lab</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-800 min-h-screen antialiased">
  <div class="bg-amber-100 border-b border-amber-300 text-amber-800 text-sm text-center py-1.5">
    ⚠️ Intentionally vulnerable — teaching lab only. Do not deploy.
  </div>
  <header class="border-b border-slate-200 bg-white/80 backdrop-blur sticky top-0 z-10">
    <nav class="max-w-5xl mx-auto flex flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3">
      <a href="/" class="font-bold text-indigo-600 mr-2">XSS&nbsp;Lab</a>
      <a href="/reflected" class="hover:text-indigo-600 text-slate-600">Reflected</a>
      <a href="/guestbook" class="hover:text-indigo-600 text-slate-600">Stored</a>
      <a href="/contact"   class="hover:text-indigo-600 text-slate-600">Contact&nbsp;Us</a>
      <a href="/admin/messages" class="hover:text-rose-500 text-rose-600">Admin&nbsp;Panel</a>
      <a href="/reset" class="ml-auto text-xs text-slate-400 hover:text-slate-600">reset data</a>
    </nav>
  </header>
  <main class="max-w-5xl mx-auto px-5 py-8">${body}</main>
  <footer class="max-w-5xl mx-auto px-5 py-10 text-xs text-slate-400 border-t border-slate-200 mt-10">
    Software Security · XSS module · payloads run because output is not escaped.
  </footer>
</body>
</html>`;
}

/* small UI helpers */
const card = (inner, cls = "") =>
  `<section class="rounded-2xl border border-slate-200 bg-white shadow-sm p-6 ${cls}">${inner}</section>`;
const badge = (txt, color) =>
  `<span class="inline-block text-xs font-semibold px-2 py-0.5 rounded-full bg-${color}-100 text-${color}-700 border border-${color}-200">${txt}</span>`;
const h1 = (t, b) =>
  `<div class="mb-6"><h1 class="text-2xl font-bold text-slate-900">${t}</h1><p class="text-slate-500 mt-1">${b}</p></div>`;

/* ------------------------------------------------------------------- home  */
app.get("/", (_req, res) => {
  res.send(
    layout(
      "Home",
      `
    ${h1("Cross-Site Scripting (XSS)", "Injecting JavaScript that runs in a victim's browser, in the trusted site's origin.")}
    ${card(`
      <h2 class="text-lg font-semibold text-slate-900 mb-2">What is XSS?</h2>
      <p class="text-slate-600 leading-relaxed">
        A site takes input from a user and places it into a page <b>without escaping</b>.
        The browser can't tell the injected markup from the site's own, so it executes
        attacker JavaScript with the site's cookies, DOM and privileges. Impact: session
        theft, account takeover, keylogging, defacement, worms.
      </p>
      <div class="grid sm:grid-cols-3 gap-4 mt-5">
        <a href="/reflected" class="rounded-xl border border-slate-200 p-4 hover:border-indigo-400 hover:shadow-sm">
          ${badge("Reflected", "amber")}<h3 class="font-semibold mt-2 text-slate-900">Reflected</h3>
          <p class="text-sm text-slate-500 mt-1">Payload in the request, echoed back immediately. Delivered via a crafted link.</p></a>
        <a href="/guestbook" class="rounded-xl border border-slate-200 p-4 hover:border-indigo-400 hover:shadow-sm">
          ${badge("Stored", "rose")}<h3 class="font-semibold mt-2 text-slate-900">Stored</h3>
          <p class="text-sm text-slate-500 mt-1">Payload saved server-side, runs for <i>every</i> visitor. Highest impact.</p></a>
        <a href="/contact" class="rounded-xl border border-slate-200 p-4 hover:border-indigo-400 hover:shadow-sm">
          ${badge("Blind", "fuchsia")}<h3 class="font-semibold mt-2 text-slate-900">Blind</h3>
          <p class="text-sm text-slate-500 mt-1">Stored, but fires in someone else's session (an admin) — you never see the result directly.</p></a>
      </div>
    `)}
    ${card(
      `
      <h2 class="text-lg font-semibold text-slate-900 mb-2">The one-line fix</h2>
      <p class="text-slate-600">Escape output for its context (HTML-encode <code>&lt; &gt; &amp; " '</code>), use an
      auto-escaping template engine, and add a <code>Content-Security-Policy</code>. We'll break
      each lab, then fix it.</p>`,
      "mt-6",
    )}
  `,
    ),
  );
});

/* -------------------------------------------------------------- reflected  */
app.get("/reflected", (req, res) => {
  const q = req.query.q;
  const result =
    q === undefined
      ? ""
      : // VULNERABLE: q is written straight into HTML, unescaped.
        `<div class="mt-5 rounded-lg border border-slate-200 bg-slate-50 p-4">
       <p class="text-slate-500 text-sm mb-1">You searched for:</p>
       <div class="text-lg">${q}</div>
     </div>`;
  res.send(
    layout(
      "Reflected XSS",
      `
    ${h1(`Reflected XSS ${badge("live", "amber")}`, "The value of <code>?q=</code> is reflected into the page with no escaping.")}
    ${card(`
      <form method="get" class="flex gap-2">
        <input name="q"  placeholder="search…" autofocus
          class="flex-1 rounded-lg bg-white border border-slate-300 px-3 py-2 focus:outline-none focus:border-indigo-500">
        <button class="rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2 font-semibold text-white">Search</button>
      </form>
      ${result}
    `)}
    ${card(
      `
      <p class="text-slate-500 text-xs"><b>Why:</b> <code>q</code> is concatenated into HTML with no escaping. <b>Fix:</b> HTML-encode it before output.</p>
    `,
      "mt-6",
    )}
  `,
    ),
  );
});

/* ----------------------------------------------------------------- stored  */
app.get("/guestbook", (_req, res) => {
  // VULNERABLE: each entry's name/message rendered unescaped.
  const entries = guestbook
    .map(
      (e) => `
    <div class="rounded-lg border border-slate-200 bg-slate-50 p-4">
      <div class="text-sm text-indigo-700 font-semibold">${e.name}</div>
      <div class="mt-1 text-slate-700">${e.message}</div>
    </div>`,
    )
    .join("");
  res.send(
    layout(
      "Stored XSS",
      `
    ${h1(`Stored XSS ${badge("persistent", "rose")}`, "Entries are saved on the server and rendered to everyone who opens this page — unescaped.")}
    ${card(`
      <form method="post" action="/guestbook" class="grid gap-3">
        <input name="name" placeholder="your name"
          class="rounded-lg bg-white border border-slate-300 px-3 py-2 focus:outline-none focus:border-indigo-500">
        <textarea name="message" placeholder="leave a message…" rows="3"
          class="rounded-lg bg-white border border-slate-300 px-3 py-2 focus:outline-none focus:border-indigo-500"></textarea>
        <button class="justify-self-start rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2 font-semibold text-white">Post</button>
      </form>`)}
    <div class="grid gap-3 mt-6">${entries}</div>
    ${card(
      `
      <p class="text-slate-500 text-xs"><b>Why:</b> the message is stored, then injected into HTML for all users with no escaping. <b>Fix:</b> escape on output (and/or sanitize on input).</p>
    `,
      "mt-6",
    )}
  `,
    ),
  );
});
app.post("/guestbook", (req, res) => {
  guestbook.push({
    name: req.body.name || "anon",
    message: req.body.message || "",
  });
  res.redirect("/guestbook");
});

/* ------------------------------------------------------- blind (contact)   */
app.get("/contact", (_req, res) => {
  res.send(
    layout(
      "Contact Us",
      `
    ${h1(`Contact Us ${badge("blind", "fuchsia")}`, "Send us a message. You'll get a clean confirmation — but staff review every message in the admin panel.")}
    ${card(`
      <form method="post" action="/contact" class="grid gap-3">
        <input name="name" placeholder="your name"
          class="rounded-lg bg-white border border-slate-300 px-3 py-2 focus:outline-none focus:border-indigo-500">
        <input name="email" placeholder="your email"
          class="rounded-lg bg-white border border-slate-300 px-3 py-2 focus:outline-none focus:border-indigo-500">
        <textarea name="message" placeholder="your message…" rows="4"
          class="rounded-lg bg-white border border-slate-300 px-3 py-2 focus:outline-none focus:border-indigo-500"></textarea>
        <button class="justify-self-start rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2 font-semibold text-white">Send message</button>
      </form>`)}
    ${card(
      `
      <p class="text-slate-500 text-sm">Your submission is escaped on the confirmation page — you see nothing. The payload
      only executes later when an <b>admin opens the panel</b>, so use an out-of-band callback to learn it fired.</p>
      <p class="text-slate-500 text-xs mt-3"><b>Why blind:</b> the sink (admin panel) is a different page/user than the source (this form). <b>Fix:</b> escape in the admin view too — every sink counts.</p>
    `,
      "mt-6",
    )}
  `,
    ),
  );
});
app.post("/contact", (req, res) => {
  messages.push({
    name: req.body.name || "anon",
    email: req.body.email || "",
    message: req.body.message || "",
    at: new Date().toISOString(),
  });
  // SAFE here on purpose -> attacker sees a clean page (that's what makes it "blind")
  res.send(
    layout(
      "Message sent",
      `
    ${card(`
      <h1 class="text-xl font-bold text-slate-900">✅ Thanks, ${esc(req.body.name || "there")}!</h1>
      <p class="text-slate-600 mt-2">We received your message and our team will review it shortly.</p>
      <p class="text-slate-500 text-sm mt-4">(Notice: nothing executed here — your payload is waiting for the admin.)</p>
      <a href="/contact" class="inline-block mt-4 text-indigo-600 hover:text-indigo-500">← send another</a>
    `)}
  `,
    ),
  );
});

/* --------------------------------------------------------- admin login    */
const ADMIN_USER = "admin", ADMIN_PASS = "admin";

function loginPage(error = "") {
  return layout("Admin Login", `
    ${h1(`Admin Login ${badge("staff only", "rose")}`, "Sign in to review contact messages.")}
    ${card(`
      ${error ? `<p class="mb-3 text-sm text-rose-600">${error}</p>` : ""}
      <form method="post" action="/admin/login" class="grid gap-3 max-w-sm">
        <input name="username" placeholder="username" autofocus
          class="rounded-lg bg-white border border-slate-300 px-3 py-2 focus:outline-none focus:border-indigo-500">
        <input name="password" type="password" placeholder="password"
          class="rounded-lg bg-white border border-slate-300 px-3 py-2 focus:outline-none focus:border-indigo-500">
        <button class="justify-self-start rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2 font-semibold text-white">Sign in</button>
      </form>
      <p class="text-slate-400 text-xs mt-4">Lab credentials: <code>admin</code> / <code>admin</code></p>
    `)}
  `);
}
app.get("/admin/login", (req, res) => {
  if (adminSessions.has(getCookie(req, "admin_sid"))) return res.redirect("/admin/messages");
  res.send(loginPage());
});
app.post("/admin/login", (req, res) => {
  if (req.body.username === ADMIN_USER && req.body.password === ADMIN_PASS) {
    const token = crypto.randomBytes(16).toString("hex");
    adminSessions.add(token);
    // NOT HttpOnly on purpose -> the blind XSS can steal this admin session
    res.setHeader("Set-Cookie", `admin_sid=${token}; Path=/; SameSite=Lax`);
    return res.redirect("/admin/messages");
  }
  res.status(401).send(loginPage("Invalid username or password."));
});
app.get("/admin/logout", (req, res) => {
  adminSessions.delete(getCookie(req, "admin_sid"));
  res.setHeader("Set-Cookie", "admin_sid=; Path=/; Max-Age=0");
  res.redirect("/admin/login");
});

/* ----------------------------------------------- admin panel (blind sink)  */
app.get("/admin/messages", (req, res) => {
  // require an admin session
  if (!adminSessions.has(getCookie(req, "admin_sid"))) return res.redirect("/admin/login");
  // VULNERABLE: renders every contact message unescaped -> blind XSS fires here.
  const rows =
    messages.length === 0
      ? `<p class="text-slate-500">No messages yet.</p>`
      : messages
          .map(
            (m) => `
      <div class="rounded-lg border border-slate-200 bg-slate-50 p-4">
        <div class="flex justify-between text-sm">
          <span class="text-rose-700 font-semibold">${m.name} &lt;${m.email}&gt;</span>
          <span class="text-slate-400">${esc(m.at)}</span>
        </div>
        <div class="mt-2 text-slate-800">${m.message}</div>
      </div>`,
          )
          .join("");
  res.send(
    layout(
      "Admin · Messages",
      `
    ${h1(`Admin Panel ${badge("staff only", "rose")}`, "Support staff review incoming messages here. This page renders submissions raw — the blind XSS sink.")}
    ${card(`<div class="grid gap-3">${rows}</div>`)}
    <div class="flex items-center justify-between mt-4">
      <p class="text-slate-500 text-xs">You're signed in as <b>admin</b>; a blind payload here runs in <i>your</i> session and can steal <code>admin_sid</code>.</p>
      <a href="/admin/logout" class="text-xs text-slate-400 hover:text-slate-600">log out</a>
    </div>
  `,
    ),
  );
});

/* ---------------------------------------------------------------- reset    */
app.get("/reset", (_req, res) => {
  guestbook = [{ name: "ACME Team", message: "Welcome to our guestbook! 👋" }];
  messages = [];
  res.redirect("/");
});

app.listen(PORT, "0.0.0.0", () =>
  console.log(
    `XSS Lab running: http://localhost:${PORT}  (VM: http://<host-ip>:${PORT})`,
  ),
);
