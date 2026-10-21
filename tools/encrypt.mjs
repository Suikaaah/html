#!/usr/bin/env node
// Encrypts a plaintext HTML page into a password-gated page for static hosting.
// Usage: PAGE_PASSWORD=... node tools/encrypt.mjs src/points.html points/index.html
//        (omit PAGE_PASSWORD to be prompted)
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { webcrypto as crypto } from "node:crypto";
import { createInterface } from "node:readline";

const ITERATIONS = 600000;
const [, , input, output] = process.argv;
if (!input || !output) {
  console.error("usage: node tools/encrypt.mjs <input.html> <output.html>");
  process.exit(1);
}

async function readPassword() {
  if (process.env.PAGE_PASSWORD) return process.env.PAGE_PASSWORD;
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  rl._writeToOutput = () => {};
  process.stderr.write("Password: ");
  const pw = await new Promise((res) => rl.question("", res));
  rl.close();
  process.stderr.write("\n");
  return pw;
}

const b64 = (buf) => Buffer.from(buf).toString("base64");

const password = await readPassword();
if (!password) {
  console.error("empty password");
  process.exit(1);
}

const plaintext = readFileSync(input);
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
  baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

const payload = JSON.stringify({ v: 1, iter: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ciphertext) });

const page = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Password required</title>
<style>
:root{--bg:#f3f5f8;--surface:#fff;--ink:#14213a;--muted:#7b879a;--line:#dfe4ec;--blue:#2563eb;--on-c:#fff;--err:#c62828;color-scheme:light}
@media (prefers-color-scheme: dark){:root{--bg:#0e1218;--surface:#161c25;--ink:#e7ecf3;--muted:#7f8b9b;--line:#29313d;--blue:#6ea2ff;--on-c:#0e1218;--err:#ff7b7b;color-scheme:dark}}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--ink);
  font-family:"Hiragino Sans","Hiragino Kaku Gothic ProN","Yu Gothic",Meiryo,system-ui,sans-serif;font-size:14px;line-height:1.6}
form{width:100%;max-width:340px;background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:24px;display:grid;gap:12px}
h1{font-size:18px;margin:0}
input[type=password]{width:100%;font:inherit;font-size:16px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit}
input[type=password]:focus{outline:2px solid var(--blue);outline-offset:-1px}
label.remember{display:flex;gap:8px;align-items:center;color:var(--muted);font-size:13px}
button{font:inherit;font-weight:700;padding:10px;border:0;border-radius:8px;background:var(--blue);color:var(--on-c);cursor:pointer}
button:disabled{opacity:.6;cursor:wait}
.msg{min-height:1.6em;margin:0;color:var(--err);font-size:13px}
</style>
</head>
<body>
<form id="f" autocomplete="on">
  <h1>Enter password</h1>
  <input type="text" name="username" value="points" autocomplete="username" hidden>
  <input id="pw" type="password" autocomplete="current-password" aria-label="Password" required autofocus>
  <label class="remember"><input id="rm" type="checkbox">Remember on this device</label>
  <button id="go" type="submit">Unlock</button>
  <p class="msg" id="msg" role="alert"></p>
</form>
<script id="payload" type="application/json">${payload}</script>
<script>
(function(){
  const P = JSON.parse(document.getElementById("payload").textContent);
  const STORE = "pagekey:" + location.pathname + ":" + P.salt;
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const store = {
    get(){ try { return localStorage.getItem(STORE); } catch(e){ return null; } },
    set(v){ try { localStorage.setItem(STORE, v); } catch(e){} },
    del(){ try { localStorage.removeItem(STORE); } catch(e){} }
  };

  async function deriveRaw(pw){
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
    return crypto.subtle.deriveBits({name:"PBKDF2", salt:unb64(P.salt), iterations:P.iter, hash:"SHA-256"}, base, 256);
  }
  async function decrypt(raw){
    const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(P.iv)}, key, unb64(P.ct));
    return new TextDecoder().decode(pt);
  }
  function show(html){
    document.open();
    document.write(html);
    document.close();
  }

  const saved = store.get();
  if (saved) decrypt(unb64(saved)).then(show, () => store.del());

  const f = document.getElementById("f"), go = document.getElementById("go"), msg = document.getElementById("msg");
  f.addEventListener("submit", async e => {
    e.preventDefault();
    go.disabled = true; msg.textContent = "";
    try {
      const raw = await deriveRaw(document.getElementById("pw").value);
      const html = await decrypt(raw);
      if (document.getElementById("rm").checked) store.set(b64(raw));
      show(html);
    } catch(err) {
      msg.textContent = "Incorrect password";
      go.disabled = false;
    }
  });
})();
</script>
</body>
</html>
`;

mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, page);
console.error(`wrote ${output} (${page.length} bytes)`);
