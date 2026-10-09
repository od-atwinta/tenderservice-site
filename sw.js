// Расшифровывает страницы макетов на лету. Ключ — из пароля, введённого на странице входа;
// хранится в браузере (IndexedDB) в неизвлекаемом виде. Собирается скриптом build.mjs.
const SALT = "atw-maket-94d4cc4901f8884a";
const SCOPE = new URL(self.registration.scope).pathname;
const PASS_THROUGH = new Set(["sw.js", "gate.html", "404.html"]);
const TYPES = {
  html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8", css: "text/css; charset=utf-8",
  json: "application/json", txt: "text/plain; charset=utf-8", svg: "image/svg+xml",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp", gif: "image/gif",
  ico: "image/x-icon", mp4: "video/mp4", woff2: "font/woff2", pdf: "application/pdf",
};
const BIG = new Map();
let keyPromise = null;

function db() {
  return new Promise((ok, fail) => {
    const r = indexedDB.open("maket-gate", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("k");
    r.onsuccess = () => ok(r.result);
    r.onerror = () => fail(r.error);
  });
}
async function idb(mode, fn) {
  const d = await db();
  return new Promise((ok, fail) => {
    const req = fn(d.transaction("k", mode).objectStore("k"));
    req.onsuccess = () => ok(req.result);
    req.onerror = () => fail(req.error);
  });
}
async function getKey() {
  if (!keyPromise) keyPromise = idb("readonly", (s) => s.get(SALT)).catch(() => null);
  const k = await keyPromise;
  if (!k) keyPromise = null;
  return k || null;
}
async function forgetKey() {
  keyPromise = null;
  BIG.clear();
  await idb("readwrite", (s) => s.delete(SALT)).catch(() => {});
}
async function sha(text) {
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function gate() {
  return fetch(SCOPE + "gate.html", { cache: "no-cache" });
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => {
  if (e.data === "key-changed") { keyPromise = null; BIG.clear(); }
  if (e.data === "logout") e.waitUntil(forgetKey());
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin || !url.pathname.startsWith(SCOPE)) return;
  let rel = decodeURIComponent(url.pathname.slice(SCOPE.length));
  if (PASS_THROUGH.has(rel) || rel.startsWith("enc/")) return;
  if (rel === "" || rel.endsWith("/")) rel += "index.html";
  else if (!rel.split("/").pop().includes(".")) rel += ".html";
  e.respondWith(serve(e.request, rel));
});

async function serve(request, rel) {
  const key = await getKey();
  const isPage = request.mode === "navigate";
  if (!key) return isPage ? gate() : new Response("", { status: 401 });

  let data = BIG.get(rel);
  if (!data) {
    const res = await fetch(SCOPE + "enc/" + (await sha(SALT + "/" + rel)) + ".bin", { cache: "no-cache" });
    if (!res.ok) {
      return new Response(isPage ? "<meta charset=utf-8><p style='font:16px sans-serif;padding:40px'>Страница не найдена</p>" : "",
        { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    try {
      data = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, key, buf.slice(12));
    } catch {
      // пароль сменили — просим ввести заново
      await forgetKey();
      return isPage ? gate() : new Response("", { status: 401 });
    }
    if (data.byteLength > 1_000_000) BIG.set(rel, data);
  }

  const type = TYPES[rel.split(".").pop().toLowerCase()] || "application/octet-stream";
  const headers = { "Content-Type": type, "Accept-Ranges": "bytes", "Cache-Control": "no-store" };
  const range = request.headers.get("Range");
  const m = range && /bytes=(\d*)-(\d*)/.exec(range);
  if (m) {
    const size = data.byteLength;
    let start = m[1] === "" ? size - Number(m[2]) : Number(m[1]);
    let end = m[1] !== "" && m[2] !== "" ? Number(m[2]) : size - 1;
    start = Math.max(0, start); end = Math.min(end, size - 1);
    return new Response(data.slice(start, end + 1), {
      status: 206,
      headers: { ...headers, "Content-Range": `bytes ${start}-${end}/${size}`, "Content-Length": String(end - start + 1) },
    });
  }
  return new Response(data, { headers: { ...headers, "Content-Length": String(data.byteLength) } });
}
