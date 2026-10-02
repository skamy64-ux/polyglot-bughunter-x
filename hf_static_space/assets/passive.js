// PolyglotBugHunter-X - passive + access-control checks, ported from
// scanner/passive.py and scanner/access.py.
//
// Passive means nothing here can change state, so it is safe to run against
// anything. It is also where most real-world findings come from, because missing
// headers and sloppy cookies are everywhere.

import { escapeHtml } from "./demo_target.js";

const SECURITY_HEADERS = {
  "content-security-policy": [
    "No Content-Security-Policy. Nothing stops an injected script from running with your origin's cookies attached.",
    "medium", "CWE-693", "N,L,N,N,U,L,L,N"],
  "x-frame-options": [
    "No frame protection. This page can be iframed, which is how clickjacking and session-riding attacks work.",
    "low", "CWE-1021", "N,L,N,R,U,L,H,N"],
  "x-content-type-options": [
    "No nosniff. Browsers will MIME-sniff a response you meant to be inert.",
    "low", "CWE-16", "N,L,N,N,U,L,L,N"],
  "referrer-policy": [
    "No Referrer-Policy. Full URLs (often with tokens) leak to third parties in the Referer header.",
    "info", "CWE-200", "N,L,N,N,U,L,L,N"],
  "permissions-policy": [
    "No Permissions-Policy. Camera, mic, geolocation stay available to any iframe you embed.",
    "info", "CWE-16", "N,L,N,N,U,L,L,N"],
};

const EXPOSURE_PROBES = [
  ["/.env", "critical", "Django/Node env file with secrets"],
  ["/.git/config", "critical", "source control config, full history"],
  ["/wp-config.php.bak", "high", "WordPress DB credentials"],
  ["/backup.zip", "high", "often full source + creds"],
  ["/phpinfo.php", "medium", "PHP config dump"],
  ["/server-status", "medium", "Apache status page"],
  ["/actuator/env", "critical", "Spring Boot environment + secrets"],
];

const COOKIE_HINT = (raw) => raw.toLowerCase();

export function checkHeaders(resp, url) {
  const out = [];
  for (const [header, [why, sev, cwe, vec]] of Object.entries(SECURITY_HEADERS)) {
    if (resp.headers && resp.headers[header]) continue;
    out.push({
      title: `Missing security header: ${header}`,
      severity: sev,
      cvssVector: `CVSS:3.1/${vec.split(",").join("/")}`,
      modality: "passive",
      confidence: "high",
      cwe,
      owasp: "A05:2021 - Security Misconfiguration",
      url,
      endpoint: url,
      description: why,
      impact: "Weakens defence in depth; alone it is rarely exploitable.",
      remediation: `Add \`${header}: <value>\` at the edge or in your framework config.`,
      proof: `header '${header}' absent from response`,
      tags: ["passive", "headers", "hardening"],
      scope: "host",
    });
  }

  const csp = (resp.headers && resp.headers["content-security-policy"]) || "";
  if (csp) {
    const weak = ["unsafe-inline", "unsafe-eval", "data:", "*", "http://", "https://*"]
      .filter((d) => csp.toLowerCase().includes(d));
    if (weak.length) {
      out.push({
        title: "Content-Security-Policy is present but weak",
        severity: "low",
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        modality: "passive", confidence: "high", cwe: "CWE-693",
        owasp: "A05:2021 - Security Misconfiguration",
        url, endpoint: url,
        description: `CSP contains ${weak.join(", ")} - inline script still runs.`,
        impact: "CSP is not actually blocking XSS payloads.",
        remediation: "Drop unsafe-inline/unsafe-eval; use nonces or hashes.",
        proof: csp.slice(0, 300),
        tags: ["passive", "csp"], scope: "host",
      });
    }
  }
  return out;
}

export function checkCookies(resp, url, isHttps) {
  const raw = COOKIE_HINT((resp.headers && resp.headers["set-cookie"]) || "");
  if (!raw) return [];
  const out = [];
  if (!raw.includes("httponly")) {
    out.push({
      title: "Session cookie missing HttpOnly",
      severity: "medium",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
      modality: "passive", confidence: "high", cwe: "CWE-1004",
      owasp: "A05:2021 - Security Misconfiguration",
      url, endpoint: url,
      description: "A cookie set here is readable from JavaScript, so any XSS on the origin exfiltrates the session immediately.",
      impact: "Full session hijack from a single XSS.",
      remediation: "Set HttpOnly on every session/auth cookie.",
      proof: raw.slice(0, 200),
      tags: ["passive", "cookie", "xss-chain"], scope: "host",
    });
  }
  if (isHttps && !raw.includes("secure")) {
    out.push({
      title: "Session cookie missing Secure flag",
      severity: "medium",
      cvssVector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
      modality: "passive", confidence: "high", cwe: "CWE-614",
      owasp: "A02:2021 - Cryptographic Failures",
      url, endpoint: url,
      description: "Cookie will be sent over plain HTTP, so a network attacker reading the wire gets the session.",
      impact: "Session theft over an untrusted network.",
      remediation: "Add `Secure` to the cookie.",
      proof: raw.slice(0, 200),
      tags: ["passive", "cookie"], scope: "host",
    });
  }
  if (!raw.includes("samesite")) {
    out.push({
      title: "Session cookie missing SameSite",
      severity: "low",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
      modality: "passive", confidence: "medium", cwe: "CWE-1275",
      owasp: "A01:2021 - Broken Access Control",
      url, endpoint: url,
      description: "No SameSite means a cross-site POST carries this cookie, which is the whole CSRF story.",
      impact: "CSRF attacks become viable.",
      remediation: "Set `SameSite=Lax` (or Strict) unless you truly need otherwise.",
      proof: raw.slice(0, 200),
      tags: ["passive", "cookie", "csrf"], scope: "host",
    });
  }
  return out;
}

export const PROBE_ORIGIN = "https://pbhx-test.example";

/**
 * Send an Origin header and see whether the server reflects it.
 *
 * Takes the target rather than just a response because the probe is the whole
 * point: a server that reflects an attacker origin while allowing credentials
 * is the finding.
 */
export function checkCors(target, path, resp, url) {
  // Always ask with an Origin header. A server that only emits ACAO when asked
  // is the normal case, so judging the baseline response finds nothing.
  let probe;
  try {
    probe = target.request(path, {}, "GET", null, { Origin: PROBE_ORIGIN });
  } catch {
    probe = resp;
  }
  const ph = probe.headers || {};
  const acao = ph["access-control-allow-origin"] || "";
  if (!acao) return [];
  const acac = (ph["access-control-allow-credentials"] || "").toLowerCase();
  if ((acao === "*" || /^https?:\/\//.test(acao)) && acac === "true") {
    return [{
      title: "CORS reflects any origin WITH credentials allowed",
      severity: "high",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
      modality: "passive", confidence: "high", cwe: "CWE-942",
      owasp: "A05:2021 - Security Misconfiguration",
      url, endpoint: url,
      description: "Access-Control-Allow-Origin echoes an attacker-controlled origin and Access-Control-Allow-Credentials is true. Any website can read authenticated responses from this endpoint.",
      impact: "Cross-origin data theft of every authenticated API call.",
      remediation: "Allowlist exact origins. Never reflect Origin when credentials are allowed.",
      proof: `ACAO: ${acao}\nACAC: true`,
      tags: ["passive", "cors", "critical-class"], scope: "host",
    }];
  }
  if (acao === "*") {
    return [{
      title: "Wildcard Access-Control-Allow-Origin",
      severity: "low",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
      modality: "passive", confidence: "high", cwe: "CWE-942",
      owasp: "A05:2021 - Security Misconfiguration",
      url, endpoint: url,
      description: "ACAO: * lets any site read this response.",
      impact: "Data exposure on endpoints meant to be private.",
      remediation: "Replace * with an explicit origin allowlist.",
      proof: "access-control-allow-origin: *",
      tags: ["passive", "cors"], scope: "host",
    }];
  }
  return [];
}

export function checkExposure(target, baseUrl, budget = 7) {
  const out = [];
  for (const [path, sev, desc] of EXPOSURE_PROBES.slice(0, budget)) {
    const r = target.request(path, {});
    if (r.status !== 200 && r.status !== 206) continue;
    // a SPA catch-all returns 200 for everything; a real body beats a 200
    if (r.headers["content-type"] && r.headers["content-type"].includes("text/html")
        && (r.body || "").length < 512) continue;
    out.push({
      title: `Exposed sensitive path: ${path}`,
      severity: sev,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      modality: "passive", confidence: "medium", cwe: "CWE-538",
      owasp: "A01:2021 - Broken Access Control",
      url: baseUrl + path, endpoint: baseUrl + path,
      description: `${desc} returned HTTP ${r.status} without authentication.`,
      impact: "Credential or source disclosure; often instant full compromise.",
      remediation: "Remove the file from the deploy artifact, add deny rules, and rotate anything that was inside it.",
      proof: `HTTP ${r.status}, ${(r.body || "").length} bytes`,
      tags: ["passive", "exposure"], scope: "host",
    });
  }
  return out;
}

export function checkLeakage(resp, url) {
  const low = (resp.body || "").toLowerCase();
  const out = [];
  for (const tok of ["debug=true", "whoops", "traceback", "stack trace",
                     "laravel_session", "error in your sql", "sql syntax",
                     "django debug"]) {
    if (low.includes(tok)) {
      out.push({
        title: "Debug information leaked in response body",
        severity: "medium",
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        modality: "passive", confidence: "high", cwe: "CWE-209",
        owasp: "A05:2021 - Security Misconfiguration",
        url, endpoint: url,
        description: `Response body contains '${tok}'. Debug mode or a raw exception is reachable by anyone.`,
        impact: "Leaks paths, library versions, queries, occasionally secrets.",
        remediation: "Disable debug output in production and return generic errors.",
        proof: tok,
        tags: ["passive", "info-leak"], scope: "host",
      });
      break;
    }
  }
  // HTML comments leak intent, hosts and occasionally credentials
  const comments = (resp.body || "").match(/<!--([\s\S]*?)-->/g) || [];
  for (const raw of comments.slice(0, 5)) {
    const note = raw.replace(/<!--|-->/g, "").trim();
    const n = note.toLowerCase();
    if (["password", "passwd", "secret", "api_key", "apikey", "token",
         "credential", "private_key", "todo", "fixme", "hack", "xxx", "admin"]
        .some((k) => n.includes(k)) && note.length > 12) {
      out.push({
        title: "Possible credential or internal note in HTML comment",
        severity: "medium",
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        modality: "passive", confidence: "medium", cwe: "CWE-798",
        owasp: "A05:2021 - Security Misconfiguration",
        url, endpoint: url,
        description: "An HTML comment contains something that looks like a credential or internal endpoint.",
        impact: "Direct credential disclosure from view-source.",
        remediation: "Strip comments in production builds.",
        proof: note.slice(0, 240),
        tags: ["info-leak", "comments", "secret"], scope: "host",
      });
      break;
    }
  }
  return out;
}

export function checkMixedContent(resp, url, isHttps) {
  if (!isHttps) return [];
  const hits = ((resp.body || "").match(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi) || [])
    .filter((h) => !h.includes("localhost") && !h.includes("127.0.0.1"));
  if (!hits.length) return [];
  return [{
    title: "Mixed content: HTTP subresources on an HTTPS page",
    severity: "medium",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    modality: "passive", confidence: "high", cwe: "CWE-319",
    owasp: "A02:2021 - Cryptographic Failures",
    url, endpoint: url,
    description: `${hits.length} http:// subresource(s) load on an https page. A network attacker can swap them.`,
    impact: "Script/asset tampering, keylogging via a swapped JS file.",
    remediation: "Serve every subresource over HTTPS.",
    proof: hits.slice(0, 6).join("\n"),
    tags: ["passive", "tls", "mixed-content"], scope: "host",
  }];
}

// ---- CSRF ------------------------------------------------------------------

const CSRF_NAMES = ["csrf", "xsrf", "_token", "authenticity_token",
                    "__requestverificationtoken", "anti_forgery"];

export function assessCsrf(html) {
  const m = html.match(/<input[^>]+name=["']([^"']*)["'][^>]*value=["']([^"']{6,})["']/i);
  const hasToken = !!m && CSRF_NAMES.some((n) => m[1].toLowerCase().includes(n));
  return { hasToken, tokenName: hasToken ? m[1] : "", risk: hasToken ? "low" : "high" };
}

export function csrfFinding(html, url) {
  const a = assessCsrf(html);
  if (a.risk === "low") return null;
  return {
    title: "Missing CSRF protection on POST form",
    severity: "high",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
    modality: "text", confidence: a.hasToken ? "low" : "medium", cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    url, endpoint: url,
    description: "A state-changing form with no per-request anti-CSRF token. An attacker can host a page that auto-submits this action while the victim is logged in, and the browser attaches their session cookie automatically.",
    impact: "Any action a logged-in user can perform, performed by someone else: password change, email change, purchase, delete.",
    remediation: "Per-session-per-request CSRF token, SameSite=Lax|Strict on the session cookie, and re-check Referer/Origin server-side.",
    proof: a.hasToken ? `token present but weak: ${a.tokenName}` : "no anti-CSRF token found on any POST form",
    tags: ["csrf", "passive", "forms"],
  };
}

// ---- IDOR -----------------------------------------------------------------

const ID_PARAM_RE = /^(id|.*_id|uuid|guid|key|doc|document|post|article|item|product|order|ticket|user|account|profile|file|object|record|row|entity|case|task|number|no|num|ref|slug|hash|token|uid|pid|cid|oid|sid|fid)$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUM_RE = /^\d{1,9}$/;

export function looksLikeId(name) { return ID_PARAM_RE.test(String(name || "").trim()); }

export function neighbours(value, count = 2) {
  const out = [];
  if (UUID_RE.test(value)) {
    const tail = parseInt(value.replace(/-/g, "").slice(-8), 16);
    for (let i = 1; i <= count; i += 1) {
      const hex = (tail + i).toString(16).padStart(8, "0");
      out.push(value.slice(0, value.replace(/-/g, "").length - 8) + hex);
    }
  } else if (NUM_RE.test(value)) {
    const base = Number(value);
    for (let i = 1; i <= count; i += 1) out.push(String(base + i));
  } else if (/^[a-z]+$/i.test(value)) {
    for (const ch of ["b", "c"]) {
      out.push(value.length > 1 ? value.slice(0, -1) + ch : value + ch);
    }
  }
  return out;
}

const PII_LINE_RE = /(?:[\w.+-]+@[\w-]+\.[\w.]+)|(?:(?:\+?\d[\d\s().-]{8,17}\d))|(?:(?:\b\d{4}[- ]\d{2}[- ]\d{2}\b))|(?:(?:\b(?:balance|salary|iban|ssn)\b\s*[:=]))/gi;

export function piiHits(body, limit = 6) {
  const out = [];
  const re = new RegExp(PII_LINE_RE.source, "gi");
  let m = re.exec(body || "");
  while (m && out.length < limit) {
    const frag = (body || "").slice(Math.max(0, m.index - 40), m.index + m[0].length + 40)
      .replace(/\s+/g, " ").trim();
    if (!out.includes(frag)) out.push(frag.slice(0, 160));
    m = re.exec(body || "");
  }
  return out;
}

/**
 * One step sideways from `original`. Never a sweep, never a write.
 */
export function analyzeIdor(target, path, param, original, budget = 2) {
  const baseline = target.request(path, { [param]: original });
  const result = { vulnerable: false, signals: [], probeValue: "", leaked: [] };

  for (const candidate of neighbours(original, budget)) {
    const probe = target.request(path, { [param]: candidate });
    if (!probe.body) continue;
    if ([401, 403, 404].includes(probe.status) && ![401, 403].includes(baseline.status)) {
      result.signals.push(`${param}=${candidate} correctly denied (HTTP ${probe.status})`);
      continue;
    }
    const a = baseline.body || "";
    const b = probe.body || "";
    if (a === b) continue;

    const leaked = piiHits(b).filter((f) => !a.includes(f));
    if (leaked.length) {
      result.signals.push(
        `${param}=${candidate} returned ${probe.status} with personal data that was not in the ${param}=${original} response`);
      result.vulnerable = true;
      result.leaked = leaked.slice(0, 6);
      result.probeValue = candidate;
      result.snippet = leaked[0];
      break;
    }
  }
  return result;
}

export function idorFinding(r, url) {
  if (!r || !r.vulnerable) return null;
  const high = r.leaked.some((f) => /email|balance|ssn|card|iban|salary|password|token/i.test(f));
  return {
    title: `IDOR: '${r.param}' returns another object's personal data`,
    severity: high ? "critical" : "high",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    modality: "text", confidence: high ? "high" : "medium", cwe: "CWE-639",
    owasp: "A01:2021 - Broken Access Control",
    url, endpoint: url, parameter: r.param,
    description: `An unauthenticated request for ${r.param}=${r.probeValue} returned content that differs from ${r.param}=${r.original} and contains personal data. The server checks whether you can reach the URL, not whether you own the object.`,
    impact: "Read (and often write) every record of every user in the system by incrementing one integer. This is the most commonly exploited web bug in bug bounties.",
    remediation: "Authorise every access server-side against the session owner. Never rely on an unguessable id. Use opaque UUIDs *as well as* real authorisation - UUIDs hide, they do not protect.",
    proof: r.signals.join("; "),
    tags: ["idor", "access-control", "unauthenticated", "owasp-a1"],
  };
}

export { escapeHtml };