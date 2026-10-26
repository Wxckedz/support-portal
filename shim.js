(function () {
  "use strict";
  var G = typeof globalThis !== "undefined" ? globalThis : self;
  if (G.__xrpShim) return;
  Object.defineProperty(G, "__xrpShim", { value: true });
  var C = __XRP_CONFIG__;
  var LOC = G.location;
  var MOUNT = C.prefix.replace(/\/+$/, "") + "/";
  var ABS = /^\s*(?:(?:https?|wss?):)?\/\//i;
  var handoffInProgress = false;
  var handoffStorageKey = "__xrpLoginHandoff";
  var pendingHandoff = null;
  try { pendingHandoff = JSON.parse(G.sessionStorage.getItem(handoffStorageKey)); }
  catch (e) {}

  function handoffSavedSession(value, responseURL, redirectURL) {
    if (value !== "1" || handoffInProgress || !G.document) return;
    try { if (new URL(responseURL, LOC.href).origin !== LOC.origin) return; }
    catch (e) { return; }
    try {
      var destination = new URL(redirectURL || "https://x.com/");
      if (destination.protocol !== "https:" || destination.username || destination.password || destination.hostname === LOC.hostname) return;
    } catch (e) { return; }
    try {
      if (G.top && G.top !== G && typeof G.top.__xrpHandoff === "function") {
        G.top.__xrpHandoff(value, responseURL, destination.href);
        return;
      }
    } catch (e) {}
    handoffInProgress = true;
    var now = Date.now();
    var expiresAt = pendingHandoff && pendingHandoff.url === destination.href &&
      typeof pendingHandoff.expiresAt === "number" && pendingHandoff.expiresAt > now && pendingHandoff.expiresAt <= now + 30000
      ? pendingHandoff.expiresAt : now + 30000;
    pendingHandoff = { url: destination.href, expiresAt: expiresAt };
    try { G.sessionStorage.setItem(handoffStorageKey, JSON.stringify(pendingHandoff)); }
    catch (e) {}
    if (document.body) {
      var notice = document.createElement("p");
      notice.setAttribute("role", "status");
      notice.textContent = "Session saved. Continuing…";
      document.body.prepend(notice);
    }
    setTimeout(function () {
      try { G.sessionStorage.removeItem(handoffStorageKey); }
      catch (e) {}
      var policy = document.createElement("meta");
      policy.name = "referrer";
      policy.content = "no-referrer";
      if (document.head) document.head.appendChild(policy);
      LOC.replace(destination.href);
    }, 250);
  }
  Object.defineProperty(G, "__xrpHandoff", { value: handoffSavedSession });

  function allowed(h) {
    h = String(h).toLowerCase();
    if (C.exact.indexOf(h) >= 0) return true;
    for (var i = 0; i < C.suffix.length; i++) {
      var s = C.suffix[i];
      if (h.length > s.length && h.slice(-s.length) === s) return true;
    }
    return false;
  }

  function rw(input) {
    var s;
    if (typeof input === "string") s = input;
    else if (typeof URL !== "undefined" && input instanceof URL) s = input.href;
    else return input;
    if (!ABS.test(s)) return input;
    var u;
    try { u = new URL(s.trim(), LOC.href); } catch (e) { return input; }
    if (!/^(https?|wss?):$/.test(u.protocol) || u.host === LOC.host) return input;
    if (u.port && u.port !== "443" && u.port !== "80") return input;
    if (u.username || u.password) return input;
    var h = u.hostname.toLowerCase();
    if (!allowed(h)) return input;
    var ws = u.protocol === "ws:" || u.protocol === "wss:";
    var scheme = ws ? (LOC.protocol === "https:" ? "wss:" : "ws:") : LOC.protocol;
    var mount = C.exact.indexOf(h) >= 0 ? "" : MOUNT + h;
    return scheme + "//" + LOC.host + mount + u.pathname + u.search + u.hash;
  }
  function rwStr(v) { return typeof v === "string" ? rw(v) : v; }
  function rwSrcset(v) {
    if (typeof v !== "string" || v.indexOf("//") < 0) return v;
    return v.split(",").map(function (part) {
      var m = /^(\s*)(\S+)(.*)$/.exec(part);
      return m ? m[1] + rw(m[2]) + m[3] : part;
    }).join(",");
  }
  function rwCss(v) {
    if (typeof v !== "string" || v.indexOf("url(") < 0) return v;
    return v.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, function (all, q, u) {
      var n = rw(u);
      return n === u ? all : "url(" + q + n + q + ")";
    });
  }
  Object.defineProperty(G, "__xrpRewrite", { value: rw });

  if (typeof G.fetch === "function") {
    var oFetch = G.fetch;
    G.fetch = function fetch(input, init) {
      try {
        if (typeof input === "string" || (typeof URL !== "undefined" && input instanceof URL)) {
          input = rw(input);
        } else if (input && typeof input.url === "string") {
          var n = rw(input.url);
          if (n !== input.url) input = new Request(n, input);
        }
      } catch (e) {}
      return oFetch.call(G, input, init).then(function (response) {
        handoffSavedSession(response.headers.get("X-Xrevp-Session-Saved"), response.url, response.headers.get("X-Xrevp-Redirect-Url"));
        return response;
      });
    };
  }
  if (G.XMLHttpRequest && G.XMLHttpRequest.prototype) {
    var oOpen = G.XMLHttpRequest.prototype.open;
    G.XMLHttpRequest.prototype.open = function open(method, url) {
      var a = Array.prototype.slice.call(arguments);
      if (a.length > 1) a[1] = rw(a[1]);
      this.addEventListener("load", function () {
        handoffSavedSession(this.getResponseHeader("X-Xrevp-Session-Saved"), this.responseURL, this.getResponseHeader("X-Xrevp-Redirect-Url"));
      }, { once: true });
      return oOpen.apply(this, a);
    };
  }
  function wrapCtor(name) {
    var O = G[name];
    if (typeof O !== "function") return;
    var W = function () {
      var a = Array.prototype.slice.call(arguments);
      if (a.length > 0) a[0] = rw(a[0]);
      return Reflect.construct(O, a, new.target || O);
    };
    W.prototype = O.prototype;
    Object.setPrototypeOf(W, O);
    try { Object.defineProperty(W, "name", { value: name }); } catch (e) {}
    G[name] = W;
  }
  ["WebSocket", "EventSource", "Worker", "SharedWorker"].forEach(wrapCtor);
  if (typeof G.importScripts === "function") {
    var oImport = G.importScripts;
    G.importScripts = function importScripts() {
      return oImport.apply(G, Array.prototype.map.call(arguments, rw));
    };
  }
  if (G.navigator && typeof G.navigator.sendBeacon === "function") {
    var oBeacon = G.navigator.sendBeacon;
    G.navigator.sendBeacon = function sendBeacon(url, data) {
      return oBeacon.call(G.navigator, rw(url), data);
    };
  }
  if (G.ServiceWorkerContainer && G.ServiceWorkerContainer.prototype) {
    G.ServiceWorkerContainer.prototype.register = function register() {
      return Promise.reject(new Error("service workers are disabled by the proxy"));
    };
  }

  if (typeof document === "undefined" || typeof Element === "undefined") return;

  var URL_ATTRS = { src: 1, href: 1, poster: 1, action: 1, formaction: 1 };
  var oSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function setAttribute(name, value) {
    var n = String(name).toLowerCase();
    if (URL_ATTRS[n] === 1) value = rwStr(String(value));
    else if (n === "srcset" || n === "imagesrcset") value = rwSrcset(String(value));
    else if (n === "style") value = rwCss(String(value));
    return oSetAttr.call(this, name, value);
  };
  function patchSetter(proto, prop, fn) {
    if (!proto) return;
    var d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set || !d.configurable) return;
    Object.defineProperty(proto, prop, {
      configurable: true, enumerable: d.enumerable, get: d.get,
      set: function (v) { return d.set.call(this, fn(v)); }
    });
  }
  function proto(name) { return G[name] && G[name].prototype; }
  var toUrl = function (v) { return rwStr(typeof v === "string" ? v : String(v)); };
  [["HTMLImageElement", "src"], ["HTMLScriptElement", "src"], ["HTMLMediaElement", "src"],
   ["HTMLSourceElement", "src"], ["HTMLTrackElement", "src"], ["HTMLIFrameElement", "src"],
   ["HTMLEmbedElement", "src"], ["HTMLInputElement", "src"], ["HTMLLinkElement", "href"],
   ["HTMLAnchorElement", "href"], ["HTMLAreaElement", "href"], ["HTMLVideoElement", "poster"],
   ["HTMLFormElement", "action"]].forEach(function (p) { patchSetter(proto(p[0]), p[1], toUrl); });
  patchSetter(proto("HTMLImageElement"), "srcset", rwSrcset);
  patchSetter(proto("HTMLSourceElement"), "srcset", rwSrcset);
  patchSetter(proto("HTMLLinkElement"), "imageSrcset", rwSrcset);

  var styleProto = Object.getPrototypeOf(document.documentElement.style);
  ["backgroundImage", "background", "cssText", "listStyleImage", "maskImage", "borderImageSource"].forEach(function (p) {
    for (var o = styleProto; o; o = Object.getPrototypeOf(o)) {
      if (Object.getOwnPropertyDescriptor(o, p)) { patchSetter(o, p, rwCss); break; }
    }
  });
  if (G.CSSStyleDeclaration) {
    var oSetProp = G.CSSStyleDeclaration.prototype.setProperty;
    G.CSSStyleDeclaration.prototype.setProperty = function setProperty(n, v, p) {
      return oSetProp.call(this, n, rwCss(v), p);
    };
  }

  var cookieOwner = proto("Document");
  var cd = cookieOwner && Object.getOwnPropertyDescriptor(cookieOwner, "cookie");
  if (cd && cd.set && cd.configurable) {
    var insecure = LOC.protocol !== "https:";
    Object.defineProperty(cookieOwner, "cookie", {
      configurable: true, enumerable: cd.enumerable, get: cd.get,
      set: function (v) {
        var parts = String(v).split(";"), out = [parts[0]];
        for (var i = 1; i < parts.length; i++) {
          var k = parts[i].trim().toLowerCase();
          if (k.indexOf("domain=") === 0) continue;
          if (insecure && k === "secure") continue;
          if (insecure && k.replace(/\s+/g, "") === "samesite=none") { out.push(" SameSite=Lax"); continue; }
          out.push(parts[i]);
        }
        return cd.set.call(this, out.join(";"));
      }
    });
  }

  // NOTE: the previous "keepSigningSvgs" MutationObserver was removed. It
  // observed the entire document (childList + subtree) and re-appended cloned
  // spinner SVGs to the body the moment they disappeared. That DOM mutation
  // runs inside React's hydration/Suspense window — React 18 assumes exclusive
  // ownership of the DOM, so an external appendChild mid-reconciliation can
  // corrupt its internal bookkeeping and leave the server-rendered jetfuel
  // onboarding form unmounted (the "form appears then disappears" bug). It was
  // only cosmetic (preserving a loading spinner), so removing it is safe.

  if (typeof G.open === "function") {
    var oWinOpen = G.open;
    G.open = function open(url) {
      var a = Array.prototype.slice.call(arguments);
      if (a.length > 0) a[0] = rw(a[0]);
      return oWinOpen.apply(G, a);
    };
  }

  if (G.navigation && typeof G.navigation.addEventListener === "function") {
    G.navigation.addEventListener("navigate", function (e) {
      try {
        if (handoffInProgress) return;
        if (!e.cancelable || e.hashChange || e.downloadRequest || e.formData) return;
        var n = rw(e.destination.url);
        if (n !== e.destination.url) { e.preventDefault(); LOC.assign(n); }
      } catch (err) {}
    });
  }
  if (pendingHandoff) {
    var now = Date.now();
    if (typeof pendingHandoff.expiresAt === "number" && pendingHandoff.expiresAt > now && pendingHandoff.expiresAt <= now + 30000) {
      handoffSavedSession("1", LOC.href, pendingHandoff.url);
    } else {
      try { G.sessionStorage.removeItem(handoffStorageKey); }
      catch (e) {}
    }
  }
})();
