/* Encrypted static workspace. No password, key, or plaintext is persisted here. */
(function (root) {
  'use strict';
  const VIRTUAL_ORIGIN = 'https://cover-vault.invalid';
  const CHANNEL = 'cover-vault-navigation-v1';
  const CHILD_CSP = "default-src 'none'; script-src 'unsafe-inline' blob:; style-src 'unsafe-inline' blob:; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src blob:; object-src blob:; form-action 'none'; base-uri 'none'";

  function failure(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
  }
  function decodeBase64(value) {
    if (typeof value !== 'string' || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw failure('format', 'The encrypted package has an invalid format.');
    const raw = root.atob(value);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
    return bytes;
  }
  function validPath(path) {
    return typeof path === 'string' && path.length > 0 && !/[\\?#\u0000-\u001f]/.test(path) && !path.startsWith('/') &&
      path.split('/').every(part => part && part !== '.' && part !== '..');
  }
  function resolveRoute(raw, currentPath) {
    if (typeof raw !== 'string' || !raw.trim() || raw.trim().startsWith('#')) return null;
    try {
      const url = new URL(raw, new URL(currentPath, VIRTUAL_ORIGIN + '/'));
      if (url.origin !== VIRTUAL_ORIGIN) return null;
      const path = decodeURIComponent(url.pathname.slice(1));
      return validPath(path) ? {path, hash: url.hash, search: url.search} : null;
    } catch (_) { return null; }
  }
  function validateBundle(bundle) {
    if (!bundle || bundle.version !== 1 || !validPath(bundle.entry) || !Array.isArray(bundle.files)) throw failure('format', 'The encrypted workspace has an invalid format.');
    const paths = new Set();
    for (const file of bundle.files) {
      if (!file || !validPath(file.path) || paths.has(file.path) || typeof file.mime !== 'string' || /[\r\n]/.test(file.mime)) throw failure('format', 'The encrypted workspace has an invalid file record.');
      const inline = typeof file.data === 'string';
      const lazy = typeof file.asset === 'string' && /^encrypted\/[a-f0-9]{64}\.bin$/.test(file.asset) && typeof file.iv === 'string';
      if (inline === lazy || !inline && !lazy) throw failure('format', 'The encrypted workspace has an invalid file record.');
      if (lazy && decodeBase64(file.iv).length !== 12) throw failure('format', 'The encrypted workspace has an invalid file record.');
      paths.add(file.path);
    }
    const entry = bundle.files.find(file => file.path === bundle.entry);
    if (!entry || typeof entry.data !== 'string' || !/^text\/html(?:;|$)/i.test(entry.mime)) throw failure('format', 'The encrypted workspace has no valid entry page.');
    return bundle;
  }
  async function gunzip(bytes) {
    if (typeof root.DecompressionStream !== 'function') throw failure('browser', 'This browser cannot open compressed workspaces. Use a current version of Chrome, Edge, Firefox, or Safari.');
    return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new root.DecompressionStream('gzip'))).arrayBuffer());
  }
  async function decryptBundle(vault, password) {
    if (!root.crypto || !root.crypto.subtle) throw failure('browser', 'Secure decryption is unavailable. Open this workspace over HTTPS in a current browser.');
    if (!vault || vault.version !== 1 || vault.cipher !== 'AES-GCM' || !vault.kdf || vault.kdf.name !== 'PBKDF2' || vault.kdf.hash !== 'SHA-256' || vault.kdf.iterations !== 600000) throw failure('format', 'The encrypted package has an unsupported format.');
    const salt = decodeBase64(vault.kdf.salt), iv = decodeBase64(vault.iv), payload = decodeBase64(vault.payload);
    if (salt.length < 16 || salt.length > 64 || iv.length !== 12 || payload.length < 17) throw failure('format', 'The encrypted package has an invalid format.');
    const passwordBytes = new TextEncoder().encode(password);
    let key, plain;
    try {
      const material = await root.crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
      key = await root.crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: vault.kdf.iterations}, material, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
    } finally { passwordBytes.fill(0); password = ''; }
    try {
      plain = new Uint8Array(await root.crypto.subtle.decrypt({name: 'AES-GCM', iv, tagLength: 128}, key, payload));
    } catch (_) { throw failure('password', 'That password did not open the workspace. Please try again.'); }
    let decoded;
    try {
      decoded = await gunzip(plain);
      const bundle = validateBundle(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(decoded)));
      return {bundle, key};
    } finally { plain.fill(0); if (decoded) decoded.fill(0); }
  }

  // This bridge contains no credentials and stays inert in a saved standalone copy.
  function childBridge(origin, channel) {
    if (parent === window) return;
    document.addEventListener('click', function (event) {
      const node = event.target instanceof Element ? event.target.closest('a[data-vault-route]') : null;
      if (!node || event.button !== 0) return;
      event.preventDefault();
      parent.postMessage({channel, path: node.dataset.vaultRoute, hash: node.dataset.vaultHash || '', download: node.hasAttribute('download')}, origin);
    }, true);
  }

  let initialized = false;
  function init() {
    if (initialized || !root.document) return;
    initialized = true;
    const doc = root.document, $ = id => doc.getElementById(id);
    const gate = $('gate'), workspace = $('workspace'), form = $('unlock-form'), passwordInput = $('workspace-password');
    const submit = $('unlock-button'), show = $('show-password'), status = $('gate-status'), navStatus = $('navigation-status'), host = $('frame-host'), back = $('back-to-editor');
    let active = null, iframe = null, sessionVersion = 0, navigationVersion = 0;

    function setStatus(message, isError) { status.textContent = message; status.dataset.error = isError ? 'true' : 'false'; }
    function setBusy(busy) { submit.disabled = busy; passwordInput.disabled = busy; show.disabled = busy; submit.textContent = busy ? 'Opening workspace…' : 'Unlock workspace'; form.setAttribute('aria-busy', String(busy)); }
    function assertActive(context) { if (active !== context || context.closed) throw failure('cancelled', 'Workspace locked.'); }
    function clearContext(context) {
      if (!context) return;
      context.closed = true;
      context.abort.abort();
      for (const url of context.urls.values()) root.URL.revokeObjectURL(url);
      for (const bytes of context.buffers) bytes.fill(0);
      context.urls.clear(); context.buffers.clear(); context.reads.clear(); context.files.clear();
      context.key = null; context.bundle = null;
    }
    function lock(message) {
      sessionVersion += 1; navigationVersion += 1;
      host.replaceChildren(); iframe = null;
      const old = active; active = null; clearContext(old);
      workspace.hidden = true; gate.hidden = false; back.hidden = true; navStatus.textContent = '';
      form.reset(); passwordInput.value = ''; passwordInput.type = 'password';
      show.textContent = 'Show'; show.setAttribute('aria-label', 'Show password'); show.setAttribute('aria-pressed', 'false');
      setBusy(false); setStatus(message || 'Workspace locked.', false); passwordInput.focus();
    }
    async function readFile(context, path) {
      assertActive(context);
      if (context.reads.has(path)) return context.reads.get(path);
      const file = context.files.get(path);
      if (!file) throw failure('missing', 'This linked file is not included in the workspace.');
      const pending = (async function () {
        let bytes;
        if (typeof file.data === 'string') bytes = decodeBase64(file.data);
        else {
          const response = await root.fetch(new URL(file.asset, root.location.href).href, {credentials: 'omit', cache: 'force-cache', signal: context.abort.signal});
          if (!response.ok) throw failure('network', 'This encrypted file could not be loaded. Check your connection and try again.');
          const encrypted = await response.arrayBuffer();
          assertActive(context);
          const compressed = new Uint8Array(await root.crypto.subtle.decrypt({name: 'AES-GCM', iv: decodeBase64(file.iv), tagLength: 128}, context.key, encrypted));
          try { bytes = await gunzip(compressed); } finally { compressed.fill(0); }
        }
        try { assertActive(context); } catch (error) { bytes.fill(0); throw error; }
        context.buffers.add(bytes);
        return bytes;
      })();
      context.reads.set(path, pending);
      try { return await pending; } catch (error) { context.reads.delete(path); throw error; }
    }
    async function resourceURL(context, path) {
      assertActive(context);
      if (context.urls.has(path)) return context.urls.get(path);
      const bytes = await readFile(context, path);
      assertActive(context);
      if (context.urls.has(path)) return context.urls.get(path);
      const url = root.URL.createObjectURL(new Blob([bytes], {type: context.files.get(path).mime}));
      context.urls.set(path, url);
      return url;
    }
    async function prepareHTML(context, path) {
      const bytes = await readFile(context, path);
      const html = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
      // A detached HTML document can still request images while parsing. Its
      // temporary base prevents relative requests before assets become blobs;
      // the parent policy also prohibits network images and fonts.
      const parsed = new DOMParser().parseFromString('<!doctype html><base href="about:blank">' + html, 'text/html');
      parsed.querySelectorAll('base,meta[http-equiv="refresh" i]').forEach(node => node.remove());
      const policy = parsed.createElement('meta'); policy.httpEquiv = 'Content-Security-Policy'; policy.content = CHILD_CSP; parsed.head.prepend(policy);
      const referrer = parsed.createElement('meta'); referrer.name = 'referrer'; referrer.content = 'no-referrer'; parsed.head.prepend(referrer);
      const jobs = [];
      for (const anchor of parsed.querySelectorAll('a[href]')) {
        const href = anchor.getAttribute('href');
        if (!href || href.trim().startsWith('#')) continue;
        const route = resolveRoute(href, path);
        if (route) { anchor.dataset.vaultRoute = route.path; anchor.dataset.vaultHash = route.hash; }
        else if (/^(https?:|mailto:|tel:|\/\/)/i.test(href.trim())) { anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; }
        else if (!/^(blob:|data:)/i.test(href.trim())) { anchor.removeAttribute('href'); anchor.setAttribute('aria-disabled', 'true'); }
      }
      function rewriteAttribute(node, attribute) {
        const value = node.getAttribute(attribute);
        if (!value || /^(data:|blob:|#)/i.test(value.trim())) return;
        const route = resolveRoute(value, path);
        if (!route || !context.files.has(route.path)) { node.removeAttribute(attribute); return; }
        jobs.push(resourceURL(context, route.path).then(url => node.setAttribute(attribute, url + route.hash)));
      }
      for (const node of parsed.querySelectorAll('[src]')) rewriteAttribute(node, 'src');
      for (const node of parsed.querySelectorAll('[poster]')) rewriteAttribute(node, 'poster');
      // The supplied pages use ordinary src images; discard unneeded network hints.
      parsed.querySelectorAll('[srcset]').forEach(node => node.removeAttribute('srcset'));
      for (const node of parsed.querySelectorAll('link[href]')) {
        if (['stylesheet', 'icon'].includes(node.rel)) rewriteAttribute(node, 'href'); else node.remove();
      }
      async function rewriteCSS(css) {
        const matches = [...css.matchAll(/url\(\s*(['"]?)(.*?)\1\s*\)/gi)];
        let result = css;
        const replacements = await Promise.all(matches.map(async match => {
          const value = match[2];
          if (/^(data:|blob:|#)/i.test(value.trim())) return [match[0], match[0]];
          const route = resolveRoute(value, path);
          if (!route || !context.files.has(route.path)) return [match[0], 'url("data:,")'];
          return [match[0], 'url("' + await resourceURL(context, route.path) + route.hash + '")'];
        }));
        for (const [before, after] of replacements) if (before !== after) result = result.split(before).join(after);
        return result;
      }
      for (const node of parsed.querySelectorAll('style')) jobs.push(rewriteCSS(node.textContent).then(css => { node.textContent = css; }));
      for (const node of parsed.querySelectorAll('[style]')) jobs.push(rewriteCSS(node.getAttribute('style')).then(css => node.setAttribute('style', css)));
      await Promise.all(jobs); assertActive(context);
      const bridge = parsed.createElement('script');
      bridge.dataset.vaultBridge = 'true';
      bridge.textContent = '(' + childBridge.toString() + ')(' + JSON.stringify(root.location.origin) + ',' + JSON.stringify(CHANNEL) + ');';
      parsed.body.append(bridge);
      return '<!doctype html>\n' + parsed.documentElement.outerHTML;
    }
    async function mount(path, hash) {
      const context = active;
      if (!context || !context.files.has(path)) { navStatus.textContent = 'This linked file is not included in the workspace.'; return; }
      const navigation = ++navigationVersion;
      navStatus.textContent = 'Opening…';
      try {
        const file = context.files.get(path), isHTML = /^text\/html(?:;|$)/i.test(file.mime);
        const content = isHTML ? await prepareHTML(context, path) : await resourceURL(context, path);
        assertActive(context);
        if (navigation !== navigationVersion) return;
        const frame = doc.createElement('iframe');
        frame.title = isHTML ? 'Cover workspace' : 'Workspace document'; frame.referrerPolicy = 'no-referrer';
        if (isHTML) frame.srcdoc = content; else frame.src = content + (hash || '');
        frame.addEventListener('load', function () {
          if (iframe !== frame) return;
          navStatus.textContent = path === context.bundle.entry ? '' : path.split('/').pop();
          if (isHTML && hash) {
            try { frame.contentDocument.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView(); } catch (_) { /* A missing fragment leaves the page at its start. */ }
          }
        });
        iframe = frame; host.replaceChildren(frame); back.hidden = path === context.bundle.entry;
      } catch (error) {
        if (active === context && navigation === navigationVersion && error.code !== 'cancelled') navStatus.textContent = error.code === 'network' || error.code === 'missing' ? error.message : 'This document could not be opened. Try again or lock and reopen the workspace.';
      }
    }
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (submit.disabled || !passwordInput.value) return;
      const attempt = ++sessionVersion;
      let password = passwordInput.value; passwordInput.value = '';
      setBusy(true); setStatus('Opening the encrypted workspace…', false);
      try {
        const response = await root.fetch(new URL('vault.json', root.location.href).href, {credentials: 'omit', cache: 'no-store'});
        if (!response.ok) throw failure('network', 'The encrypted workspace could not be loaded. Check your connection and try again.');
        const result = await decryptBundle(await response.json(), password);
        password = '';
        if (attempt !== sessionVersion) return;
        active = {bundle: result.bundle, key: result.key, files: new Map(result.bundle.files.map(file => [file.path, file])), reads: new Map(), urls: new Map(), buffers: new Set(), abort: new AbortController(), closed: false};
        gate.hidden = true; workspace.hidden = false; setStatus('', false); setBusy(false);
        await mount(result.bundle.entry, '');
      } catch (error) {
        if (attempt !== sessionVersion) return;
        password = ''; passwordInput.value = ''; setBusy(false);
        setStatus(['password', 'network', 'browser', 'format'].includes(error.code) ? error.message : 'The workspace could not be opened. Check your connection and try again.', true);
        passwordInput.focus();
      } finally { password = ''; }
    });
    show.addEventListener('click', function () {
      const revealed = passwordInput.type === 'password'; passwordInput.type = revealed ? 'text' : 'password';
      show.textContent = revealed ? 'Hide' : 'Show'; show.setAttribute('aria-label', revealed ? 'Hide password' : 'Show password'); show.setAttribute('aria-pressed', String(revealed));
    });
    $('lock-workspace').addEventListener('click', () => lock());
    back.addEventListener('click', () => { if (active) mount(active.bundle.entry, ''); });
    root.addEventListener('message', async function (event) {
      if (!active || !iframe || event.source !== iframe.contentWindow || event.origin !== root.location.origin || !event.data || event.data.channel !== CHANNEL) return;
      const path = event.data.path;
      if (typeof path !== 'string' || !active.files.has(path)) { navStatus.textContent = 'This linked file is not included in the workspace.'; return; }
      const hash = typeof event.data.hash === 'string' && event.data.hash.startsWith('#') ? event.data.hash : '';
      if (event.data.download === true) {
        const context = active;
        try {
          const url = await resourceURL(context, path); assertActive(context);
          const anchor = doc.createElement('a'); anchor.href = url; anchor.download = path.split('/').pop(); doc.body.append(anchor); anchor.click(); anchor.remove();
        } catch (error) { if (active === context) navStatus.textContent = 'This download could not be opened. Try again.'; }
      } else mount(path, hash);
    });
    root.addEventListener('pagehide', () => lock('Workspace locked. Enter the password to reopen it.'));
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(root.location.hostname);
    if (!root.isSecureContext || root.location.protocol !== 'https:' && !local || !root.crypto?.subtle) {
      submit.disabled = true; passwordInput.disabled = true; show.disabled = true;
      setStatus('This workspace needs HTTPS. Open the secure https:// version of this page in a current browser.', true);
    } else if (typeof root.DecompressionStream !== 'function') {
      submit.disabled = true; setStatus('This browser cannot open compressed workspaces. Use a current version of Chrome, Edge, Firefox, or Safari.', true);
    } else passwordInput.focus();
  }
  root.CoverVault = Object.freeze({decryptBundle, validateBundle, resolveRoute, init});
  if (root.document) {
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', init, {once: true}); else init();
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
