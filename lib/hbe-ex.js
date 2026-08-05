(() => {
  'use strict';

  const cryptoObj = window.crypto || window.msCrypto;
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder('utf-8', { fatal: true });
  const storageKey = 'hbe.v4.ex.' + window.location.pathname;
  const keyBits = 256;
  const tagBits = 128;
  const fileMagic = new TextEncoder().encode('HBEEXFILE\n');
  const fileKeyCache = new Map();
  let lastContainer = null;

  function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
      throw new Error('Invalid hexadecimal data');
    }

    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function deriveKey(password, salt, iterations) {
    const baseKey = await cryptoObj.subtle.importKey(
      'raw',
      textEncoder.encode(String(password)),
      { name: 'PBKDF2' },
      false,
      ['deriveKey'],
    );
    return cryptoObj.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: keyBits },
      true,
      ['decrypt'],
    );
  }

  async function decryptWithKey(key, nonce, ciphertext) {
    const plain = await cryptoObj.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: tagBits },
      key,
      ciphertext,
    );
    return textDecoder.decode(plain);
  }

  async function decryptBytesWithKey(key, nonce, ciphertext) {
    const plain = await cryptoObj.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: tagBits },
      key,
      ciphertext,
    );
    return new Uint8Array(plain);
  }

  function rememberKey(saltHex, key) {
    if (saltHex && key) {
      fileKeyCache.set(saltHex.toLowerCase(), key);
    }
  }

  function getContainers() {
    return Array.from(document.querySelectorAll('[data-hbe-ex-container="true"]'));
  }

  function getWireData(container) {
    const dataElement = container.querySelector('script[type="hbeData"]');
    if (!dataElement) {
      return null;
    }

    const data = container.dataset;
    return {
      format: data.hbeFormat || '4',
      salt: data.salt,
      nonce: data.nonce,
      iterations: parseInt(data.kdfIterations, 10) || 250000,
      autoSave: data.autoSave === 'true',
      mode: data.hbeExMode || (container.id === 'hexo-blog-encrypt-ex' ? 'full' : 'segment'),
      wrongPassMessage: data.wpm || 'Wrong password.',
      wrongHashMessage: data.whm || data.wpm || 'Wrong password.',
      encryptedData: dataElement.textContent.trim(),
    };
  }

  function showError(container, message) {
    const error = container.querySelector('[role="alert"]');
    if (error) {
      error.textContent = message;
      return;
    }
    window.alert(message);
  }

  function setBusy(container, busy) {
    const input = container.querySelector('input[type="password"]');
    const button = container.querySelector('button');
    if (input) input.disabled = busy;
    if (button) button.disabled = busy;
  }

  function getStoredEntries() {
    try {
      const value = JSON.parse(window.localStorage.getItem(storageKey) || '[]');
      return Array.isArray(value) ? value : [];
    } catch (error) {
      console.log(error);
      return [];
    }
  }

  async function loadStoredKey(saltHex) {
    const entry = getStoredEntries().find((item) => item.salt === saltHex);
    if (!entry || typeof entry.key !== 'string') {
      return null;
    }

    try {
      return await cryptoObj.subtle.importKey(
        'raw',
        base64ToBytes(entry.key),
        { name: 'AES-GCM' },
        true,
        ['decrypt'],
      );
    } catch (error) {
      console.log(error);
      return null;
    }
  }

  async function saveStoredKey(saltHex, key) {
    try {
      const raw = await cryptoObj.subtle.exportKey('raw', key);
      const entries = getStoredEntries().filter((item) => item.salt !== saltHex);
      entries.push({
        salt: saltHex,
        key: bytesToBase64(new Uint8Array(raw)),
      });
      window.localStorage.setItem(storageKey, JSON.stringify(entries));
    } catch (error) {
      // localStorage and key export are both best-effort features.
      console.log(error);
    }
  }

  function makeExecutableScripts(wrapper) {
    wrapper.querySelectorAll('script').forEach((oldScript) => {
      const newScript = document.createElement('script');
      Array.from(oldScript.attributes).forEach((attribute) => {
        newScript.setAttribute(attribute.name, attribute.value);
      });
      newScript.text = oldScript.text;
      oldScript.parentNode.replaceChild(newScript, oldScript);
    });
  }

  function plaintextToWrapper(plaintext) {
    const wrapper = document.createElement('div');
    wrapper.innerHTML = plaintext;
    makeExecutableScripts(wrapper);
    return wrapper;
  }

  function assignContextKey(wrapper, key, saltHex) {
    wrapper.querySelectorAll('[data-hbe-file-renderer="true"]').forEach((renderer) => {
      renderer.__hbeFileContextKey = key;
      renderer.__hbeFileContextSalt = String(saltHex).toLowerCase();
    });
  }

  function revealFullPost(container, plaintext, key, saltHex) {
    const wrapper = plaintextToWrapper(plaintext);
    wrapper.id = 'hexo-blog-encrypt';
    wrapper.classList.add('hbe', 'hbe-decrypted-content');
    assignContextKey(wrapper, key, saltHex);
    container.parentNode.replaceChild(wrapper, container);
    refreshAfterDecrypt();
  }

  function revealSegment(container, plaintext, key, saltHex) {
    const showEncryptAgain = isLastContainer(container);
    const wrapper = plaintextToWrapper(plaintext);
    assignContextKey(wrapper, key, saltHex);

    while (wrapper.firstChild) {
      container.parentNode.insertBefore(wrapper.firstChild, container);
    }
    if (showEncryptAgain) {
      container.parentNode.insertBefore(createEncryptAgainButton(), container);
    }
    container.remove();
    refreshAfterDecrypt();
  }

  function reveal(container, plaintext, mode, key, saltHex) {
    if (mode === 'full') {
      revealFullPost(container, plaintext, key, saltHex);
      return;
    }
    revealSegment(container, plaintext, key, saltHex);
  }

  function isLastContainer(container) {
    return container === lastContainer;
  }

  function createEncryptAgainButton() {
    const button = document.createElement('button');
    button.textContent = 'Encrypt again';
    button.type = 'button';
    button.className = 'hbe hbe-button';
    button.addEventListener('click', () => {
      try {
        window.localStorage.removeItem(storageKey);
      } catch (error) {
        console.log(error);
      }
      window.location.reload();
    });
    return button;
  }

  function refreshAfterDecrypt() {
    document.querySelectorAll('img').forEach((image) => {
      if (image.getAttribute('data-src') && !image.src) {
        image.src = image.getAttribute('data-src');
      }
    });

    if (window.NexT && window.NexT.boot && typeof window.NexT.boot.refresh === 'function') {
      window.NexT.boot.refresh();
    }

    refreshMathRenderers();

    const toc = document.getElementById('toc-div');
    if (toc) toc.style.display = 'inline';

    Array.from(document.getElementsByClassName('toc-div-class')).forEach((item) => {
      item.style.display = 'inline';
    });

    try {
      window.dispatchEvent(new CustomEvent('hexo-blog-decrypt'));
    } catch (error) {
      window.dispatchEvent(new Event('hexo-blog-decrypt'));
    }

    bindFileRenderers();
    tryDecryptFileRenderers();
  }

  function refreshMathRenderers(remainingAttempts) {
    const attempts = remainingAttempts === undefined ? 10 : remainingAttempts;

    if (window.MathJax) {
      if (window.MathJax.Hub && typeof window.MathJax.Hub.Queue === 'function') {
        window.MathJax.Hub.Queue(['Typeset', window.MathJax.Hub, document.body]);
        return;
      }

      if (typeof window.MathJax.typesetPromise === 'function') {
        window.MathJax.typesetPromise([document.body]).catch((error) => {
          console.log(error);
        });
        return;
      }
    }

    if (typeof window.renderMathInElement === 'function') {
      try {
        window.renderMathInElement(document.body);
      } catch (error) {
        console.log(error);
      }
      return;
    }

    if (attempts > 0) {
      window.setTimeout(() => {
        refreshMathRenderers(attempts - 1);
      }, 300);
    }
  }

  async function decryptContainer(container, password, saveKey) {
    const wire = getWireData(container);
    if (!wire || wire.format !== '4' || container.dataset.hbeDecrypted === 'true') {
      return false;
    }

    const key = await deriveKey(password, hexToBytes(wire.salt), wire.iterations);
    const plaintext = await decryptWithKey(
      key,
      hexToBytes(wire.nonce),
      hexToBytes(wire.encryptedData),
    );

    if (saveKey && wire.autoSave) {
      await saveStoredKey(wire.salt, key);
    }
    rememberKey(wire.salt, key);
    container.dataset.hbeDecrypted = 'true';
    reveal(container, plaintext, wire.mode, key, wire.salt);
    return true;
  }

  async function decryptRemainingContainers(password, sourceContainer) {
    const containers = getContainers();
    for (let i = 0; i < containers.length; i++) {
      if (containers[i] === sourceContainer) {
        continue;
      }

      try {
        await decryptContainer(containers[i], password, true);
      } catch (error) {
        // A page may contain blocks protected by different passwords.
        // Only blocks matching the submitted password should open.
        console.log(error);
      }
    }
  }

  async function tryStoredKey(container) {
    const wire = getWireData(container);
    if (!wire || !wire.autoSave) {
      return false;
    }

    const key = await loadStoredKey(wire.salt);
    if (!key) {
      return false;
    }

    try {
      const plaintext = await decryptWithKey(
        key,
        hexToBytes(wire.nonce),
        hexToBytes(wire.encryptedData),
      );
      rememberKey(wire.salt, key);
      container.dataset.hbeDecrypted = 'true';
      reveal(container, plaintext, wire.mode, key, wire.salt);
      return true;
    } catch (error) {
      console.log(error);
      return false;
    }
  }

  function bindContainer(container) {
    const input = container.querySelector('input[type="password"]');
    if (!input || container.dataset.hbeInitialized === 'true') {
      return;
    }

    container.dataset.hbeInitialized = 'true';
    const submit = async () => {
      const password = input.value;
      if (!password) {
        showError(container, getWireData(container).wrongPassMessage);
        return;
      }

      setBusy(container, true);
      try {
        const decrypted = await decryptContainer(container, password, true);
        if (decrypted) {
          await decryptRemainingContainers(password, container);
        }
      } catch (error) {
        showError(container, getWireData(container).wrongPassMessage);
        console.log(error);
      } finally {
        setBusy(container, false);
      }
    };

    input.addEventListener('keydown', (event) => {
      if (!event.isComposing && (event.key === 'Enter' || event.keyCode === 13)) {
        event.preventDefault();
        submit();
      }
    });

    const form = container.querySelector('form');
    if (form) {
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        submit();
      });
    }
  }

  function getFileRenderers() {
    return Array.from(document.querySelectorAll('[data-hbe-file-renderer="true"]'));
  }

  function setFileBusy(renderer, busy) {
    const input = renderer.querySelector('.hbe-file-password');
    const button = renderer.querySelector('.hbe-file-decrypt');
    if (input) input.disabled = busy;
    if (button) button.disabled = busy;
  }

  function showFileError(renderer, message) {
    const error = renderer.querySelector('.hbe-file-error');
    if (error) {
      error.textContent = message;
    }
  }

  function parseEncryptedFile(bytes) {
    if (bytes.length < fileMagic.length + 4) {
      throw new Error('Encrypted file is too short');
    }
    for (let i = 0; i < fileMagic.length; i++) {
      if (bytes[i] !== fileMagic[i]) {
        throw new Error('Unsupported encrypted file format');
      }
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const headerLength = view.getUint32(fileMagic.length, false);
    const headerStart = fileMagic.length + 4;
    const headerEnd = headerStart + headerLength;
    if (headerLength === 0 || headerEnd >= bytes.length) {
      throw new Error('Invalid encrypted file header');
    }

    const header = JSON.parse(textDecoder.decode(bytes.subarray(headerStart, headerEnd)));
    if (header.format !== 'hexo-blog-encrypt-ex:file' || header.version !== 1 ||
      header.cipher !== 'aes-256-gcm' || header.kdf !== 'pbkdf2-sha256' ||
      !Number.isInteger(header.iterations) || header.iterations < 100000 ||
      header.tagBytes !== 16 || !Number.isSafeInteger(header.originalSize) ||
      header.originalSize < 0) {
      throw new Error('Unsupported encrypted file parameters');
    }

    const salt = hexToBytes(header.salt);
    const nonce = hexToBytes(header.nonce);
    const ciphertext = bytes.subarray(headerEnd);
    if (salt.length !== 32 || nonce.length !== 12 || ciphertext.length <= tagBits / 8) {
      throw new Error('Invalid encrypted file payload');
    }

    return {
      salt: header.salt.toLowerCase(),
      nonce: nonce,
      iterations: header.iterations,
      originalSize: header.originalSize,
      ciphertext: ciphertext,
    };
  }

  async function loadFileWire(renderer) {
    if (!renderer.__hbeFileWirePromise) {
      renderer.__hbeFileWirePromise = (async () => {
        const response = await window.fetch(renderer.dataset.hbeFileUrl, {
          credentials: 'same-origin',
        });
        if (!response.ok) {
          throw new Error(`Unable to load encrypted file (${response.status})`);
        }
        return parseEncryptedFile(new Uint8Array(await response.arrayBuffer()));
      })();
    }
    return renderer.__hbeFileWirePromise;
  }

  async function getKnownFileKey(wire) {
    const cached = fileKeyCache.get(wire.salt);
    if (cached) {
      return cached;
    }

    const stored = await loadStoredKey(wire.salt);
    if (stored) {
      rememberKey(wire.salt, stored);
      return stored;
    }
    return null;
  }

  function fileMime(kind, fileName) {
    const extension = (fileName.split('.').pop() || '').toLowerCase();
    const mimes = {
      aac: 'audio/aac', flac: 'audio/flac', m4a: 'audio/mp4', mp3: 'audio/mpeg',
      oga: 'audio/ogg', ogg: 'audio/ogg', opus: 'audio/ogg', wav: 'audio/wav', weba: 'audio/webm',
      m4v: 'video/mp4', mov: 'video/quicktime', mp4: 'video/mp4', ogv: 'video/ogg', webm: 'video/webm',
      avif: 'image/avif', bmp: 'image/bmp', gif: 'image/gif', jpeg: 'image/jpeg', jpg: 'image/jpeg',
      png: 'image/png', svg: 'image/svg+xml', webp: 'image/webp',
    };
    return mimes[extension] || (kind === 'image' ? 'image/*' : 'application/octet-stream');
  }

  function revealFileRenderer(renderer, plaintext) {
    const kind = renderer.dataset.hbeFileKind || 'file';
    const fileName = renderer.dataset.hbeFileName || 'download';

    clearFileRendererReveal(renderer);

    const blob = new Blob([plaintext], { type: fileMime(kind, fileName) });
    const url = URL.createObjectURL(blob);
    renderer.__hbeFileUrl = url;
    renderer.dataset.hbeFileDecrypted = 'true';

    const form = renderer.querySelector('.hbe-file-form');
    const error = renderer.querySelector('.hbe-file-error');
    const actions = renderer.querySelector('.hbe-file-actions');
    if (form) form.hidden = true;
    if (error) error.textContent = '';
    if (!actions) return;
    actions.hidden = false;

    const download = document.createElement('a');
    download.className = 'hbe-file-download';
    download.href = url;
    download.download = fileName;
    download.textContent = 'Download';
    actions.appendChild(download);

    function appendMedia(media) {
      renderer.insertBefore(media, error || null);
      renderer.insertBefore(actions, error || null);
    }

    if (kind === 'image') {
      const image = document.createElement('img');
      image.className = 'hbe-file-image';
      image.src = url;
      const message = renderer.querySelector('.hbe-file-message');
      image.alt = message ? message.textContent || fileName : fileName;
      appendMedia(image);
      return;
    }

    if (kind === 'video') {
      const media = document.createElement('video');
      media.className = 'hbe-file-video';
      media.controls = true;
      media.preload = 'metadata';
      media.src = url;
      appendMedia(media);
      return;
    }

    if (kind === 'audio') {
      const media = document.createElement('audio');
      media.className = 'hbe-file-audio';
      media.controls = true;
      media.preload = 'metadata';
      media.src = url;
      appendMedia(media);
    }
  }

  function clearFileRendererReveal(renderer) {
    if (renderer.__hbeFileUrl) {
      URL.revokeObjectURL(renderer.__hbeFileUrl);
      renderer.__hbeFileUrl = null;
    }

    const actions = renderer.querySelector('.hbe-file-actions');
    if (actions) {
      while (actions.firstChild) {
        actions.removeChild(actions.firstChild);
      }
    }

    Array.from(renderer.children).forEach((child) => {
      if (
        child.classList.contains('hbe-file-image') ||
        child.classList.contains('hbe-file-audio') ||
        child.classList.contains('hbe-file-video')
      ) {
        child.remove();
      }
    });
  }

  async function decryptFileRenderer(renderer, password) {
    if (renderer.dataset.hbeFileDecrypted === 'true') {
      return true;
    }

    if (renderer.__hbeFileDecryptPromise) {
      let previousResult = false;
      try {
        previousResult = await renderer.__hbeFileDecryptPromise;
      } catch (error) {
        if (password === undefined) {
          throw error;
        }
      }
      if (previousResult || password === undefined) {
        return previousResult;
      }
      if (renderer.dataset.hbeFileDecrypted === 'true') {
        return true;
      }
    }

    renderer.__hbeFileDecryptPromise = (async () => {
      const wire = await loadFileWire(renderer);
      const contextKey = renderer.__hbeFileContextKey;
      const contextSalt = renderer.__hbeFileContextSalt;
      const key = password === undefined && contextKey && contextSalt === wire.salt
        ? contextKey
        : password === undefined
          ? await getKnownFileKey(wire)
          : await deriveKey(password, hexToBytes(wire.salt), wire.iterations);
      if (!key) {
        return false;
      }
      const plaintext = await decryptBytesWithKey(key, wire.nonce, wire.ciphertext);
      if (Number.isInteger(wire.originalSize) && plaintext.length !== wire.originalSize) {
        throw new Error('Decrypted file size does not match its header');
      }
      if (renderer.dataset.hbeFileDecrypted !== 'true') {
        rememberKey(wire.salt, key);
        revealFileRenderer(renderer, plaintext);
      }
      return true;
    })();

    try {
      return await renderer.__hbeFileDecryptPromise;
    } finally {
      renderer.__hbeFileDecryptPromise = null;
    }
  }

  function bindFileRenderer(renderer) {
    if (renderer.dataset.hbeFileInitialized === 'true') {
      return;
    }
    renderer.dataset.hbeFileInitialized = 'true';
    const form = renderer.querySelector('.hbe-file-form');
    const input = renderer.querySelector('.hbe-file-password');
    if (!form || !input) return;

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!input.value) {
        showFileError(renderer, renderer.dataset.hbeFileWrongPass || 'Wrong password.');
        return;
      }

      setFileBusy(renderer, true);
      try {
        await decryptFileRenderer(renderer, input.value);
      } catch (error) {
        showFileError(renderer, renderer.dataset.hbeFileWrongPass || 'Wrong password.');
        console.log(error);
      } finally {
        setFileBusy(renderer, false);
      }
    });
  }

  function bindFileRenderers() {
    getFileRenderers().forEach(bindFileRenderer);
  }

  function tryDecryptFileRenderers() {
    getFileRenderers().forEach((renderer) => {
      if (renderer.dataset.hbeFileDecrypted === 'true') return;
      decryptFileRenderer(renderer).catch((error) => {
        // A renderer without an inherited key remains locked until submission.
        console.log(error);
      });
    });
  }

  async function bootstrap() {
    if (!cryptoObj || !cryptoObj.subtle) {
      return;
    }

    const containers = getContainers();
    lastContainer = containers.length > 0 ? containers[containers.length - 1] : null;
    containers.forEach(bindContainer);
    bindFileRenderers();

    for (let i = 0; i < containers.length; i++) {
      try {
        await tryStoredKey(containers[i]);
      } catch (error) {
        console.log(error);
      }
    }
    tryDecryptFileRenderers();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
