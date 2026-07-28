(() => {
  'use strict';

  const cryptoObj = window.crypto || window.msCrypto;
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder('utf-8', { fatal: true });
  const storageKey = 'hbe.v4.ex.' + window.location.pathname;
  const keyBits = 256;
  const tagBits = 128;
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

  function revealFullPost(container, plaintext) {
    const wrapper = plaintextToWrapper(plaintext);
    wrapper.id = 'hexo-blog-encrypt';
    wrapper.classList.add('hbe', 'hbe-decrypted-content');
    container.parentNode.replaceChild(wrapper, container);
    refreshAfterDecrypt();
  }

  function revealSegment(container, plaintext) {
    const showEncryptAgain = isLastContainer(container);
    const wrapper = plaintextToWrapper(plaintext);

    while (wrapper.firstChild) {
      container.parentNode.insertBefore(wrapper.firstChild, container);
    }
    if (showEncryptAgain) {
      container.parentNode.insertBefore(createEncryptAgainButton(), container);
    }
    container.remove();
    refreshAfterDecrypt();
  }

  function reveal(container, plaintext, mode) {
    if (mode === 'full') {
      revealFullPost(container, plaintext);
      return;
    }
    revealSegment(container, plaintext);
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
    container.dataset.hbeDecrypted = 'true';
    reveal(container, plaintext, wire.mode);
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
      container.dataset.hbeDecrypted = 'true';
      reveal(container, plaintext, wire.mode);
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

  async function bootstrap() {
    if (!cryptoObj || !cryptoObj.subtle) {
      return;
    }

    const containers = getContainers();
    lastContainer = containers.length > 0 ? containers[containers.length - 1] : null;
    containers.forEach(bindContainer);

    for (let i = 0; i < containers.length; i++) {
      try {
        await tryStoredKey(containers[i]);
      } catch (error) {
        console.log(error);
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
