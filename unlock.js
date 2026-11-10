'use strict';

const form = document.querySelector('#gate');
const password = document.querySelector('#password');
const reveal = document.querySelector('#reveal');
const unlock = document.querySelector('#unlock');
const status = document.querySelector('#status');
const encoder = new TextEncoder();
const format = 'SCJ1';

reveal.addEventListener('click', () => {
  const shown = password.type === 'password';
  password.type = shown ? 'text' : 'password';
  reveal.textContent = shown ? '隐藏' : '显示';
  reveal.setAttribute('aria-pressed', String(shown));
});

async function loadPayload() {
  const response = await fetch('./guide.enc', { cache: 'no-cache' });
  if (!response.ok) throw new Error('Payload is unavailable');
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length < 49 || new TextDecoder().decode(bytes.subarray(0, 4)) !== format) {
    throw new Error('Invalid payload');
  }
  return bytes;
}

async function decrypt(bytes, secret) {
  const { subtle } = crypto;
  const material = await subtle.importKey('raw', encoder.encode(secret), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: bytes.subarray(4, 20), iterations: 600_000 },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.subarray(20, 32), additionalData: encoder.encode(format) },
    key,
    bytes.subarray(32),
  );
  return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
}

if (window.isSecureContext && window.crypto?.subtle) {
  unlock.disabled = false;
} else {
  status.textContent = '请通过 HTTPS 链接，在支持加密功能的浏览器中打开。';
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (unlock.disabled) return;

  unlock.disabled = true;
  status.textContent = '正在解锁…';
  const secret = password.value.trim();
  let payload;
  try {
    payload = await loadPayload();
  } catch {
    status.textContent = '暂时无法加载手册，请检查网络后重试。';
    unlock.disabled = false;
    return;
  }

  let html;
  try {
    html = await decrypt(payload, secret);
  } catch {
    status.textContent = '密码不正确，或手册文件已损坏。';
    unlock.disabled = false;
    password.select();
    return;
  }

  password.value = '';
  document.open();
  document.write(html);
  document.close();
});
