(() => {
  const codeForm = document.querySelector('.code-form');
  const codeValue = document.querySelector('#code');
  const codeInputs = [...document.querySelectorAll('.code-input')];
  const codeSeparators = [...document.querySelectorAll('.code-separator')];
  const codeGroups = Number(document.querySelector('.code-inputs')?.dataset.codeGroups || codeInputs.length);

  codeInputs.forEach((input, index) => {
    if (index >= codeGroups) input.hidden = true;

    input.addEventListener('input', () => {
      input.value = input.value.toUpperCase().replace(/[^ABCDEFGHJKMNPQRSTUVWXYZ23456789]/g, '').slice(-4);
      if (input.value.length === 4 && codeInputs[index + 1] && index + 1 < codeGroups) codeInputs[index + 1].focus();
    });

    input.addEventListener('keydown', (event) => {
      if (event.key === 'Backspace' && input.value === '' && codeInputs[index - 1]) {
        codeInputs[index - 1].focus();
      }
    });

    input.addEventListener('paste', (event) => {
      event.preventDefault();
      const pasted = event.clipboardData?.getData('text') || '';
      const clean = pasted.toUpperCase().replace(/[^ABCDEFGHJKMNPQRSTUVWXYZ23456789]/g, '');
      codeInputs.forEach((group, groupIndex) => {
        group.value = groupIndex < codeGroups ? clean.slice(groupIndex * 4, groupIndex * 4 + 4) : '';
      });
      const next = Math.min(Math.floor(clean.length / 4), codeGroups - 1);
      codeInputs[next]?.focus();
    });
  });

  codeSeparators.forEach((separator, index) => {
    separator.hidden = index >= codeGroups - 1;
  });

  codeForm?.addEventListener('submit', () => {
    if (codeValue) codeValue.value = codeInputs.slice(0, codeGroups).map((input) => input.value).join('');
  });

  const status = document.querySelector('[data-login-id]');
  if (!status) return;
  const id = encodeURIComponent(status.dataset.loginId);
  const message = status.querySelector('span:last-child');
  const setStatus = (text, state) => {
    if (message) message.textContent = text;
    else status.textContent = text;
    status.dataset.state = state;
  };
  const expiry = document.querySelector('[data-login-expiry]');
  const expiresAt = Date.parse(status.dataset.expiresAt || '');
  let failureRedirect = status.dataset.failureRedirect || '';
  let finished = false;
  let source;
  const expire = (redirect) => {
    if (finished) return;
    finished = true;
    failureRedirect = redirect || failureRedirect;
    setStatus('This request expired. Returning to the application..', 'expired');
    source?.close();
    if (failureRedirect) window.setTimeout(() => window.location.replace(failureRedirect), 700);
  };
  const updateExpiry = () => {
    if (!expiry || !Number.isFinite(expiresAt)) return;
    const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    expiry.textContent = remaining > 0 ? `Expires in ${remaining}s` : 'This request has expired.';
    if (remaining === 0) expire();
  };
  updateExpiry();
  const expiryTimer = window.setInterval(updateExpiry, 1000);
  source = new EventSource(`/api/logins/${id}/events`);
  source.addEventListener('approved', () => { finished = true; window.clearInterval(expiryTimer); location.reload(); });
  source.addEventListener('denied', () => { finished = true; window.clearInterval(expiryTimer); setStatus('This login was denied. You can safely close this window.', 'denied'); source.close(); });
  source.addEventListener('expired', (event) => {
    window.clearInterval(expiryTimer);
    let redirect = '';
    try { redirect = JSON.parse(event.data).redirect || ''; } catch {}
    expire(redirect);
  });
  source.onerror = () => setStatus('Connection interrupted. Retrying securely..', 'reconnecting');
})();
