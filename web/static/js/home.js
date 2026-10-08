(() => {
  const dialog = document.querySelector('#relay-qr');
  const open = document.querySelector('[data-open-relay-qr]');
  const close = document.querySelector('[data-close-relay-qr]');

  if (!dialog || !open || !close) return;

  open.addEventListener('click', (event) => {
    event.preventDefault();
    dialog.showModal();
  });

  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close();
  });
})();
