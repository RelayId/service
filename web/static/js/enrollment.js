(() => {
  const status = document.querySelector('[data-enrollment-status]');
  if (!status) return;

  const id = encodeURIComponent(status.dataset.enrollmentId);
  const state = status.querySelector('[data-enrollment-state]');
  const dot = status.querySelector('.status-dot');
  const note = status.querySelector('[data-enrollment-note]');
  const message = document.querySelector('[data-enrollment-message]');

  const labels = {
    pending: 'Pending',
    verified: 'Verified',
    complete: 'Complete',
    expired: 'Expired',
  };

  const update = (value) => {
    if (state) state.textContent = labels[value] || value;
    if (dot) {
      dot.className = `status-dot status-dot-${value}`;
    }

    if (value === 'complete') {
      if (note) note.textContent = 'Enrollment complete. You may now close this window.';
      if (message) message.textContent = 'Your Relay app finished enrollment successfully.';
      return true;
    }

    if (value === 'verified') {
      if (note) note.textContent = 'Waiting for the Relay app to finish enrollment.';
      if (message) message.textContent = 'Identity verified. Your Relay app is completing enrollment.';
    }

    if (value === 'expired') {
      if (note) note.textContent = 'Enrollment expired.';
      if (message) message.textContent = 'This enrollment expired. Start a new enrollment from the Relay app.';
      return true;
    }

    return false;
  };

  const poll = async () => {
    try {
      const response = await fetch(`/api/enrollments/${id}`, {cache: 'no-store'});
      if (!response.ok) return false;
      const body = await response.json();
      return update(body.data?.state || body.state || '');
    } catch (_) {
      return false;
    }
  };

  const timer = window.setInterval(async () => {
    if (await poll()) window.clearInterval(timer);
  }, 1000);
})();
