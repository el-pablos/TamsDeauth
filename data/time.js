// Time display utility
function updateTime() {
  const now = new Date();
  const timeEl = document.getElementById('current-time');
  if (timeEl) {
    timeEl.textContent = now.toLocaleTimeString();
  }
  const dateEl = document.getElementById('current-date');
  if (dateEl) {
    dateEl.textContent = now.toLocaleDateString();
  }
}
setInterval(updateTime, 1000);
updateTime();
