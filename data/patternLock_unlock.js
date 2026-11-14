// Pattern Lock Unlock for TamsDeauth
(function() {
  const canvas = document.getElementById('patternUnlock');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const size = 200;
  canvas.width = size;
  canvas.height = size;
  const dots = [];
  const grid = 3;
  const spacing = size / (grid + 1);
  for (let y = 0; y < grid; y++) {
    for (let x = 0; x < grid; x++) {
      dots.push({ x: (x + 1) * spacing, y: (y + 1) * spacing, id: y * grid + x });
    }
  }
  let selected = [];
  let drawing = false;
  let attempts = 0;
  function draw() {
    ctx.clearRect(0, 0, size, size);
    dots.forEach(d => {
      ctx.beginPath();
      ctx.arc(d.x, d.y, 15, 0, Math.PI * 2);
      ctx.fillStyle = selected.includes(d.id) ? '#0e5cc2' : '#333';
      ctx.fill();
    });
  }
  let currentX = 0, currentY = 0;
  canvas.addEventListener('mousedown', e => { drawing = true; selected = []; draw(); });
  canvas.addEventListener('mousemove', e => {
    if (!drawing) return;
    const rect = canvas.getBoundingClientRect();
    currentX = e.clientX - rect.left;
    currentY = e.clientY - rect.top;
    dots.forEach(d => {
      if (!selected.includes(d.id) && Math.hypot(currentX - d.x, currentY - d.y) < 20) {
        selected.push(d.id);
      }
    });
    draw();
  });
  canvas.addEventListener('mouseup', () => {
    drawing = false;
    attempts++;
    // Submit unlock attempt
    fetch('/?unlockpattern=' + selected.join(','), { method: 'POST' })
      .then(r => r.text())
      .then(result => {
        if (result === 'OK') {
          window.location.href = '/';
        } else {
          selected = [];
          draw();
        }
      });
  });
  draw();
})();
