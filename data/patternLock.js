// Pattern Lock for TamsDeauth
(function() {
  const canvas = document.getElementById('patternLock');
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
  function draw() {
    ctx.clearRect(0, 0, size, size);
    dots.forEach(d => {
      ctx.beginPath();
      ctx.arc(d.x, d.y, 15, 0, Math.PI * 2);
      ctx.fillStyle = selected.includes(d.id) ? '#0e5cc2' : '#333';
      ctx.fill();
    });
    if (drawing && selected.length > 0) {
      const last = dots[selected[selected.length - 1]];
      ctx.beginPath();
      ctx.moveTo(last.x, last.y);
      ctx.lineTo(currentX, currentY);
      ctx.strokeStyle = '#7db5ff';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
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
    if (selected.length >= 4) {
      // Submit pattern
      fetch('/?newpattern=' + selected.join(','), { method: 'POST' });
    }
    draw();
  });
  draw();
})();
