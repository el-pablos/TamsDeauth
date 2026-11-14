document.addEventListener('DOMContentLoaded', function() {
  const headers = [
    { headerId: 'menu-header', contentId: 'menu-content' },
    { headerId: 'target-header', contentId: 'target-content' }
  ];
  headers.forEach(function(item) {
    const header = document.getElementById(item.headerId);
    const content = document.getElementById(item.contentId);
    if (header && content) {
      content.style.display = 'block';
      header.addEventListener('click', function() {
        if (content.style.display === 'none') {
          content.style.display = 'block';
        } else {
          content.style.display = 'none';
        }
      });
    }
  });
});
