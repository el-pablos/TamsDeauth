// IP override for captive portal
// Redirects to TamsDeauth when captive portal is detected
window.onload = function() {
  // Check if we're not on the TamsDeauth AP
  if (window.location.hostname !== '192.168.4.1' && 
      window.location.hostname !== 'necthercap.local' &&
      !window.location.hostname.startsWith('192.168.')) {
    // Redirect to TamsDeauth
    window.location.href = 'http://192.168.4.1/';
  }
};
