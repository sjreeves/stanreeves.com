/* stanreeves.com — Mobile nav toggle */
(function () {
  document.addEventListener('DOMContentLoaded', function () {
    var toggle = document.getElementById('nav-toggle');
    var menu   = document.getElementById('nav-mobile-menu');
    if (!toggle || !menu) return;

    toggle.addEventListener('click', function () {
      var open = menu.classList.toggle('open');
      toggle.classList.toggle('open', open);
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      // Prevent body scroll when menu is open
      document.body.style.overflow = open ? 'hidden' : '';
    });

    // Mobile accordion for Work With Me dropdown
    menu.querySelectorAll('.mob-dropdown-trigger').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var parent = btn.closest('.mob-dropdown');
        parent.classList.toggle('open');
      });
    });

    // Close menu when a leaf link is clicked (not dropdown triggers)
    menu.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        menu.classList.remove('open');
        toggle.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      });
    });

    // Close menu on resize back to desktop
    window.addEventListener('resize', function () {
      if (window.innerWidth > 768) {
        menu.classList.remove('open');
        toggle.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      }
    });
  });
})();
