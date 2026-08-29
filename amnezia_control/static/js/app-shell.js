(() => {
  const body = document.body;
  const toggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('appSidebar');
  const overlay = document.getElementById('sidebarOverlay');
  const mobileMoreToggle = document.getElementById('mobileMoreToggle');
  const media = window.matchMedia('(max-width: 991.98px)');
  const storageKey = 'amnezia-control.sidebar-collapsed';

  if (!toggle || !sidebar) return;

  const readCollapsed = () => {
    try {
      return window.localStorage.getItem(storageKey) === '1';
    } catch (_) {
      return false;
    }
  };

  const saveCollapsed = (collapsed) => {
    try {
      window.localStorage.setItem(storageKey, collapsed ? '1' : '0');
    } catch (_) {
      // Storage may be blocked. The UI still works for the current page.
    }
  };

  const updateA11yState = () => {
    const expanded = media.matches
      ? body.classList.contains('sidebar-open')
      : !body.classList.contains('sidebar-collapsed');
    toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    mobileMoreToggle?.setAttribute(
      'aria-expanded',
      expanded ? 'true' : 'false',
    );
  };

  const closeMobileSidebar = () => {
    body.classList.remove('sidebar-open');
    updateA11yState();
  };

  if (!media.matches && readCollapsed()) {
    body.classList.add('sidebar-collapsed');
  }
  updateA11yState();

  toggle.addEventListener('click', () => {
    if (media.matches) {
      body.classList.toggle('sidebar-open');
    } else {
      body.classList.toggle('sidebar-collapsed');
      saveCollapsed(body.classList.contains('sidebar-collapsed'));
    }
    updateA11yState();
  });

  mobileMoreToggle?.addEventListener('click', () => {
    if (!media.matches) return;

    body.classList.add('sidebar-open');
    updateA11yState();
  });

  overlay?.addEventListener('click', closeMobileSidebar);

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && body.classList.contains('sidebar-open')) {
      closeMobileSidebar();
      toggle.focus();
    }
  });

  media.addEventListener('change', () => {
    body.classList.remove('sidebar-open');
    if (media.matches) {
      body.classList.remove('sidebar-collapsed');
    } else if (readCollapsed()) {
      body.classList.add('sidebar-collapsed');
    }
    updateA11yState();
  });

  sidebar.querySelectorAll('a.nav-link').forEach((link) => {
    link.addEventListener('click', () => {
      if (media.matches) closeMobileSidebar();
    });
  });
})();
