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

  const ensureV52Styles = () => {
    const modernV52Page = document.querySelector(
      '.v4-dashboard, .v4-customer-detail, .v4-form-page, .v4-system-page',
    );

    if (!modernV52Page) return;

    const alreadyLoaded = Array.from(
      document.querySelectorAll('link[rel="stylesheet"]'),
    ).some((link) => link.href.includes('/static/css/app-v5-2.css'));

    if (alreadyLoaded) return;

    const stylesheet = document.createElement('link');
    stylesheet.rel = 'stylesheet';
    stylesheet.href = '/static/css/app-v5-2.css';
    stylesheet.dataset.v5Precision = 'true';
    document.head.appendChild(stylesheet);
  };

  const enhanceCustomerDetail = () => {
    const detail = document.querySelector('.v4-customer-detail');
    if (!detail) return;

    const overview = detail.querySelector('#customer-overview');
    const readyState = overview?.querySelector('.v4-ready-state');
    const overviewTab = detail.querySelector(
      '.v4-detail-tabs a[href="#customer-overview"]',
    );

    if (overview && readyState) {
      overview.hidden = true;
      if (overviewTab) overviewTab.hidden = true;

      if (window.location.hash === '#customer-overview') {
        window.history.replaceState(null, '', window.location.pathname + window.location.search);
      }
    }

    detail.querySelectorAll('.v4-device-card').forEach((deviceCard) => {
      const grid = deviceCard.querySelector('.v4-connection-grid');
      if (!grid) return;

      const cards = Array.from(grid.querySelectorAll('.v4-connection-card'));
      const visibleCards = cards.filter((card) => !card.classList.contains('is-empty'));

      cards
        .filter((card) => card.classList.contains('is-empty'))
        .forEach((card) => {
          card.hidden = true;
          card.setAttribute('aria-hidden', 'true');
        });

      if (visibleCards.length === 0) {
        grid.hidden = true;
        grid.setAttribute('aria-hidden', 'true');
      }
    });

    detail.querySelectorAll('.v4-connection-error').forEach((error) => {
      if (error.dataset.v5Enhanced === 'true') return;

      const message = error.textContent.trim();
      if (!message) return;

      const details = document.createElement('details');
      const summary = document.createElement('summary');
      const code = document.createElement('code');

      details.className = 'v5-connection-error-details';
      summary.textContent = 'Ошибка подключения';
      summary.style.cursor = 'pointer';
      summary.style.fontWeight = '650';
      code.textContent = message;
      code.style.display = 'block';
      code.style.marginTop = '4px';
      code.style.whiteSpace = 'normal';
      code.style.overflowWrap = 'anywhere';

      details.append(summary, code);
      error.replaceChildren(details);
      error.dataset.v5Enhanced = 'true';
      error.style.maxHeight = '34px';
      error.style.overflow = 'hidden';
      error.style.whiteSpace = 'normal';

      details.addEventListener('toggle', () => {
        error.style.maxHeight = details.open ? '160px' : '34px';
        error.style.overflow = details.open ? 'auto' : 'hidden';
      });
    });
  };

  const enhanceOnboarding = () => {
    const formPage = document.querySelector('.v4-form-page');
    if (!formPage) return;

    const loginToggle = formPage.querySelector(
      '.v4-login-toggle input[type="checkbox"]',
    );
    const loginFields = formPage.querySelector('.v4-login-fields');

    if (!loginToggle || !loginFields) return;

    const managedControls = Array.from(
      loginFields.querySelectorAll('input, select, textarea, button'),
    );

    const syncLoginFields = () => {
      const expanded = loginToggle.checked;

      loginFields.hidden = !expanded;
      loginFields.setAttribute('aria-hidden', expanded ? 'false' : 'true');
      loginToggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');

      managedControls.forEach((control) => {
        if (!expanded) {
          if (!control.disabled) {
            control.dataset.v5WasEnabled = 'true';
            control.disabled = true;
          }
          return;
        }

        if (control.dataset.v5WasEnabled === 'true') {
          control.disabled = false;
          delete control.dataset.v5WasEnabled;
        }
      });
    };

    loginToggle.addEventListener('change', syncLoginFields);
    syncLoginFields();
  };

  const enhanceSettings = () => {
    if (window.location.pathname !== '/settings/') return;

    const page = document.querySelector('.v4-system-page');
    const grid = page?.querySelector('.v4-settings-grid');
    if (!page || !grid || page.classList.contains('v5-settings-page')) return;

    const stacks = Array.from(grid.querySelectorAll(':scope > .v4-settings-stack'));
    if (stacks.length < 2) return;

    const primaryPanels = Array.from(
      stacks[0].querySelectorAll(':scope > .v4-system-panel'),
    );
    const auxiliaryPanels = Array.from(
      stacks[1].querySelectorAll(':scope > .v4-system-panel'),
    );

    const sections = [
      { key: 'clients', label: 'Клиенты', panel: primaryPanels[0] },
      { key: 'notifications', label: 'Уведомления', panel: primaryPanels[1] },
      { key: 'interface', label: 'Интерфейс', panel: auxiliaryPanels[0] },
      { key: 'system', label: 'Система', panel: auxiliaryPanels[1] },
    ].filter((section) => section.panel);

    if (sections.length < 2) return;

    page.classList.add('v5-settings-page');

    const mainSettingsForm = stacks[0].matches('form')
      ? stacks[0]
      : stacks[0].closest('form');
    if (mainSettingsForm) mainSettingsForm.noValidate = true;

    const tabs = document.createElement('div');
    tabs.className = 'v5-settings-tabs';
    tabs.setAttribute('role', 'tablist');
    tabs.setAttribute('aria-label', 'Разделы настроек');

    const buttons = new Map();

    sections.forEach((section) => {
      const panelId = `settings-panel-${section.key}`;
      const tabId = `settings-tab-${section.key}`;

      section.panel.classList.add('v5-settings-panel');
      section.panel.id = panelId;
      section.panel.setAttribute('role', 'tabpanel');
      section.panel.setAttribute('aria-labelledby', tabId);

      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'v5-settings-tab';
      button.id = tabId;
      button.textContent = section.label;
      button.setAttribute('role', 'tab');
      button.setAttribute('aria-controls', panelId);
      button.setAttribute('aria-selected', 'false');
      button.tabIndex = -1;
      tabs.appendChild(button);
      buttons.set(section.key, button);
    });

    grid.before(tabs);

    const activate = (key, { updateHash = false, focus = false } = {}) => {
      const resolved = sections.some((section) => section.key === key)
        ? key
        : sections[0].key;

      sections.forEach((section) => {
        const selected = section.key === resolved;
        section.panel.hidden = !selected;
        section.panel.setAttribute('aria-hidden', selected ? 'false' : 'true');

        const button = buttons.get(section.key);
        button.setAttribute('aria-selected', selected ? 'true' : 'false');
        button.tabIndex = selected ? 0 : -1;

        if (selected && focus) button.focus();
      });

      if (updateHash) {
        const url = new URL(window.location.href);
        url.hash = `settings-${resolved}`;
        window.history.replaceState(null, '', url);
      }
    };

    sections.forEach((section) => {
      const button = buttons.get(section.key);
      button.addEventListener('click', () => {
        activate(section.key, { updateHash: true });
      });
    });

    tabs.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;

      event.preventDefault();
      const keys = sections.map((section) => section.key);
      const currentIndex = Math.max(
        0,
        keys.findIndex((key) => buttons.get(key).getAttribute('aria-selected') === 'true'),
      );

      let nextIndex = currentIndex;
      if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % keys.length;
      if (event.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + keys.length) % keys.length;
      if (event.key === 'Home') nextIndex = 0;
      if (event.key === 'End') nextIndex = keys.length - 1;

      activate(keys[nextIndex], { updateHash: true, focus: true });
    });

    const panelWithErrors = sections.find((section) =>
      section.panel.querySelector(
        '.text-danger, .invalid-feedback, .is-invalid, .errorlist',
      ),
    );

    const hashMatch = window.location.hash.match(/^#settings-(clients|notifications|interface|system)$/);
    const initialKey = panelWithErrors?.key || hashMatch?.[1] || sections[0].key;
    activate(initialKey);
  };

  ensureV52Styles();
  enhanceCustomerDetail();
  enhanceOnboarding();
  enhanceSettings();

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
