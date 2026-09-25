(() => {
  const ready = (callback) => {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', callback, { once: true });
    } else {
      callback();
    }
  };

  const enhanceSettings = () => {
    if (window.location.pathname !== '/settings/') return;

    const page = document.querySelector('.v4-system-page');
    const grid = page?.querySelector('.v4-settings-grid');
    if (!page || !grid || page.classList.contains('v6-settings-page')) return;

    const stacks = Array.from(grid.querySelectorAll(':scope > .v4-settings-stack'));
    if (stacks.length < 2) return;

    const primary = Array.from(stacks[0].querySelectorAll(':scope > .v4-system-panel'));
    const secondary = Array.from(stacks[1].querySelectorAll(':scope > .v4-system-panel'));

    const sections = [
      { key: 'clients', label: 'Клиенты', panel: primary[0] },
      { key: 'notifications', label: 'Уведомления', panel: primary[1] },
      { key: 'interface', label: 'Интерфейс', panel: secondary[0] },
      { key: 'system', label: 'Система', panel: secondary[1] },
    ].filter((section) => section.panel);

    if (sections.length < 2) return;

    page.classList.add('v6-settings-page');

    const tabs = document.createElement('div');
    tabs.className = 'v6-settings-tabs';
    tabs.setAttribute('role', 'tablist');
    tabs.setAttribute('aria-label', 'Разделы настроек');

    const buttons = new Map();

    sections.forEach((section) => {
      const panelId = 'v6-settings-' + section.key;
      const tabId = 'v6-settings-tab-' + section.key;

      section.panel.classList.add('v6-settings-panel');
      section.panel.id = panelId;
      section.panel.setAttribute('role', 'tabpanel');
      section.panel.setAttribute('aria-labelledby', tabId);

      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'v6-settings-tab';
      button.id = tabId;
      button.textContent = section.label;
      button.setAttribute('role', 'tab');
      button.setAttribute('aria-controls', panelId);
      tabs.appendChild(button);
      buttons.set(section.key, button);
    });

    grid.before(tabs);

    const activate = (key, options = {}) => {
      const selectedKey = sections.some((item) => item.key === key)
        ? key
        : sections[0].key;

      sections.forEach((section) => {
        const selected = section.key === selectedKey;
        section.panel.hidden = !selected;
        section.panel.setAttribute('aria-hidden', selected ? 'false' : 'true');

        const button = buttons.get(section.key);
        button.setAttribute('aria-selected', selected ? 'true' : 'false');
        button.tabIndex = selected ? 0 : -1;
        if (selected && options.focus) button.focus();
      });

      if (options.hash) {
        const url = new URL(window.location.href);
        url.hash = 'settings-' + selectedKey;
        window.history.replaceState(null, '', url);
      }
    };

    sections.forEach((section) => {
      buttons.get(section.key).addEventListener('click', () => {
        activate(section.key, { hash: true });
      });
    });

    tabs.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();

      const keys = sections.map((item) => item.key);
      const current = Math.max(
        0,
        keys.findIndex((key) => buttons.get(key).getAttribute('aria-selected') === 'true'),
      );

      let next = current;
      if (event.key === 'ArrowRight') next = (current + 1) % keys.length;
      if (event.key === 'ArrowLeft') next = (current - 1 + keys.length) % keys.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = keys.length - 1;

      activate(keys[next], { hash: true, focus: true });
    });

    const withErrors = sections.find((section) =>
      section.panel.querySelector('.text-danger, .invalid-feedback, .is-invalid, .errorlist'),
    );

    const match = window.location.hash.match(/^#settings-(clients|notifications|interface|system)$/);
    activate(withErrors?.key || match?.[1] || sections[0].key);
  };

  const enhanceConnectionCreator = () => {
    const form = document.querySelector('[data-v6-connection-form]');
    if (!form) return;

    const radios = Array.from(form.querySelectorAll('input[name="product_type"]'));
    const cards = Array.from(form.querySelectorAll('[data-v6-product-card]'));
    const panels = Array.from(form.querySelectorAll('[data-v6-product-panel]'));
    const submit = form.querySelector('[data-v6-submit]');
    const summaryProduct = form.querySelector('[data-v6-summary-product]');

    const applyTraffic = form.querySelector('[data-v6-traffic-mode] select');
    const preset = form.querySelector('[data-v6-traffic-preset] select');
    const sizeField = form.querySelector('[data-v6-traffic-size]');
    const customField = form.querySelector('[data-v6-traffic-custom]');

    const labels = {
      full: 'Создать FULL',
      selective: 'Создать SELECT',
      alt: 'Создать ALT',
    };

    const titles = {
      full: 'FULL · весь интернет',
      selective: 'SELECT · выбранные сервисы',
      alt: 'ALT · VLESS/XHTTP',
    };

    const syncProduct = () => {
      const selected = radios.find((radio) => radio.checked)?.value || '';

      cards.forEach((card) => {
        const radio = card.querySelector('input[name="product_type"]');
        card.classList.toggle('is-selected', Boolean(radio?.checked));
      });

      panels.forEach((panel) => {
        const active = panel.dataset.v6ProductPanel === selected;
        panel.hidden = !active;
        panel.setAttribute('aria-hidden', active ? 'false' : 'true');

        panel.querySelectorAll('input, select, textarea, button').forEach((control) => {
          control.disabled = !active;
        });
      });

      if (submit) submit.textContent = labels[selected] || 'Создать подключение';
      if (summaryProduct) summaryProduct.textContent = titles[selected] || 'Не выбрано';
    };

    const syncTraffic = () => {
      const setting = applyTraffic?.value === 'set';
      if (sizeField) sizeField.hidden = !setting;

      const custom = setting && preset?.value === 'custom';
      if (customField) customField.hidden = !custom;
    };

    radios.forEach((radio) => radio.addEventListener('change', syncProduct));
    applyTraffic?.addEventListener('change', syncTraffic);
    preset?.addEventListener('change', syncTraffic);

    form.addEventListener('submit', () => {
      if (!submit || submit.disabled) return;
      submit.classList.add('is-busy');
      submit.disabled = true;
      submit.textContent = 'Создаём…';
    });

    syncProduct();
    syncTraffic();
  };

  ready(() => {
    enhanceSettings();
    enhanceConnectionCreator();
  });
})();
