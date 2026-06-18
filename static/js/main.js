/*
 * WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
 * Drafted with assistance from Google Antigravity (Gemini) inside the
 * Antigravity IDE, from a specification I authored. All visual,
 * accessibility, and final-review decisions are mine.
 *
 * Frontend Spec §11 — five init functions, no others.
 */

document.addEventListener('DOMContentLoaded', function () {
  initLikeButtons();
  initTagCounters();
  initImagePreviews();
  initUploadZones();
  initWordCounter();
  initMobileNav();
  initLogoutConfirm();
  initPasswordToggle();
  initSchoolOther();
});

// 1. Like buttons — AJAX POST, X-CSRFToken header, optimistic UI update.
//    Response shape: { liked: bool, count: int }.
function initLikeButtons() {
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.content : '';

  document.querySelectorAll('.like-btn').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      try {
        const res = await fetch(this.dataset.url, {
          method: 'POST',
          headers: {
            'X-CSRFToken': this.dataset.csrf || csrfToken,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          }
        });
        if (!res.ok) throw new Error('Like request failed: ' + res.status);
        const data = await res.json();

        this.classList.toggle('liked', data.liked);
        this.setAttribute('aria-pressed', data.liked ? 'true' : 'false');
        this.setAttribute('aria-label',
          (data.liked ? 'Ya no me gusta' : 'Me gusta') + ' este trabajo');

        const counter = this.querySelector('.like-count');
        if (counter) counter.textContent = data.count;

        const icon = this.querySelector('.like-icon');
        if (icon) icon.setAttribute('fill', data.liked ? 'currentColor' : 'none');
      } catch (e) {
        console.error('Like failed:', e);
      }
    });
  });
}

// 2. Tag counter — "N / max etiquetas". Driven by templates emitting
//    data-tag-counter="N" + data-counter-target="ELEMENT_ID".
function initTagCounters() {
  document.querySelectorAll('[data-tag-counter]').forEach(function (input) {
    const maxTags = parseInt(input.dataset.tagCounter, 10) || 5;
    const counter = document.getElementById(input.dataset.counterTarget);
    if (!counter) return;

    function update() {
      const tags = input.value.split(',')
        .map(function (t) { return t.trim(); })
        .filter(function (t) { return t.length > 0; });
      counter.textContent = Math.min(tags.length, maxTags) + ' / ' + maxTags + ' etiquetas';
      counter.style.color = tags.length > maxTags ? '#E24B4A' : 'var(--color-muted)';
    }

    input.addEventListener('input', update);
    update();
  });
}

// 3. Image preview on file select. data-preview holds the ID of the
//    target <img> element. Drives edit_profile.html avatar preview.
function initImagePreviews() {
  document.querySelectorAll('input[type="file"][data-preview]').forEach(function (input) {
    input.addEventListener('change', function () {
      const preview = document.getElementById(this.dataset.preview);
      if (!preview || !this.files || !this.files[0]) return;

      const reader = new FileReader();
      reader.onload = function (e) {
        preview.src = e.target.result;
        preview.style.display = 'block';
        preview.alt = 'Vista previa del archivo seleccionado';
      };
      reader.readAsDataURL(this.files[0]);
    });
  });
}

// 3b. Upload-zone filename feedback. Surfaces the selected filename in the
//     drop-zone label so the user has visible confirmation that the file is
//     attached to the input (otherwise the zone looks unchanged and a missed
//     click on the file picker silently submits the form with no file).
function initUploadZones() {
  document.querySelectorAll('.upload-zone__input').forEach(function (input) {
    const zone = input.closest('.upload-zone');
    if (!zone) return;
    const textEl = zone.querySelector('.upload-zone__text');
    const originalText = textEl ? textEl.textContent : '';

    input.addEventListener('change', function () {
      if (this.files && this.files.length > 0) {
        if (textEl) textEl.textContent = this.files[0].name;
        zone.classList.add('upload-zone--selected');
      } else {
        if (textEl) textEl.textContent = originalText;
        zone.classList.remove('upload-zone--selected');
      }
    });
  });
}

// 4. Word counter for the research-abstract textarea. Hard-bound IDs
//    per spec §11: #abstract + #word-counter.
function initWordCounter() {
  const abstract = document.getElementById('abstract');
  const counter = document.getElementById('word-counter');
  if (!abstract || !counter) return;

  function countWords() {
    const words = abstract.value.trim().split(/\s+/).filter(function (w) {
      return w.length > 0;
    });
    counter.textContent = words.length + ' / 250 palabras';
    counter.style.color = words.length > 250 ? '#E24B4A' : 'var(--color-muted)';
  }

  abstract.addEventListener('input', countWords);
  countWords();
}

// 5. Mobile nav toggle. .nav-toggle button + #primary-nav target.
function initMobileNav() {
  const toggle = document.querySelector('.nav-toggle');
  const links = document.getElementById('primary-nav');
  if (!toggle || !links) return;

  toggle.addEventListener('click', function () {
    const isOpen = links.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  });
}

// 6. Logout confirmation. Intercepts submit on any form marked with
//    data-confirm-logout and shows an in-app modal; the form submits
//    only after the user confirms.
function initLogoutConfirm() {
  const forms = document.querySelectorAll('form[data-confirm-logout]');
  if (forms.length === 0) return;

  const modal = document.createElement('div');
  modal.className = 'confirm-modal';
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.setAttribute('aria-labelledby', 'confirm-modal-title');
  modal.hidden = true;
  modal.innerHTML =
    '<div class="confirm-modal__backdrop" data-confirm-cancel></div>' +
    '<div class="confirm-modal__dialog">' +
      '<h2 id="confirm-modal-title" class="confirm-modal__title">CERRAR SESIÓN</h2>' +
      '<p class="confirm-modal__body">¿Seguro que quieres cerrar sesión en WikiSTEM?</p>' +
      '<div class="confirm-modal__actions">' +
        '<button type="button" class="btn-ghost" data-confirm-cancel>CANCELAR</button>' +
        '<button type="button" class="btn-yellow" data-confirm-ok>CERRAR SESIÓN</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(modal);

  let pendingForm = null;
  const okBtn = modal.querySelector('[data-confirm-ok]');

  function open(form) {
    pendingForm = form;
    modal.hidden = false;
    document.body.classList.add('has-modal-open');
    okBtn.focus();
  }
  function close() {
    pendingForm = null;
    modal.hidden = true;
    document.body.classList.remove('has-modal-open');
  }

  modal.querySelectorAll('[data-confirm-cancel]').forEach(function (el) {
    el.addEventListener('click', close);
  });
  okBtn.addEventListener('click', function () {
    const form = pendingForm;
    close();
    if (form) form.submit();
  });
  document.addEventListener('keydown', function (e) {
    if (!modal.hidden && e.key === 'Escape') close();
  });

  forms.forEach(function (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      open(form);
    });
  });
}

// 8. School "Otro" reveal. When a [data-school-select] dropdown is set to
//    "Other", show the sibling [data-school-other-wrap] block so the user can
//    type a custom school name. Hidden otherwise. The text field stays in the
//    DOM either way so its server-side validation still binds.
function initSchoolOther() {
  document.querySelectorAll('[data-school-select]').forEach(function (select) {
    const form = select.form;
    if (!form) return;
    const wrap = form.querySelector('[data-school-other-wrap]');
    if (!wrap) return;
    const input = wrap.querySelector('input[type="text"], input:not([type])');

    function sync() {
      const isOther = select.value === 'Other';
      wrap.hidden = !isOther;
      if (!isOther && input) input.value = '';
    }

    select.addEventListener('change', sync);
    sync();
  });
}

// 7. Password show/hide toggle. Each [data-password-toggle] button toggles
//    the type of the password input that is its previous sibling inside the
//    same .password-field wrapper.
function initPasswordToggle() {
  document.querySelectorAll('[data-password-toggle]').forEach(function (btn) {
    const field = btn.closest('.password-field');
    if (!field) return;
    const input = field.querySelector('input[type="password"], input[type="text"]');
    if (!input) return;
    const label = btn.querySelector('.password-toggle__text');

    btn.addEventListener('click', function () {
      const showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      btn.setAttribute('aria-pressed', showing ? 'false' : 'true');
      btn.setAttribute('aria-label',
        showing ? 'Mostrar contraseña' : 'Ocultar contraseña');
      if (label) label.textContent = showing ? 'MOSTRAR' : 'OCULTAR';
    });
  });
}
