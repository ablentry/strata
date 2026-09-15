const BASE_LANGUAGE = 'en-GB';
const STRING_FILES = ['ui', 'tooltips', 'messages', 'help'];

let STRINGS = {};
let BASE_STRINGS = {};
const MISSING_STRINGS = new Set();

const PLURAL_FORMS = ['zero', 'one', 'two', 'few', 'many', 'other'];

function isPluralSet(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v)
    && 'other' in v
    && Object.keys(v).every(k => PLURAL_FORMS.includes(k));
}

function flattenStrings(obj, prefix, into) {
  for (const [k, v] of Object.entries(obj || {})) {
    if (k.startsWith('_')) continue;
    const key = prefix ? `${prefix}.${k}` : k;
    if (isPluralSet(v)) {
      into[key] = v;
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      flattenStrings(v, key, into);
    } else {
      into[key] = Array.isArray(v) ? v.join(' ') : String(v);
    }
  }
  return into;
}

let PLURAL_RULES = null;

function pluralForm(set, count) {
  if (typeof count !== 'number' || !Number.isFinite(count)) return set.other;
  let category = 'other';
  try {
    if (!PLURAL_RULES) {
      PLURAL_RULES = new Intl.PluralRules(document.documentElement.lang
                                          || BASE_LANGUAGE);
    }
    category = PLURAL_RULES.select(count);
  } catch {
  }
  return set[category] !== undefined ? set[category] : set.other;
}

async function readStringFiles(lang) {
  const out = {};
  for (const file of STRING_FILES) {
    const r = await fetch(`strings/${lang}/${file}.json`, { cache: 'no-cache' });
    if (!r.ok) throw new Error(`strings/${lang}/${file}.json — ${r.status}`);
    flattenStrings(await r.json(), file, out);
  }
  return out;
}

async function loadStrings(lang) {
  BASE_STRINGS = await readStringFiles(BASE_LANGUAGE);
  STRINGS = lang && lang !== BASE_LANGUAGE
    ? { ...BASE_STRINGS, ...(await readStringFiles(lang)) }
    : BASE_STRINGS;
  document.documentElement.lang = lang || BASE_LANGUAGE;
  PLURAL_RULES = null;
  return STRINGS;
}

function txt(key, vars) {
  let text = STRINGS[key];
  if (text === undefined) text = BASE_STRINGS[key];
  if (text === undefined) {
    MISSING_STRINGS.add(key);
    return key;
  }
  if (isPluralSet(text)) {
    text = pluralForm(text, vars && vars.count);
    if (text === undefined) {
      MISSING_STRINGS.add(key + ' (plural)');
      return key;
    }
  }
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (whole, name) =>
    (vars[name] === undefined ? whole : String(vars[name])));
}

function applyStrings(root = document) {
  for (const el of root.querySelectorAll('[data-i18n]')) {
    el.textContent = txt(el.dataset.i18n);
  }
  for (const el of root.querySelectorAll('[data-i18n-html]')) {
    el.innerHTML = txt(el.dataset.i18nHtml);
  }
  for (const [attr, key] of [['title', 'i18nTitle'],
                             ['placeholder', 'i18nPlaceholder'],
                             ['aria-label', 'i18nAria']]) {
    const sel = attr === 'aria-label' ? 'data-i18n-aria' : 'data-i18n-' + attr;
    for (const el of root.querySelectorAll(`[${sel}]`)) {
      el.setAttribute(attr, txt(el.dataset[key]));
    }
  }
}

(async function start() {
  let language = null;
  try {
    const r = await fetch('api/prefs', { cache: 'no-cache' });
    if (r.ok) language = ((await r.json()).prefs || {}).language || null;
  } catch {                                                         }

  try {
    await loadStrings(language);
  } catch (e) {
    document.body.innerHTML =
      '<div style="padding:2rem;font:14px system-ui;line-height:1.6;max-width:46em">'
      + '<h1 style="font-size:16px">Strata could not start</h1>'
      + '<p>The interface reads its text from <code>web/strings/</code>, and '
      + 'one of those files could not be read:</p>'
      + `<pre style="white-space:pre-wrap">${String(e.message || e)}</pre>`
      + '<p>The engine and the evidence are unaffected. Restore the file, or '
      + 'reinstall this copy of the interface, and reload.</p></div>';
    return;
  }

  applyStrings();
  const s = document.createElement('script');
  s.src = 'app.js';
  document.body.appendChild(s);
})();
