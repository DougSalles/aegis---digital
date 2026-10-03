/**
 * Aegis Digital — análise passiva de segurança de sites (Vercel Serverless Function).
 *
 * O que faz: abre a página inicial do site informado como um navegador comum faria
 * (poucas requisições GET) e avalia cabeçalhos, certificado, redirecionamento e cookies.
 * O que NÃO faz: não testa falhas, não tenta adivinhar arquivos/pastas, não envia payloads.
 *
 * Proteções: SSRF (bloqueia IPs privados/reservados, fixa o IP resolvido, só portas 80/443),
 * limite de tamanho/tempo, limite de requisições por IP e confirmação de autorização.
 */
'use strict';

const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');

const UA = 'AegisDigitalScanner/1.0 (verificacao passiva; contato: douglassales890@gmail.com)';
const TIMEOUT_MS = 8000;
const MAX_BODY = 200 * 1024;
const MAX_REDIRECTS = 4;

/* ---------- Limite simples por IP (melhor esforço em ambiente serverless) ---------- */
const hits = new Map();
const WINDOW_MS = 10 * 60 * 1000;
const MAX_PER_WINDOW = 8;
function rateLimited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  if (list.length >= MAX_PER_WINDOW) { hits.set(ip, list); return true; }
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5000) { for (const [k, v] of hits) if (!v.some((t) => now - t < WINDOW_MS)) hits.delete(k); }
  return false;
}

/* ---------- Proteção contra SSRF ---------- */
function ipv4Private(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = p;
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}
function ipv6Private(ip) {
  const s = ip.toLowerCase();
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return ipv4Private(mapped[1]);
  // Só aceita endereço global unicast 2000::/3, exceto documentação (2001:db8::/32) e 6to4 (2002::/16)
  if (!/^[23]/.test(s)) return true;
  if (s.startsWith('2001:db8') || s.startsWith('2002:')) return true;
  return false;
}
function isPrivateIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) return ipv4Private(ip);
  if (v === 6) return ipv6Private(ip);
  return true;
}

async function resolveSafe(hostname) {
  if (net.isIP(hostname)) throw new UserError('Informe um nome de domínio, não um endereço IP.');
  if (!/^[a-z0-9.-]+$/i.test(hostname) || !hostname.includes('.') || hostname.length > 253) {
    throw new UserError('Domínio inválido.');
  }
  let addrs;
  try {
    addrs = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (e) {
    throw new UserError('Não foi possível resolver o domínio. Confira se está digitado corretamente.');
  }
  if (!addrs.length) throw new UserError('Domínio sem endereço IP público.');
  if (addrs.some((a) => isPrivateIp(a.address))) {
    throw new UserError('Este domínio aponta para um endereço não público e não pode ser verificado.');
  }
  return addrs[0];
}

class UserError extends Error {}

/* ---------- Requisição com IP fixo (evita DNS rebinding) ---------- */
function fetchOnce(urlObj, addr, { readBody = true } = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = urlObj.protocol === 'https:';
    const lib = isHttps ? https : http;
    const started = Date.now();
    const req = lib.request(
      {
        method: 'GET',
        hostname: urlObj.hostname,
        port: isHttps ? 443 : 80,
        path: urlObj.pathname + urlObj.search,
        headers: { 'User-Agent': UA, Accept: 'text/html,*/*;q=0.8', 'Accept-Encoding': 'identity', Connection: 'close' },
        servername: isHttps ? urlObj.hostname : undefined,
        rejectUnauthorized: false, // queremos relatar o erro de certificado, não falhar
        timeout: TIMEOUT_MS,
        // Fixa o IP já validado (evita DNS rebinding). Node 20+ pode pedir { all: true }.
        lookup: (_h, opts, cb) => (opts && opts.all
          ? cb(null, [{ address: addr.address, family: addr.family }])
          : cb(null, addr.address, addr.family)),
      },
      (res) => {
        const info = { status: res.statusCode, headers: res.headers, rawHeaders: res.rawHeaders, ms: Date.now() - started, body: '' };
        if (isHttps) {
          const s = res.socket;
          let cert = null;
          try { cert = s.getPeerCertificate(); } catch (_) { /* ignore */ }
          info.tls = {
            authorized: !!s.authorized,
            error: s.authorizationError ? String(s.authorizationError) : null,
            protocol: s.getProtocol ? s.getProtocol() : null,
            validTo: cert && cert.valid_to ? new Date(cert.valid_to).toISOString() : null,
            issuer: cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN || null) : null,
          };
        }
        if (!readBody) { res.destroy(); return resolve(info); }
        let size = 0;
        const chunks = [];
        res.on('data', (c) => {
          size += c.length;
          if (size > MAX_BODY) { res.destroy(); return; }
          chunks.push(c);
        });
        const done = () => { info.body = Buffer.concat(chunks).toString('utf8'); resolve(info); };
        res.on('end', done);
        res.on('close', done);
        res.on('error', () => resolve(info));
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

/** Segue redirecionamentos validando cada salto (host público, portas 80/443). */
async function fetchFollow(startUrl, opts) {
  let url = new URL(startUrl);
  const chain = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    if (!['http:', 'https:'].includes(url.protocol)) throw new UserError('Redirecionamento para protocolo não suportado.');
    if (url.port && !['80', '443'].includes(url.port)) throw new UserError('Redirecionamento para porta não padrão; verificação interrompida.');
    const addr = await resolveSafe(url.hostname);
    const res = await fetchOnce(url, addr);
    chain.push({ url: url.href, status: res.status });
    const loc = res.headers.location;
    if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
      url = new URL(loc, url);
      continue;
    }
    return { res, finalUrl: url, chain };
  }
  throw new UserError('Muitos redirecionamentos.');
}

/* ---------- Avaliação ---------- */
const WEIGHT = { Crítico: 4, Alto: 3, Médio: 2, Baixo: 1 };

function h(headers, name) { const v = headers[name.toLowerCase()]; return Array.isArray(v) ? v.join(', ') : v; }
function setCookies(rawHeaders) {
  const out = [];
  for (let i = 0; i < rawHeaders.length; i += 2) if (rawHeaders[i].toLowerCase() === 'set-cookie') out.push(rawHeaders[i + 1]);
  return out;
}
function add(list, id, name, cat, risk, status, detail, fix) { list.push({ id, name, cat, risk, status, detail, fix: fix || '' }); }

function evaluate({ res, finalUrl, chain }, httpProbe, secTxt) {
  const c = [];
  const hd = res.headers;
  const isHttps = finalUrl.protocol === 'https:';

  /* Conexão */
  add(c, 'https', 'Site responde por HTTPS', 'Conexão', 'Crítico', isHttps ? 'ok' : 'fail',
    isHttps ? 'A página final é entregue por HTTPS.' : 'A página final é entregue por HTTP, sem criptografia.',
    isHttps ? '' : 'Instale um certificado (ex.: Let\'s Encrypt) e sirva todo o site por HTTPS.');

  if (httpProbe.skipped) {
    add(c, 'redirect', 'HTTP redireciona para HTTPS', 'Conexão', 'Alto', 'info', httpProbe.skipped, '');
  } else if (httpProbe.error) {
    add(c, 'redirect', 'HTTP redireciona para HTTPS', 'Conexão', 'Alto', 'info', 'A porta 80 não respondeu (ok se o site só aceita HTTPS).', '');
  } else {
    const loc = httpProbe.headers.location || '';
    const toHttps = [301, 302, 307, 308].includes(httpProbe.status) && /^https:\/\//i.test(new URL(loc || '/', 'http://' + finalUrl.hostname).href);
    const permanent = [301, 308].includes(httpProbe.status);
    add(c, 'redirect', 'HTTP redireciona para HTTPS', 'Conexão', 'Alto', toHttps ? (permanent ? 'ok' : 'warn') : 'fail',
      toHttps ? (permanent ? 'Acessos por HTTP são redirecionados permanentemente para HTTPS.' : 'Há redirecionamento para HTTPS, mas temporário (' + httpProbe.status + ').')
              : 'Acessar por HTTP não leva automaticamente para HTTPS.',
      toHttps && permanent ? '' : 'Configure um redirecionamento 301 de todo o tráfego HTTP para HTTPS.');
  }

  if (res.tls) {
    const t = res.tls;
    add(c, 'cert', 'Certificado SSL/TLS confiável', 'Conexão', 'Crítico', t.authorized ? 'ok' : 'fail',
      t.authorized ? 'Certificado válido' + (t.issuer ? ' (emitido por ' + t.issuer + ').' : '.') : 'O certificado não foi aceito: ' + (t.error || 'erro desconhecido') + '.',
      t.authorized ? '' : 'Instale um certificado válido, com a cadeia completa, para o domínio exato.');
    if (t.validTo) {
      const days = Math.floor((new Date(t.validTo) - Date.now()) / 86400000);
      const st = days < 0 ? 'fail' : days < 15 ? 'fail' : days < 30 ? 'warn' : 'ok';
      add(c, 'certexp', 'Validade do certificado', 'Conexão', 'Alto', st,
        days < 0 ? 'O certificado expirou há ' + Math.abs(days) + ' dias.' : 'O certificado expira em ' + days + ' dias.',
        st === 'ok' ? '' : 'Renove o certificado e ative a renovação automática.');
    }
    if (t.protocol) {
      const okp = /TLSv1\.[23]/.test(t.protocol);
      add(c, 'tls', 'Versão do protocolo TLS', 'Conexão', 'Alto', okp ? 'ok' : 'fail',
        'Conexão negociada com ' + t.protocol + '.', okp ? '' : 'Desative TLS 1.0/1.1 e mantenha apenas TLS 1.2 e 1.3.');
    }
  }

  /* Cabeçalhos */
  const hsts = h(hd, 'strict-transport-security');
  if (!isHttps) {
    add(c, 'hsts', 'HSTS — forçar HTTPS', 'Cabeçalhos', 'Alto', 'fail', 'Não aplicável sem HTTPS.', 'Habilite HTTPS primeiro e depois o HSTS.');
  } else if (!hsts) {
    add(c, 'hsts', 'HSTS — forçar HTTPS', 'Cabeçalhos', 'Alto', 'fail', 'O cabeçalho Strict-Transport-Security não foi enviado.',
      'Adicione <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code>.');
  } else {
    const m = /max-age=(\d+)/i.exec(hsts);
    const age = m ? Number(m[1]) : 0;
    add(c, 'hsts', 'HSTS — forçar HTTPS', 'Cabeçalhos', 'Alto', age >= 15552000 ? 'ok' : 'warn',
      'Presente (max-age=' + age + ').', age >= 15552000 ? '' : 'Aumente o max-age para pelo menos 15552000 (180 dias); o ideal é 31536000.');
  }

  const csp = h(hd, 'content-security-policy');
  if (!csp) {
    add(c, 'csp', 'Content-Security-Policy', 'Cabeçalhos', 'Alto', 'fail', 'Nenhuma política de segurança de conteúdo foi enviada.',
      'Defina uma CSP que permita scripts só de origens confiáveis. Comece com <code>Content-Security-Policy-Report-Only</code> para testar sem quebrar o site.');
  } else {
    const weak = /script-src[^;]*'unsafe-(inline|eval)'/i.test(csp) || (/default-src[^;]*'unsafe-inline'/i.test(csp) && !/script-src/i.test(csp));
    add(c, 'csp', 'Content-Security-Policy', 'Cabeçalhos', 'Alto', weak ? 'warn' : 'ok',
      weak ? 'Há CSP, mas ela permite scripts inline/eval, o que reduz a proteção contra XSS.' : 'Política presente.',
      weak ? 'Troque <code>\'unsafe-inline\'</code> por nonces ou hashes nos scripts.' : '');
  }

  const xfo = h(hd, 'x-frame-options');
  const fa = csp && /frame-ancestors/i.test(csp);
  add(c, 'frame', 'Proteção contra clickjacking', 'Cabeçalhos', 'Alto', xfo || fa ? 'ok' : 'fail',
    xfo ? 'X-Frame-Options: ' + xfo + '.' : fa ? 'Protegido via frame-ancestors na CSP.' : 'Nada impede que o site seja exibido dentro de um iframe de outro site.',
    xfo || fa ? '' : 'Adicione <code>X-Frame-Options: SAMEORIGIN</code> ou <code>frame-ancestors \'self\'</code> na CSP.');

  const xcto = (h(hd, 'x-content-type-options') || '').toLowerCase();
  add(c, 'nosniff', 'X-Content-Type-Options', 'Cabeçalhos', 'Médio', xcto === 'nosniff' ? 'ok' : 'fail',
    xcto === 'nosniff' ? 'nosniff ativo.' : 'Cabeçalho ausente: o navegador pode "adivinhar" o tipo de arquivo.',
    xcto === 'nosniff' ? '' : 'Adicione <code>X-Content-Type-Options: nosniff</code>.');

  const rp = h(hd, 'referrer-policy');
  add(c, 'referrer', 'Referrer-Policy', 'Cabeçalhos', 'Baixo', rp ? 'ok' : 'warn',
    rp ? 'Política: ' + rp + '.' : 'Sem política: URLs completas podem vazar para outros sites.',
    rp ? '' : 'Adicione <code>Referrer-Policy: strict-origin-when-cross-origin</code>.');

  const pp = h(hd, 'permissions-policy');
  add(c, 'perm', 'Permissions-Policy', 'Cabeçalhos', 'Baixo', pp ? 'ok' : 'warn',
    pp ? 'Política presente.' : 'Sem restrição de recursos do navegador (câmera, microfone, localização).',
    pp ? '' : 'Adicione, por exemplo, <code>Permissions-Policy: camera=(), microphone=(), geolocation=()</code>.');

  const acao = h(hd, 'access-control-allow-origin');
  const acac = (h(hd, 'access-control-allow-credentials') || '').toLowerCase() === 'true';
  if (acao) {
    const st = acao === '*' && acac ? 'fail' : acao === '*' ? 'info' : 'ok';
    add(c, 'cors', 'Política CORS', 'Cabeçalhos', 'Médio', st,
      acao === '*' ? (acac ? 'Origem "*" com credenciais habilitadas — combinação perigosa.' : 'Qualquer origem pode ler respostas públicas (ok para conteúdo público).') : 'CORS restrito a origem específica.',
      st === 'fail' ? 'Nunca combine <code>Access-Control-Allow-Origin: *</code> com credenciais; liste origens específicas.' : '');
  }

  /* Configuração */
  const server = h(hd, 'server') || '';
  const powered = h(hd, 'x-powered-by') || '';
  const leaks = [];
  if (/\d+\.\d+/.test(server)) leaks.push('Server: ' + server);
  if (powered) leaks.push('X-Powered-By: ' + powered);
  add(c, 'leak', 'Exposição de tecnologia/versão', 'Configuração', 'Médio', leaks.length ? 'warn' : 'ok',
    leaks.length ? 'O servidor revela detalhes: ' + leaks.join(' · ') + '.' : 'Nenhuma versão de software exposta nos cabeçalhos.',
    leaks.length ? 'Apache: <code>ServerTokens Prod</code>. Nginx: <code>server_tokens off;</code>. Remova <code>X-Powered-By</code> na aplicação.' : '');

  /* Cookies */
  const cookies = setCookies(res.rawHeaders);
  if (!cookies.length) {
    add(c, 'cookies', 'Atributos de segurança dos cookies', 'Aplicação', 'Alto', 'info', 'A página inicial não define cookies.', '');
  } else {
    const problems = [];
    cookies.forEach((ck) => {
      const name = ck.split('=')[0];
      const miss = [];
      if (isHttps && !/;\s*secure/i.test(ck)) miss.push('Secure');
      if (!/;\s*httponly/i.test(ck)) miss.push('HttpOnly');
      if (!/;\s*samesite=/i.test(ck)) miss.push('SameSite');
      if (miss.length) problems.push(name + ' (falta ' + miss.join(', ') + ')');
    });
    add(c, 'cookies', 'Atributos de segurança dos cookies', 'Aplicação', 'Alto', problems.length ? 'warn' : 'ok',
      problems.length ? 'Cookies sem proteção completa: ' + problems.join('; ') + '.' : cookies.length + ' cookie(s) com Secure, HttpOnly e SameSite.',
      problems.length ? 'Defina <code>Secure; HttpOnly; SameSite=Lax</code> nos cookies de sessão. (HttpOnly pode ser dispensado só em cookies que o JavaScript precisa ler.)' : '');
  }

  /* Conteúdo misto (apenas leitura do HTML já baixado) */
  if (isHttps && res.body) {
    const mixed = /<(?:script|img|iframe|link|source|video|audio)\b[^>]*\b(?:src|href)=["']http:\/\/(?!localhost)/i.test(res.body);
    add(c, 'mixed', 'Conteúdo misto (HTTP dentro de HTTPS)', 'Aplicação', 'Médio', mixed ? 'warn' : 'ok',
      mixed ? 'A página carrega recursos por HTTP, que podem ser interceptados ou bloqueados.' : 'Nenhum recurso HTTP encontrado na página inicial.',
      mixed ? 'Troque todos os endereços <code>http://</code> de scripts, imagens e estilos por <code>https://</code>.' : '');
  }

  /* security.txt */
  add(c, 'sectxt', 'Canal de contato para vulnerabilidades (security.txt)', 'Boas práticas', 'Baixo', secTxt ? 'ok' : 'info',
    secTxt ? 'Arquivo /.well-known/security.txt encontrado.' : 'Não encontrado — recomendado para que pesquisadores saibam como avisar você.',
    secTxt ? '' : 'Crie <code>/.well-known/security.txt</code> com Contact e Expires (veja securitytxt.org).');

  return c;
}

function score(checks) {
  let got = 0, max = 0;
  for (const k of checks) {
    if (k.status === 'info') continue;
    const w = WEIGHT[k.risk] || 1;
    max += w;
    got += k.status === 'ok' ? w : k.status === 'warn' ? w * 0.5 : 0;
  }
  const s = max ? Math.round((got / max) * 100) : 0;
  const grade = s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F';
  return { score: s, grade };
}

/* ---------- Handler ---------- */
function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(obj));
}

async function readJson(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let data = '';
  for await (const chunk of req) { data += chunk; if (data.length > 4096) throw new UserError('Requisição muito grande.'); }
  try { return JSON.parse(data || '{}'); } catch (_) { throw new UserError('JSON inválido.'); }
}

module.exports = async (req, res) => {
  // CORS: por padrão só o próprio site. Para liberar outro domínio, defina ALLOWED_ORIGIN.
  const allowed = process.env.ALLOWED_ORIGIN;
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', allowed);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
  if (req.method !== 'POST') return send(res, 405, { error: 'Use POST.' });

  const ip = String((req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x')).split(',')[0].trim();
  if (rateLimited(ip)) return send(res, 429, { error: 'Muitas verificações em pouco tempo. Tente novamente em alguns minutos.' });

  try {
    const body = await readJson(req);
    if (body.authorized !== true) throw new UserError('Confirme que você é o proprietário do site ou tem autorização para verificá-lo.');

    let raw = String(body.url || '').trim();
    if (!raw || /\s/.test(raw) || raw.length > 300) throw new UserError('URL inválida.');
    if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
    let u;
    try { u = new URL(raw); } catch (_) { throw new UserError('URL inválida.'); }
    if (!['http:', 'https:'].includes(u.protocol)) throw new UserError('Use um endereço http:// ou https://.');
    if (u.username || u.password) throw new UserError('Não use usuário/senha na URL.');
    if (u.port && !['80', '443'].includes(u.port)) throw new UserError('Apenas as portas padrão (80/443) são verificadas.');
    u.hash = '';
    // Analisa apenas a página inicial do domínio informado.
    const start = new URL('/', u.origin);

    const result = await fetchFollow(start.href);

    // Sonda HTTP -> HTTPS (uma requisição, sem seguir redirecionamento)
    let httpProbe;
    try {
      const addr = await resolveSafe(result.finalUrl.hostname);
      httpProbe = await fetchOnce(new URL('http://' + result.finalUrl.hostname + '/'), addr, { readBody: false });
    } catch (e) {
      httpProbe = e instanceof UserError ? { skipped: e.message } : { error: true };
    }

    // security.txt (arquivo público padronizado)
    let secTxt = false;
    try {
      const addr = await resolveSafe(result.finalUrl.hostname);
      const st = await fetchOnce(new URL('/.well-known/security.txt', result.finalUrl.origin), addr);
      secTxt = st.status === 200 && /^\s*contact\s*:/im.test(st.body);
    } catch (_) { /* ignora */ }

    const checks = evaluate(result, httpProbe, secTxt);
    const sc = score(checks);
    return send(res, 200, {
      host: result.finalUrl.hostname,
      finalUrl: result.finalUrl.origin + '/',
      httpStatus: result.res.status,
      responseMs: result.res.ms,
      redirects: result.chain,
      ...sc,
      checks,
      scannedAt: new Date().toISOString(),
    });
  } catch (e) {
    if (e instanceof UserError) return send(res, 400, { error: e.message });
    const msg = e && e.code === 'ECONNREFUSED' ? 'O site recusou a conexão.'
      : e && (e.message === 'timeout' || e.code === 'ETIMEDOUT') ? 'O site demorou demais para responder.'
      : 'Não foi possível acessar o site. Verifique se ele está no ar.';
    return send(res, 502, { error: msg });
  }
};

// Exporta utilitários para testes locais
module.exports.__test = { isPrivateIp, evaluate, score };
