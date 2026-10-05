require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');
const { authenticator } = require('otplib');
const crypto = require('crypto');

// Tolerancia: acepta el código actual y el inmediatamente anterior/siguiente (±30s)
// para evitar fallos por desfase de reloj entre el móvil y el servidor.
authenticator.options = { window: 1 };

// Valida un código TOTP de 6 dígitos contra el secreto en la variable de entorno.
// Devuelve true si es válido. Si no hay secreto configurado, devuelve null (no configurado).
function verifyTotp(code) {
  const secret = process.env.TOTP_SECRET;
  if (!secret) return null;
  if (!code || !/^\d{6}$/.test(String(code).trim())) return false;
  try {
    return authenticator.verify({ token: String(code).trim(), secret });
  } catch (e) {
    return false;
  }
}

// ─── MODELO DE IA ─────────────────────────────────────────────────────────────
// Un único sitio para cambiar el modelo de Claude que usa toda la app.
const CLAUDE_MODEL = 'claude-sonnet-5-5';
// Claude Sonnet 5.5 "piensa" antes de responder por defecto, y ese razonamiento gasta del mismo
// límite (max_tokens) que el texto: con límites ajustados (un post) se quedaba sin texto.
// "between_tools" desactiva el razonamiento previo (como el modelo anterior).
const CLAUDE_THINKING = { type: 'between_tools' };

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// ─── SESIÓN SEGURA (tras el código de Google Authenticator) ───────────────────
// Antes, el código solo protegía la pantalla de entrada: las funciones /api respondían
// a cualquiera que conociera la dirección. Ahora, al validar el código, el servidor
// entrega una cookie de sesión firmada (HttpOnly: el navegador la envía solo y ningún
// script puede leerla). Todas las /api la exigen, salvo estas excepciones:
const SESSION_HOURS = 12;
const PUBLIC_API = new Set([
  '/api/access',          // donde se introduce el código
  '/api/session',         // comprobar si la sesión sigue viva
  '/api/auth/callback',   // vuelta de LinkedIn tras conectar la cuenta
  '/api/cron/publish-due' // cron-job.org (tiene su propio token secreto)
]);
function sessionKey() {
  // Clave derivada de secretos que ya existen en Vercel: no hace falta crear variables nuevas
  const base = process.env.TOTP_SECRET || '';
  return crypto.createHmac('sha256', base + '|' + (process.env.SUPABASE_SERVICE_KEY || '')).update('streamvoice-session-v1').digest();
}
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function signSession(expMs) {
  const payload = b64url(JSON.stringify({ exp: expMs }));
  const sig = b64url(crypto.createHmac('sha256', sessionKey()).update(payload).digest());
  return payload + '.' + sig;
}
function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
function hasValidSession(req) {
  if (!process.env.TOTP_SECRET) return true; // sin secreto configurado la app no tiene bloqueo (como antes)
  const tok = readCookie(req, 'sv_session');
  if (!tok || tok.indexOf('.') < 0) return false;
  const [payload, sig] = tok.split('.');
  const expected = b64url(crypto.createHmac('sha256', sessionKey()).update(payload).digest());
  const a = Buffer.from(sig || ''), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const { exp } = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
    return typeof exp === 'number' && exp > Date.now();
  } catch (e) { return false; }
}
function setSessionCookie(res) {
  const exp = Date.now() + SESSION_HOURS * 3600 * 1000;
  res.setHeader('Set-Cookie', `sv_session=${signSession(exp)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}`);
}
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/') || PUBLIC_API.has(req.path)) return next();
  if (hasValidSession(req)) return next();
  return res.status(401).json({ error: 'session_required', detail: 'Tu sesión ha caducado. Vuelve a introducir el código de tu app de autenticación.' });
});

// ─── SUPABASE (almacenamiento persistente) ─────────────────────────────────────
// Usamos la clave "service_role", no la anónima: con RLS cerrado (sin políticas
// para el rol público), solo service_role puede leer/escribir, saltándose el RLS
// por diseño. Así, aunque la clave anónima se filtrara algún día, no serviría de nada.
const SB_URL = process.env.SUPABASE_URL;
const SB_KEY = process.env.SUPABASE_SERVICE_KEY;
const sbHeaders = {
  'apikey': SB_KEY,
  'Authorization': `Bearer ${SB_KEY}`,
  'Content-Type': 'application/json'
};
if (!SB_KEY) {
  console.error('⚠️  Falta la variable de entorno SUPABASE_SERVICE_KEY. La app no podrá leer/escribir en Supabase.');
}
// Como la app la usa una sola persona, usamos un identificador fijo para "la" sesión
const SESSION_ID = 'borja-main';

async function sbGet(table, query='') {
  const r = await axios.get(`${SB_URL}/rest/v1/${table}${query}`, { headers: sbHeaders });
  return r.data;
}
async function sbUpsert(table, row) {
  const r = await axios.post(`${SB_URL}/rest/v1/${table}`, row, {
    headers: { ...sbHeaders, 'Prefer': 'resolution=merge-duplicates,return=representation' }
  });
  return r.data;
}
async function sbDelete(table, query) {
  await axios.delete(`${SB_URL}/rest/v1/${table}${query}`, { headers: sbHeaders });
}

// Guardar / leer la sesión de LinkedIn en Supabase
async function saveSession(data) {
  await sbUpsert('sessions', { id: SESSION_ID, data, expires_at: data.tokenExpiry ? new Date(data.tokenExpiry).toISOString() : null });
}
async function loadSession() {
  try {
    const rows = await sbGet('sessions', `?id=eq.${SESSION_ID}&select=*`);
    if (rows && rows[0]) return rows[0].data;
  } catch(e) { console.error('loadSession error:', e.response?.data || e.message); }
  return null;
}
async function clearSession() {
  try { await sbDelete('sessions', `?id=eq.${SESSION_ID}`); } catch(e) {}
}

// In-memory store solo para posts/métricas (no crítico)
const store = {
  posts: [],
  metrics: [],
  userProfile: null
};

// ─── SEGURIDAD DE ACCESO (Google Authenticator / TOTP) ──────────────────────
// Verifica el código de 6 dígitos de la app de autenticación para acceder a la app
// Protección contra fuerza bruta: tras 10 códigos fallidos en 15 minutos, se bloquea
// la entrada 15 minutos (los fallos se guardan en Supabase, tabla access_failures).
const MAX_ACCESS_FAILS = 10, ACCESS_WINDOW_MIN = 15;
async function recentAccessFailures() {
  try {
    const since = new Date(Date.now() - ACCESS_WINDOW_MIN * 60000).toISOString();
    const rows = await sbGet('access_failures', `?at=gte.${since}&select=id`);
    return (rows || []).length;
  } catch (e) { return 0; }
}
app.post('/api/access', async (req, res) => {
  const { code } = req.body;
  if (!process.env.TOTP_SECRET) {
    // No hay secreto TOTP configurado: se permite el acceso para no bloquear la app
    return res.json({ ok: true, noAuthSet: true });
  }
  if (await recentAccessFailures() >= MAX_ACCESS_FAILS) {
    return res.status(429).json({ ok: false, error: 'too_many_attempts', detail: `Demasiados intentos fallidos. Espera ${ACCESS_WINDOW_MIN} minutos y vuelve a probar.` });
  }
  if (verifyTotp(code) === true) {
    setSessionCookie(res);
    return res.json({ ok: true });
  }
  try { await sbUpsert('access_failures', { at: new Date().toISOString() }); } catch (e) {}
  return res.status(403).json({ ok: false, error: 'Código incorrecto o caducado' });
});

// ¿Sigue viva la sesión? (lo usa la pantalla al volver de conectar LinkedIn)
app.get('/api/session', (req, res) => {
  res.json({ ok: hasValidSession(req) });
});

// ─── AUTH ─────────────────────────────────────────────────────────────────────

app.get('/api/auth/linkedin', (req, res) => {
  const scope = 'openid profile email w_member_social';
  const url = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.LINKEDIN_REDIRECT_URI)}&scope=${encodeURIComponent(scope)}&state=streamvoice`;
  res.redirect(url);
});

app.get('/api/auth/callback', async (req, res) => {
  const { code } = req.query;
  try {
    const tokenRes = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', null, {
      params: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
        client_id: process.env.LINKEDIN_CLIENT_ID,
        client_secret: process.env.LINKEDIN_CLIENT_SECRET
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const accessToken = tokenRes.data.access_token;
    const tokenExpiry = Date.now() + tokenRes.data.expires_in * 1000;

    // Fetch LinkedIn profile
    const profileRes = await axios.get('https://api.linkedin.com/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    // Guardar la sesión en Supabase (persistente)
    await saveSession({ accessToken, tokenExpiry, profile: profileRes.data });

    res.redirect('/?connected=true');
  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message);
    res.redirect('/?error=auth_failed');
  }
});

app.get('/api/auth/status', async (req, res) => {
  const s = await loadSession();
  const connected = !!(s && s.accessToken && s.tokenExpiry > Date.now());
  res.json({
    connected,
    profile: connected ? s.profile : null,
    expiresIn: connected ? Math.floor((s.tokenExpiry - Date.now()) / 1000) : 0
  });
});

app.post('/api/auth/logout', async (req, res) => {
  await clearSession();
  res.json({ ok: true });
});

// ─── MIDDLEWARE: require auth ──────────────────────────────────────────────────

async function requireAuth(req, res, next) {
  const s = await loadSession();
  if (!s || !s.accessToken || s.tokenExpiry < Date.now()) {
    return res.status(401).json({ error: 'Not authenticated. Please connect LinkedIn.' });
  }
  req.linkedinSession = s;
  next();
}

// ─── PUBLISH ──────────────────────────────────────────────────────────────────

app.post('/api/publish', requireAuth, async (req, res) => {
  const { text, scheduledAt, code, image, firstComment } = req.body;
  if (!text) return res.status(400).json({ error: 'Missing text' });

  // Verificar código de la app de autenticación (segunda barrera de seguridad)
  const totp = verifyTotp(code);
  if (totp === false) {
    return res.status(403).json({ error: 'wrong_code', detail: 'Código de autenticación incorrecto o caducado.' });
  }

  // Publish now
  try {
    // Si viene imagen, la subimos primero a LinkedIn y obtenemos su asset URN
    let imageAsset = null;
    if (image) {
      try {
        imageAsset = await uploadImageToLinkedIn(image, req.linkedinSession);
      } catch (imgErr) {
        console.error('Image upload error:', imgErr.response?.data || imgErr.message);
        return res.status(500).json({ error: 'image_upload_failed', detail: imgErr.response?.data || imgErr.message });
      }
    }
    const result = await publishToLinkedIn(text, req.linkedinSession, imageAsset);
    // Enlace como primer comentario (si se pidió). Si LinkedIn no lo permite, el post
    // ya está publicado igualmente: se avisa al usuario para que lo pegue a mano.
    let comment = null;
    if (firstComment && String(firstComment).trim()) {
      comment = await addFirstComment(result.linkedinId, String(firstComment).trim(), req.linkedinSession);
    }
    // Guardar en el historial de publicados
    try {
      await sbUpsert('scheduled_posts', {
        text,
        scheduled_at: new Date().toISOString(),
        status: 'published',
        published_at: new Date().toISOString(),
        linkedin_id: result.linkedinId,
        first_comment: comment ? String(firstComment).trim() : null,
        comment_status: comment ? (comment.ok ? 'ok' : 'failed') : null
      });
    } catch(e) { console.error('No se pudo guardar en historial:', e.message); }
    res.json({ ok: true, status: 'published', linkedinId: result.linkedinId, withImage: !!imageAsset,
      comment: comment ? { ok: comment.ok } : null });
  } catch (err) {
    console.error('Publish error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to publish', detail: err.response?.data });
  }
});

// Sube una imagen a LinkedIn (API clásica de assets) y devuelve su asset URN.
// imageDataUrl: cadena base64 tipo "data:image/png;base64,AAAA..."
async function uploadImageToLinkedIn(imageDataUrl, session) {
  const authorId = session.profile?.sub;
  const authorUrn = `urn:li:person:${authorId}`;

  // 1. Registrar la subida
  const registerPayload = {
    registerUploadRequest: {
      recipes: ['urn:li:digitalmediaRecipe:feedshare-image'],
      owner: authorUrn,
      serviceRelationships: [
        { relationshipType: 'OWNER', identifier: 'urn:li:userGeneratedContent' }
      ]
    }
  };
  const regRes = await axios.post(
    'https://api.linkedin.com/v2/assets?action=registerUpload',
    registerPayload,
    { headers: {
        Authorization: `Bearer ${session.accessToken}`,
        'Content-Type': 'application/json',
        'X-Restli-Protocol-Version': '2.0.0'
    }}
  );
  const uploadUrl = regRes.data?.value?.uploadMechanism?.
    ['com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest']?.uploadUrl;
  const asset = regRes.data?.value?.asset;
  if (!uploadUrl || !asset) {
    throw new Error('LinkedIn no devolvió uploadUrl/asset al registrar la imagen');
  }

  // 2. Convertir base64 → binario
  const match = /^data:(image\/[a-zA-Z+]+);base64,(.+)$/.exec(imageDataUrl || '');
  if (!match) throw new Error('Formato de imagen no válido (se esperaba data URL base64)');
  const contentType = match[1];
  const binary = Buffer.from(match[2], 'base64');

  // 3. Subir el binario a la URL temporal
  await axios.put(uploadUrl, binary, {
    headers: {
      Authorization: `Bearer ${session.accessToken}`,
      'Content-Type': contentType
    },
    maxBodyLength: Infinity,
    maxContentLength: Infinity
  });

  return asset; // urn:li:digitalmediaAsset:...
}

// Función reutilizable para publicar en LinkedIn.
// imageAsset (opcional): urn:li:digitalmediaAsset:... ya subido, para adjuntar una imagen.
async function publishToLinkedIn(text, session, imageAsset) {
  const authorId = session.profile?.sub;
  const urlMatch = text.match(/https?:\/\/[^\s]+/);
  let shareContent;
  if (imageAsset) {
    // Con imagen propia: prioriza la imagen (no se combina con preview de artículo)
    shareContent = {
      shareCommentary: { text },
      shareMediaCategory: 'IMAGE',
      media: [{ status: 'READY', media: imageAsset }]
    };
  } else if (urlMatch) {
    shareContent = {
      shareCommentary: { text },
      shareMediaCategory: 'ARTICLE',
      media: [{ status: 'READY', originalUrl: urlMatch[0] }]
    };
  } else {
    shareContent = {
      shareCommentary: { text },
      shareMediaCategory: 'NONE'
    };
  }
  const payload = {
    author: `urn:li:person:${authorId}`,
    lifecycleState: 'PUBLISHED',
    specificContent: { 'com.linkedin.ugc.ShareContent': shareContent },
    visibility: { 'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC' }
  };
  const publishRes = await axios.post('https://api.linkedin.com/v2/ugcPosts', payload, {
    headers: {
      Authorization: `Bearer ${session.accessToken}`,
      'Content-Type': 'application/json',
      'X-Restli-Protocol-Version': '2.0.0'
    }
  });
  return { linkedinId: publishRes.data.id };
}

// Publica un comentario en un post propio (el "primer comentario" con el enlace).
// Ojo: según la documentación de LinkedIn, comentar exige el permiso w_member_social_feed,
// que esta app puede no tener. Se intenta por las dos vías de la API y, si ninguna
// funciona, se devuelve ok:false sin romper la publicación.
async function addFirstComment(postUrn, text, session) {
  const actor = `urn:li:person:${session.profile?.sub}`;
  const body = { actor, object: postUrn, message: { text } };
  const enc = encodeURIComponent(postUrn);
  const attempts = [
    { url: `https://api.linkedin.com/v2/socialActions/${enc}/comments`, headers: { 'X-Restli-Protocol-Version': '2.0.0' } },
    { url: `https://api.linkedin.com/rest/socialActions/${enc}/comments`, headers: { 'X-Restli-Protocol-Version': '2.0.0', 'LinkedIn-Version': '202509' } }
  ];
  let lastErr = null;
  for (const a of attempts) {
    try {
      await axios.post(a.url, body, { headers: { Authorization: `Bearer ${session.accessToken}`, 'Content-Type': 'application/json', ...a.headers }, timeout: 10000 });
      return { ok: true };
    } catch (e) {
      lastErr = e.response?.data || e.message;
    }
  }
  console.error('First comment failed:', JSON.stringify(lastErr).slice(0, 300));
  return { ok: false, error: lastErr };
}

// ─── PROGRAMACIÓN DE POSTS ──────────────────────────────────────────────────
// Programar un post para el futuro
app.post('/api/schedule', requireAuth, async (req, res) => {
  const { text, scheduledAt, code, firstComment } = req.body;
  if (!text || !scheduledAt) return res.status(400).json({ error: 'Faltan datos' });
  const totp = verifyTotp(code);
  if (totp === false) {
    return res.status(403).json({ error: 'wrong_code', detail: 'Código de autenticación incorrecto o caducado.' });
  }
  if (new Date(scheduledAt) <= new Date()) {
    return res.status(400).json({ error: 'La fecha debe ser futura' });
  }
  try {
    await sbUpsert('scheduled_posts', { text, scheduled_at: scheduledAt, status: 'pending',
      first_comment: firstComment && String(firstComment).trim() ? String(firstComment).trim() : null });
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: 'No se pudo programar', detail: e.message });
  }
});

// Listar posts programados (pendientes por defecto, o por status)
app.get('/api/scheduled', async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const order = status === 'published' ? 'published_at.desc' : 'scheduled_at.asc';
    const rows = await sbGet('scheduled_posts', `?status=eq.${status}&select=*&order=${order}`);
    res.json(rows || []);
  } catch(e) { res.json([]); }
});

// Editar un post programado (texto y/o fecha)
app.patch('/api/scheduled/:id', requireAuth, async (req, res) => {
  const { text, scheduledAt, code } = req.body;
  const totp = verifyTotp(code);
  if (totp === false) {
    return res.status(403).json({ error: 'wrong_code', detail: 'Código de autenticación incorrecto o caducado.' });
  }
  const patch = {};
  if (text) patch.text = text;
  if (scheduledAt) {
    if (new Date(scheduledAt) <= new Date()) return res.status(400).json({ error: 'La fecha debe ser futura' });
    patch.scheduled_at = scheduledAt;
  }
  if (!Object.keys(patch).length) return res.status(400).json({ error: 'Nada que actualizar' });
  try {
    await axios.patch(`${SB_URL}/rest/v1/scheduled_posts?id=eq.${req.params.id}`, patch, { headers: sbHeaders });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'No se pudo editar', detail: e.message }); }
});

// Cancelar/borrar un post programado
app.delete('/api/scheduled/:id', async (req, res) => {
  try {
    await sbDelete('scheduled_posts', `?id=eq.${req.params.id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'No se pudo borrar' }); }
});

// Endpoint que llama cron-job.org: publica los posts cuya hora ya llegó
app.get('/api/cron/publish-due', async (req, res) => {
  // Seguridad: requiere un token secreto para que no lo llame cualquiera
  if (req.query.token !== process.env.CRON_SECRET) {
    return res.status(403).json({ error: 'forbidden' });
  }
  try {
    const session = await loadSession();
    if (!session || !session.accessToken || session.tokenExpiry < Date.now()) {
      return res.json({ ok: false, reason: 'LinkedIn no conectado o sesión expirada' });
    }
    const nowIso = new Date().toISOString();
    const due = await sbGet('scheduled_posts', `?status=eq.pending&scheduled_at=lte.${nowIso}&select=*`);
    const results = [];
    for (const post of (due || [])) {
      try {
        const result = await publishToLinkedIn(post.text, session);
        let commentStatus = null;
        if (post.first_comment) {
          const c = await addFirstComment(result.linkedinId, post.first_comment, session);
          commentStatus = c.ok ? 'ok' : 'failed';
        }
        await axios.patch(`${SB_URL}/rest/v1/scheduled_posts?id=eq.${post.id}`,
          { status: 'published', published_at: new Date().toISOString(), linkedin_id: result.linkedinId, comment_status: commentStatus },
          { headers: sbHeaders });
        results.push({ id: post.id, status: 'published' });
      } catch(err) {
        await axios.patch(`${SB_URL}/rest/v1/scheduled_posts?id=eq.${post.id}`,
          { status: 'error', error: (err.response?.data?.message || err.message || '').slice(0,200) },
          { headers: sbHeaders });
        results.push({ id: post.id, status: 'error' });
      }
    }
    res.json({ ok: true, processed: results.length, results });
  } catch(e) {
    res.status(500).json({ error: 'cron failed', detail: e.message });
  }
});

// ─── METRICS ──────────────────────────────────────────────────────────────────

app.get('/api/metrics/:postId', requireAuth, async (req, res) => {
  const post = store.posts.find(p => p.id === req.params.postId);
  if (!post || !post.linkedinId) return res.status(404).json({ error: 'Post not found or not published' });

  try {
    // LinkedIn Statistics API
    const statsRes = await axios.get(
      `https://api.linkedin.com/v2/socialMetadata/${encodeURIComponent(post.linkedinId)}`,
      { headers: { Authorization: `Bearer ${req.linkedinSession.accessToken}` } }
    );

    const data = statsRes.data;
    const metrics = {
      postId: post.id,
      linkedinId: post.linkedinId,
      impressions: data.totalShareStatistics?.impressionCount || 0,
      reactions: data.totalShareStatistics?.likeCount || 0,
      comments: data.totalShareStatistics?.commentCount || 0,
      shares: data.totalShareStatistics?.shareCount || 0,
      clicks: data.totalShareStatistics?.clickCount || 0,
      engagementRate: data.totalShareStatistics?.engagement || 0,
      fetchedAt: new Date().toISOString()
    };

    // Cache metrics
    const existing = store.metrics.findIndex(m => m.postId === post.id);
    if (existing >= 0) store.metrics[existing] = metrics;
    else store.metrics.push(metrics);

    res.json(metrics);
  } catch (err) {
    // Return cached if available
    const cached = store.metrics.find(m => m.postId === post.id);
    if (cached) return res.json({ ...cached, fromCache: true });
    res.status(500).json({ error: 'Failed to fetch metrics', detail: err.response?.data });
  }
});

app.get('/api/metrics', requireAuth, (req, res) => {
  const enriched = store.posts.map(post => {
    const metrics = store.metrics.find(m => m.postId === post.id) || {};
    return { ...post, metrics };
  });
  res.json(enriched);
});

// ─── POSTS STORE ──────────────────────────────────────────────────────────────

app.get('/api/posts', requireAuth, (req, res) => {
  res.json(store.posts.sort((a, b) => new Date(b.createdAt || b.publishedAt || b.scheduledAt) - new Date(a.createdAt || a.publishedAt || a.scheduledAt)));
});

app.delete('/api/posts/:id', requireAuth, (req, res) => {
  const idx = store.posts.findIndex(p => p.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Not found' });
  store.posts.splice(idx, 1);
  res.json({ ok: true });
});

// ─── AI GENERATION (proxy to Anthropic) ──────────────────────────────────────

app.post('/api/generate', async (req, res) => {
  const { topic, profile, tones, length } = req.body;

  const lengthMap = {
    l500: 'aproximadamente 500 caracteres. Breve pero con una idea desarrollada. Es una cifra orientativa, no un límite estricto.',
    l800: 'aproximadamente 800 caracteres. Conciso pero con desarrollo completo de la idea. Cifra orientativa.',
    l1000: 'aproximadamente 1000 caracteres. Desarrollo completo con espacio para matices. Cifra orientativa (±100 está bien).',
    l1200: 'aproximadamente 1200 caracteres. Desarrollo amplio, ideal para dar contexto y lectura estratégica. Cifra orientativa (±150 está bien).',
    l1400: 'aproximadamente 1400 caracteres. Post sustancioso con espacio para varios ángulos. Cifra orientativa (±150 está bien).',
    l1600: 'aproximadamente 1600 caracteres. Post extenso y con profundidad, en la franja de mayor engagement de LinkedIn. Cifra orientativa (±200 está bien).'
  };

  // 38 tonos con su descripción y si llevan emojis
  const toneMap = {
    alegre:{d:'optimista y entusiasta',e:true}, neutro:{d:'sin emociones fuertes, directo y equilibrado',e:false},
    triste:{d:'expresa pena o melancolía con respeto',e:false}, formal:{d:'lenguaje estructurado y profesional',e:false},
    informal:{d:'relajado y cercano',e:true}, motivacional:{d:'inspirador y alentador',e:true},
    humoristico:{d:'con humor y tono juguetón',e:true}, serio:{d:'directo y sin adornos, para temas importantes',e:false},
    persuasivo:{d:'busca convencer e influir',e:false}, emocional:{d:'expresa sentimientos profundos y empatía',e:true},
    informativo:{d:'proporciona datos e información relevante',e:false}, inspirador:{d:'motiva a alcanzar metas',e:true},
    educativo:{d:'enseña algo nuevo o da consejos prácticos',e:false}, conversacional:{d:'como si hablaras con un amigo',e:true},
    autoritario:{d:'muestra confianza y liderazgo',e:false}, amigable:{d:'cálido y acogedor',e:true},
    entusiasta:{d:'muestra gran energía y excitación',e:true}, reflexivo:{d:'invita a la reflexión y al pensamiento profundo',e:false},
    narrativo:{d:'cuenta una historia o anécdota',e:false}, empatico:{d:'muestra comprensión hacia el lector',e:true},
    desafiante:{d:'retador, saca al lector de su zona de confort',e:false}, optimista:{d:'ve el lado positivo',e:true},
    analitico:{d:'enfocado en el análisis y los datos',e:false}, humilde:{d:'reconoce limitaciones o aprendizajes',e:false},
    divertido:{d:'incluye humor o chistes',e:true}, directo:{d:'va al grano, sin rodeos',e:false},
    provocativo:{d:'invita al debate o la controversia',e:false}, reconfortante:{d:'ofrece consuelo o seguridad',e:true},
    sorprendente:{d:'revela información impactante o inesperada',e:true}, agradecido:{d:'muestra aprecio o gratitud',e:true},
    sarcastico:{d:'usa el sarcasmo para hacer un punto',e:true}, esperanzador:{d:'transmite esperanza y positividad',e:true},
    respetuoso:{d:'muestra respeto y consideración',e:false}, intrigante:{d:'despierta la curiosidad',e:false},
    apasionado:{d:'muestra pasión y entusiasmo',e:true}, cauteloso:{d:'advierte o aconseja precaución',e:false},
    resuelto:{d:'muestra determinación y firmeza',e:false}, sonador:{d:'idealista y visionario',e:true},
    profesional:{d:'serio y centrado en el negocio',e:false}
  };

  // Procesar tonos seleccionados (puede ser array o string)
  const selectedTones = Array.isArray(tones) ? tones : (tones ? [tones] : ['opinionado']);
  const validTones = selectedTones.filter(t => toneMap[t]);
  const toneDescriptions = validTones.map(t => toneMap[t].d).join('; además ');
  const useEmojis = validTones.some(t => toneMap[t].e);
  const toneInstruction = toneDescriptions || 'directo y profesional';
  const emojiRule = useEmojis
    ? 'Usa algunos emojis con moderación, acordes al tono (1-3 en todo el post).'
    : 'NO uses emojis, mantén un tono sobrio y profesional.';

  const lang = (req.body.lang === 'en') ? 'en' : 'es';
  const langInstruction = lang === 'en'
    ? 'Write the post in ENGLISH (professional LinkedIn English).'
    : 'Escribe el post en ESPAÑOL.';

  // Fuente del contenido: tema descubierto, o enlace/texto propio del usuario
  const customSource = req.body.customSource; // { url, text } o { idea, answers } opcional
  const isIdea = !!(customSource && customSource.idea && String(customSource.idea).trim());
  let sourceBlock;
  if (isIdea) {
    const qa = (Array.isArray(customSource.answers) ? customSource.answers : [])
      .filter(x => x && x.q && x.a && String(x.a).trim())
      .slice(0, 5);
    sourceBlock = `MODO IDEA PROPIA (no hay noticia de partida): el post nace de una idea o reflexión del autor.
Idea del autor: ${String(customSource.idea).trim().slice(0, 2000)}
${qa.length ? 'Lo que el autor ha contado al responder unas preguntas:\n' + qa.map(x => `- ${String(x.q).slice(0, 300)}\n  → ${String(x.a).trim().slice(0, 1500)}`).join('\n') : ''}
REGLAS DE ESTE MODO: construye el post a partir de lo que el autor ha contado, en primera persona y con naturalidad. NO inventes anécdotas, cifras, clientes, empresas ni experiencias que el autor no haya dado. Si hace falta un dato que no tienes, plantéalo como reflexión o pregunta, nunca como hecho. Los "datos concretos" del estilo de abajo solo si el autor los ha aportado.`;
  } else if (customSource && (customSource.url || customSource.text)) {
    sourceBlock = `El usuario aporta esta fuente para comentar:
${customSource.url ? 'URL: ' + customSource.url : ''}
${customSource.text ? 'Texto/contexto: ' + customSource.text : ''}
Basa el post en esta fuente. Si hay datos o cifras concretas, ÚSALOS.`;
  } else {
    if (!topic) return res.status(400).json({ error: 'Falta el tema o la idea' });
    sourceBlock = `Tema: ${topic.title}
Por qué importa: ${topic.why}
Ángulo: ${topic.angle}`;
  }

  // Tu voz: posts reales del autor guardados como referencia de estilo
  let voiceBlock = '';
  try {
    const vs = await sbGet('voice_samples', '?select=text&order=created_at.desc&limit=5');
    if (vs && vs.length) {
      voiceBlock = `EJEMPLOS DE ESTILO DEL AUTOR (posts reales suyos). Imita su voz: ritmo, longitud de frases, vocabulario, forma de abrir y de cerrar, uso de emojis y de hashtags. Su voz manda sobre el estilo genérico que se describe más abajo, salvo en la longitud pedida y en la regla de independencia. NO copies su contenido, sus datos ni sus frases: son solo referencia de estilo.
${vs.map((v, i) => `--- Ejemplo ${i + 1} ---\n${String(v.text).slice(0, 1800)}`).join('\n')}
--- Fin de los ejemplos ---`;
    }
  } catch (e) { console.error('voice samples load error:', e.message); }

  try {
    const messages = [{
      role: 'user',
      content: `Perfil del autor: ${profile}

${voiceBlock}

${sourceBlock}

Tono (combina estos matices): ${toneInstruction}
Idioma: ${langInstruction}
Longitud objetivo: ${lengthMap[length] || lengthMap.l500}

PRINCIPIO RECTOR (por encima de todo lo demás): el post debe ser ÚTIL, no lucirse. No resumas la noticia: da una OPINIÓN CLARA y aporta CLARIDAD sobre lo que esa tendencia significa para el sector. El lector tiene que terminar sabiendo algo que no sabía o viendo el tema de una forma nueva. Si el borrador se limita a contar lo que pasó, ha fallado. Toma una postura, mójate con criterio propio, explica el "y esto qué implica".

ESTILO OBLIGATORIO (imita EXACTAMENTE este patrón, basado en posts de referencia del sector):

1. PRIMERA LÍNEA (el gancho): arranca con un dato, cifra, ejemplo real o una tesis con giro. Nunca con preámbulos ("Hoy quiero hablar de", "Es interesante ver"). Recursos válidos: una paradoja ("creció 13% pero sus acciones cayeron 6%"), un giro ("se ha contado como X, pero su interés real va más allá"), o una afirmación fuerte y concreta.

2. CUERPO (2-3 párrafos cortos, una idea por párrafo, separados por línea en blanco):
   - Ancla con DATOS CONCRETOS y NOMBRES REALES: cifras, porcentajes, montos, fechas, nombres de empresas y plataformas. Si la fuente los da, úsalos. Nada de vaguedades.
   - Aporta la LECTURA ESTRATÉGICA DE FONDO, no describas la noticia. El valor está en el "qué significa esto para el sector", el dilema o la tensión que revela (ej: "el reto será no destruirlo al buscar sinergias").
   - Escribe desde la óptica de un experto en distribución, partnerships, OTT/FAST y estrategia de contenido.

3. CIERRE (elige UNO, varía entre posts, no uses siempre el mismo):
   - Una PREGUNTA abierta de criterio profesional que invite al debate, o
   - Un AFORISMO memorable que condense la tesis ("en un mercado saturado de opciones idénticas, la fuerza no está en el contenedor sino en lo que guarda dentro"), o
   - Un GANCHO que abra a más reflexión.

4. FRASES de longitud media, muy legibles en móvil. Ritmo directo. CERO relleno motivacional, cero frases huecas, cero corporativismo.

5. ${emojiRule}

6. Termina con 4-6 hashtags relevantes y específicos (mezcla sector + nombres propios del tema), en una línea aparte. Si el tono es muy sobrio, pueden ser menos.

IMPORTANTE sobre la voz: escribes como analista INDEPENDIENTE del sector. NO hables en nombre de ninguna empresa concreta ni des a entender que representas a una compañía. Comenta la actualidad con criterio propio de experto, como un observador de la industria. NUNCA menciones la empresa en la que trabaja el autor (en particular, nunca escribas "Paramount") ni frases del tipo "en mi empresa", "nosotros en...", "hemos lanzado". La experiencia se cuenta en primera persona como trayectoria profesional ("en los acuerdos de distribución que he negociado..."), nunca como portavoz de una compañía.

${customSource ? '' : 'Si el tema afecta a España o Portugal, dale especial relevancia a ese ángulo local.'}
No incluyas enlaces (URLs) dentro del post.

⚠️ LONGITUD (regla prioritaria, respétala por encima de todo): ${lengthMap[length] || lengthMap.l500} Cuenta los caracteres del post (sin contar hashtags) y ajústate a ese límite. Si te pasas, recorta hasta cumplirlo. Los hashtags van aparte y no cuentan para el límite.

Solo el texto del post, listo para copiar.`
    }];

    // max_tokens proporcional a la longitud pedida (evita que se alargue de más)
    const tokensByLength = { l500: 450, l800: 700, l1000: 900, l1200: 1050, l1400: 1200, l1600: 1350 };
    const maxTok = tokensByLength[length] || 900;
    // Si hay URL, necesita más tokens porque además lee/procesa la web
    const finalMaxTok = (customSource && customSource.url) ? maxTok + 400 : maxTok;

    const body = {
      model: CLAUDE_MODEL,
      max_tokens: finalMaxTok,
      thinking: CLAUDE_THINKING,
      system: `Eres el ghostwriter de Borja Pérez Herraiz, experto independiente en el sector audiovisual con +15 años en distribución multiplataforma, OTT, FAST, SVOD y partnerships. Escribes posts de LinkedIn al estilo de un analista senior de la industria: arranque con dato o giro, cuerpo con cifras y nombres reales, lectura estratégica de fondo, y cierre que eleva (pregunta, aforismo o gancho). Directo, con criterio propio, cero relleno motivacional. Escribes como observador independiente del sector, nunca en nombre de una empresa concreta. RESPETA SIEMPRE el límite de longitud que se te indica.`,
      messages
    };
    if (customSource && customSource.url) {
      body.tools = [{ type: 'web_search_20250305', name: 'web_search', max_uses: 3 }];
      body.messages[0].content = `Lee el contenido de esta URL: ${customSource.url}\n\n` + body.messages[0].content;
    }

    const response = await axios.post('https://api.anthropic.com/v1/messages', body, {
      headers: {
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json'
      },
      timeout: customSource && customSource.url ? 45000 : 30000
    });

    let text = response.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
    if (!text.trim()) {
      console.error('Generate: respuesta sin texto. stop_reason=', response.data.stop_reason, 'usage=', JSON.stringify(response.data.usage || {}));
      return res.status(502).json({ error: 'La IA no devolvió texto', detail: 'Respuesta vacía (' + (response.data.stop_reason || 'sin motivo') + '). Vuelve a intentarlo.' });
    }
    // El enlace de la noticia YA NO se mete dentro del texto (un enlace en el cuerpo reduce
    // mucho el alcance). Se devuelve aparte para ofrecerlo como primer comentario al publicar.
    let articleUrl = '';
    if (customSource && customSource.url) articleUrl = customSource.url;
    else if (topic && topic.url) articleUrl = topic.url;
    res.json({ text, articleUrl });
  } catch (err) {
    console.error('Generate error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Generation failed', detail: err.response?.data?.error?.message || err.message });
  }
});

// ─── UTILIDADES PARA LLAMADAS CORTAS A CLAUDE ─────────────────────────────────
async function askClaude(prompt, maxTokens = 700, timeout = 25000) {
  const r = await axios.post('https://api.anthropic.com/v1/messages', {
    model: CLAUDE_MODEL,
    max_tokens: maxTokens,
    thinking: CLAUDE_THINKING,
    system: 'Ayudas a Borja Pérez Herraiz, experto independiente del sector audiovisual (distribución, OTT, FAST, SVOD, partnerships), a escribir en LinkedIn. Nunca escribes en nombre de ninguna empresa ni mencionas la empresa en la que trabaja (en particular, nunca "Paramount"). Respondes SOLO con el JSON pedido.',
    messages: [{ role: 'user', content: prompt }]
  }, {
    headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
    timeout
  });
  return r.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
}
// Extrae un array JSON de textos de la respuesta del modelo
function extractStringArray(text) {
  const clean = String(text || '').replace(/```json/gi, '').replace(/```/g, '').trim();
  const tryParse = (t) => { try { const p = JSON.parse(t); return Array.isArray(p) ? p.filter(x => typeof x === 'string' && x.trim()).map(x => x.trim()) : null; } catch (e) { return null; } };
  let out = tryParse(clean);
  if (!out) { const a = clean.indexOf('['), b = clean.lastIndexOf(']'); if (a > -1 && b > a) out = tryParse(clean.slice(a, b + 1)); }
  return out || [];
}

// Generador de ganchos: 5 primeras líneas alternativas para un borrador
app.post('/api/hooks', async (req, res) => {
  const { text, lang } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'Falta el borrador' });
  const en = lang === 'en';
  const prompt = `Este es el borrador de un post de LinkedIn (entre <<< y >>>):
<<<
${String(text).slice(0, 4000)}
>>>
Propón 5 PRIMERAS LÍNEAS (ganchos) alternativas para este post${en ? ', en inglés' : ', en español'}. Cada una con una técnica distinta: 1) un dato o cifra, 2) una paradoja, 3) una tesis a contracorriente, 4) una pregunta incisiva, 5) una escena o ejemplo concreto.
Reglas: máximo 150 caracteres cada una; que se entiendan sin leer el resto; basadas SOLO en lo que dice el borrador (no inventes datos ni cifras que no estén); nada de preámbulos tipo "Hoy quiero hablar de"; sin hashtags ni emojis.
Devuelve SOLO un array JSON de 5 textos.`;
  try {
    const hooks = extractStringArray(await askClaude(prompt, 700)).slice(0, 5);
    if (!hooks.length) return res.status(502).json({ error: 'No se pudieron generar ganchos' });
    res.json({ hooks });
  } catch (e) {
    console.error('hooks error:', e.response?.data || e.message);
    res.status(500).json({ error: 'No se pudieron generar ganchos' });
  }
});

// Modo "Idea propia": 3 preguntas cortas para sacar material del autor antes de redactar
app.post('/api/idea-questions', async (req, res) => {
  const { idea } = req.body;
  if (!idea || !String(idea).trim()) return res.status(400).json({ error: 'Falta la idea' });
  const prompt = `Borja quiere escribir un post de LinkedIn a partir de esta idea suya (entre <<< y >>>):
<<<
${String(idea).slice(0, 2000)}
>>>
Hazle 3 preguntas cortas (máximo 120 caracteres cada una), en español y tuteándole, para sacar material propio que haga el post único:
1) una experiencia o ejemplo concreto que haya vivido relacionado con la idea,
2) un dato, caso o situación del mercado que conozca y la respalde,
3) su postura clara o lo que cree que el sector está haciendo mal o bien.
No le preguntes por su empresa ni por información confidencial.
Devuelve SOLO un array JSON de 3 textos.`;
  try {
    const questions = extractStringArray(await askClaude(prompt, 400)).slice(0, 3);
    if (!questions.length) return res.status(502).json({ error: 'No se pudieron generar preguntas' });
    res.json({ questions });
  } catch (e) {
    console.error('idea-questions error:', e.response?.data || e.message);
    res.status(500).json({ error: 'No se pudieron generar preguntas' });
  }
});

// Tu voz: posts propios que sirven de referencia de estilo (máx. 10 guardados; se usan los 5 últimos)
app.get('/api/voice-samples', async (req, res) => {
  try { res.json(await sbGet('voice_samples', '?select=*&order=created_at.desc') || []); }
  catch (e) { res.json([]); }
});
app.post('/api/voice-samples', async (req, res) => {
  const text = String(req.body?.text || '').trim();
  if (text.length < 80) return res.status(400).json({ error: 'Pega un post completo (al menos 80 caracteres).' });
  try {
    const existing = await sbGet('voice_samples', '?select=id') || [];
    if (existing.length >= 10) return res.status(400).json({ error: 'Ya tienes 10 posts guardados. Borra alguno antes de añadir otro.' });
    const row = await sbUpsert('voice_samples', { text: text.slice(0, 5000) });
    res.json(row[0] || { ok: true });
  } catch (e) { res.status(500).json({ error: 'No se pudo guardar' }); }
});
app.delete('/api/voice-samples/:id', async (req, res) => {
  try { await sbDelete('voice_samples', `?id=eq.${Number(req.params.id)}`); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: 'No se pudo borrar' }); }
});

// ─── TIPS ENGINE ─────────────────────────────────────────────────────────────

app.get('/api/tips', requireAuth, (req, res) => {
  const publishedPosts = store.posts.filter(p => p.status === 'published');
  const metricsAll = store.metrics;

  // Analyze patterns
  const avgEngagement = metricsAll.length
    ? metricsAll.reduce((s, m) => s + (m.engagementRate || 0), 0) / metricsAll.length
    : 0;

  const tips = [
    {
      icon: '⏰',
      title: 'Mejor momento para publicar',
      body: 'Para tu audiencia en el sector audiovisual: martes y jueves entre 8:00-9:30h (hora española). El miércoles a las 12:00h también funciona bien. Evita lunes temprano y viernes tarde.',
      priority: 'high'
    },
    {
      icon: '📏',
      title: publishedPosts.length > 2 ? `Posts de longitud media generan más engagement en tu caso` : 'Posts de 800-1200 caracteres funcionan mejor en tu sector',
      body: 'El "ver más" de LinkedIn aparece tras los primeros 210 caracteres. Pon la tesis o el gancho antes de ese corte para aumentar los clicks.',
      priority: 'high'
    },
    {
      icon: '🎯',
      title: 'Tu diferencial: tu experiencia, no tu empresa',
      body: 'Los posts que parten de vivencia propia ("Después de 15 años negociando acuerdos de distribución...", "En las negociaciones de carriage que he visto...") generan mucho más debate que la opinión genérica. Habla siempre como experto independiente: nunca en nombre de ninguna compañía ni insinuando que la representas.',
      priority: 'high'
    },
    {
      icon: '💬',
      title: 'Pregunta final = más comentarios',
      body: 'Posts sin pregunta final tienen un 60% menos de comentarios. La pregunta debe requerir criterio: "¿Veis en vuestros mercados la misma presión sobre los acuerdos de afiliados?"',
      priority: 'medium'
    },
    {
      icon: '🏷️',
      title: 'Hashtags de nicho > hashtags masivos',
      body: '#Streaming tiene millones de posts. Combina con #FAST #CTV #SVOD #ContentDistribution #PayTV. El algoritmo de LinkedIn penaliza más de 5 hashtags por post.',
      priority: 'medium'
    },
    {
      icon: '🔁',
      title: 'Consistencia > viralidad',
      body: `Llevas ${publishedPosts.length} posts publicados. El algoritmo de LinkedIn premia la consistencia: 2-3 posts semanales durante 8 semanas supera a un post viral ocasional.`,
      priority: 'low'
    }
  ];

  res.json({ tips, stats: { totalPosts: publishedPosts.length, avgEngagement: (avgEngagement * 100).toFixed(1) } });
});

// ─── BEST TIME ANALYSIS ───────────────────────────────────────────────────────

app.get('/api/best-times', requireAuth, (req, res) => {
  // Without full analytics access, return evidence-based recommendations
  // for the audiovisual sector in Spain
  res.json({
    bestDays: [
      { day: 'Martes', score: 95, slots: ['8:00-9:30', '12:00-13:00'] },
      { day: 'Jueves', score: 90, slots: ['8:00-9:30', '12:00-13:00'] },
      { day: 'Miércoles', score: 80, slots: ['12:00-13:00'] },
      { day: 'Lunes', score: 60, slots: ['9:00-10:00'] }
    ],
    avoid: ['Viernes tarde', 'Sábado', 'Domingo'],
    timezone: 'Europe/Madrid',
    notes: 'Basado en análisis del sector audiovisual B2B en LinkedIn España'
  });
});

// ─── SEARCH TOPICS (proxy) ────────────────────────────────────────────────────

// Guarda la búsqueda en el historial y actualiza el límite de 24h
async function persistSearch(sector, topics, searchedAt) {
  try {
    // Solo guardamos en historial y activamos el límite de 24h si hubo resultados reales
    if (topics && topics.length) {
      await sbUpsert('searches', { sector, sector_name: sector, topics, searched_at: searchedAt });
      await sbUpsert('rate_limit', { sector, last_search: searchedAt });
    }
  } catch(e) { console.error('persistSearch error:', e.response?.data || e.message); }
}

// Endpoint: historial de búsquedas (últimas 20)
app.get('/api/search-history', async (req, res) => {
  try {
    const rows = await sbGet('searches', '?select=*&order=searched_at.desc&limit=20');
    res.json(rows || []);
  } catch(e) {
    res.json([]);
  }
});

// ─── HISTORIAL DE BORRADORES ──────────────────────────────────────────────────

// Guarda un borrador generado (se llama automáticamente tras cada generación exitosa)
app.post('/api/draft-history', async (req, res) => {
  const { draftText, charCount, tones, topic, source } = req.body;
  if (!draftText) return res.status(400).json({ error: 'Falta el texto del borrador' });
  try {
    const row = await sbUpsert('draft_history', {
      draft_text: draftText,
      char_count: charCount || draftText.length,
      tones: tones || [],
      topic: topic || null,
      source: source || 'topic'
    });
    res.json(row[0] || { ok: true });
  } catch (e) {
    console.error('draft-history save error:', e.response?.data || e.message);
    res.status(500).json({ error: 'No se pudo guardar el borrador' });
  }
});

// Lista los últimos 50 borradores generados (más reciente primero)
app.get('/api/draft-history', async (req, res) => {
  try {
    const rows = await sbGet('draft_history', '?select=*&order=created_at.desc&limit=50');
    res.json(rows || []);
  } catch (e) {
    console.error('draft-history list error:', e.response?.data || e.message);
    res.json([]);
  }
});

// Borra una entrada del historial de borradores
app.delete('/api/draft-history/:id', async (req, res) => {
  try {
    await sbDelete('draft_history', `?id=eq.${req.params.id}`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'No se pudo borrar' });
  }
});

// ─── FUENTES (gestión) ────────────────────────────────────────────────────────
app.get('/api/sources', async (req, res) => {
  try {
    const rows = await sbGet('sources', '?select=*&order=created_at.asc');
    res.json(rows || []);
  } catch(e) { res.json([]); }
});

app.post('/api/sources', async (req, res) => {
  const { name, url, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Falta el nombre' });
  try {
    const row = await sbUpsert('sources', { name, url: url || null, description: description || null, active: true, category: 'propias' });
    res.json(row[0] || { ok: true });
  } catch(e) { res.status(500).json({ error: 'No se pudo añadir' }); }
});

app.patch('/api/sources/:id', async (req, res) => {
  const { active, sectors, rss_url } = req.body;
  const patch = {};
  if (active !== undefined) patch.active = active;
  if (sectors !== undefined) patch.sectors = Array.isArray(sectors) && sectors.length ? sectors : null;
  if (rss_url !== undefined) {
    // RSS editado a mano: se guarda y queda pendiente de comprobar
    const u = String(rss_url || '').trim();
    patch.rss_url = u ? (/^https?:\/\//i.test(u) ? u : 'https://' + u) : null;
    patch.rss_status = null; patch.rss_items = null; patch.rss_checked_at = null;
  }
  try {
    await axios.patch(`${SB_URL}/rest/v1/sources?id=eq.${req.params.id}`, patch, { headers: sbHeaders });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'No se pudo actualizar' }); }
});

app.delete('/api/sources/:id', async (req, res) => {
  try {
    await sbDelete('sources', `?id=eq.${req.params.id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'No se pudo borrar' }); }
});

// Marcas de referencia por categoría, para reforzar la búsqueda con nombres
// concretos del sector (el buscador rinde mejor con nombres propios que con términos genéricos).
const SECTOR_BRANDS = {
  streaming: ['Netflix', 'Disney+', 'Max', 'Prime Video', 'Apple TV+', 'Movistar Plus+', 'DAZN', 'SkyShowtime'],
  fast: ['Pluto TV', 'Tubi', 'Roku Channel', 'Samsung TV Plus', 'LG Channels', 'Rakuten TV', 'LoveTV Channels'],
  operadores: ['Movistar', 'Orange TV', 'Vodafone TV', 'Telefónica', 'DIGI', 'MásMóvil', 'Yoigo', 'Jazztel', 'MEO', 'NOS'],
  contenido: ['Netflix', 'HBO', 'Banijay', 'Mediaset', 'Atresmedia', 'RTVE'],
  adtech: ['The Trade Desk', 'LG Ads', 'VIZIO', 'Samsung Ads', 'Amazon DSP', 'FreeWheel'],
  partnerships: ['Netflix', 'Warner Bros Discovery', 'Comcast', 'Skydance', 'Banijay', 'NBCUniversal']
};
const DEFAULT_BRANDS = ['Netflix', 'Disney+', 'Max', 'Prime Video', 'SkyShowtime', 'Pluto TV'];
const SECTOR_LABELS = {
  streaming: 'Streaming & SVOD', fast: 'FAST & Free TV', operadores: 'Operadores y Pay TV',
  contenido: 'Contenido (producción y distribución)', adtech: 'Ad Tech & CTV', partnerships: 'Partnerships, acuerdos y M&A'
};

// ─── RSS: lectura de los feeds de las fuentes ────────────────────────────────
// Los RSS dan la fecha EXACTA de cada noticia, son gratis e instantáneos. Así la IA
// ya no tiene que "adivinar" fechas buscando en la web: solo elige y propone ángulos.
const RSS_UA = 'Mozilla/5.0 (compatible; StreamVoice RSS reader)';
const RSS_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // ventana de frescura: 7 días

// Descarga una URL y la decodifica respetando su codificación (UTF-8, ISO-8859-1...)
async function fetchDecoded(url, timeoutMs = 6000) {
  const r = await axios.get(url, {
    timeout: timeoutMs,
    responseType: 'arraybuffer',
    maxContentLength: 5 * 1024 * 1024,
    maxRedirects: 5,
    headers: {
      'User-Agent': RSS_UA,
      'Accept': 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, text/html;q=0.8, */*;q=0.5'
    }
  });
  const buf = Buffer.from(r.data);
  const head = buf.subarray(0, 300).toString('latin1');
  const ctype = String(r.headers['content-type'] || '');
  const enc = ((head.match(/encoding=["']([\w-]+)["']/i) || [])[1] ||
               (ctype.match(/charset=([\w-]+)/i) || [])[1] || 'utf-8').toLowerCase();
  let text;
  try { text = new TextDecoder(enc).decode(buf); } catch (e) { text = buf.toString('utf8'); }
  return { text, finalUrl: r.request?.res?.responseUrl || url };
}

const HTML_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', hellip: '…', mdash: '—', ndash: '–',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', laquo: '«', raquo: '»', euro: '€', iexcl: '¡', iquest: '¿',
  aacute: 'á', eacute: 'é', iacute: 'í', oacute: 'ó', uacute: 'ú', ntilde: 'ñ', uuml: 'ü', ccedil: 'ç',
  Aacute: 'Á', Eacute: 'É', Iacute: 'Í', Oacute: 'Ó', Uacute: 'Ú', Ntilde: 'Ñ', Uuml: 'Ü', Ccedil: 'Ç',
  atilde: 'ã', otilde: 'õ', acirc: 'â', ecirc: 'ê', ocirc: 'ô', agrave: 'à', egrave: 'è', ograve: 'ò',
  Atilde: 'Ã', Otilde: 'Õ', Acirc: 'Â', Ecirc: 'Ê', Ocirc: 'Ô', Agrave: 'À'
};
function decodeEntities(s) {
  return String(s || '').replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try { return String.fromCodePoint(code); } catch (err) { return m; }
    }
    return Object.prototype.hasOwnProperty.call(HTML_ENTITIES, e) ? HTML_ENTITIES[e] : m;
  });
}
// Convierte el contenido de una etiqueta (con CDATA, HTML o entidades) en texto limpio
function cleanText(raw) {
  let t = String(raw || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  t = decodeEntities(t);                 // &lt;p&gt; → <p>
  t = t.replace(/<[^>]*>/g, ' ');        // quitar etiquetas HTML
  t = decodeEntities(t);                 // entidades que quedaran dentro del HTML
  return t.replace(/\s+/g, ' ').trim();
}
function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
// Contenido de la primera etiqueta <name>…</name> (admite nombres con prefijo, ej. dc:date)
function getTag(block, name) {
  const m = block.match(new RegExp('<' + escapeRe(name) + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + escapeRe(name) + '>', 'i'));
  return m ? m[1] : '';
}
// Fechas de feeds: RFC 822 ("Fri, 02 Oct 2026 10:49:33 +0000") o ISO. Algunos medios
// españoles/portugueses usan nombres de día/mes en su idioma: los pasamos a inglés.
const MONTH_WORDS = {
  ene: 'Jan', jan: 'Jan', feb: 'Feb', fev: 'Feb', mar: 'Mar', abr: 'Apr', apr: 'Apr', may: 'May', mai: 'May',
  jun: 'Jun', jul: 'Jul', ago: 'Aug', aug: 'Aug', sep: 'Sep', set: 'Sep', oct: 'Oct', out: 'Oct',
  nov: 'Nov', dic: 'Dec', dez: 'Dec', dec: 'Dec'
};
function parseFeedDate(raw) {
  if (!raw) return null;
  let d = new Date(raw);
  if (isNaN(d.getTime())) {
    // Formato "Día, 05 Mes 2026 12:13:29 +0200" con nombres en otro idioma:
    // quitamos el día de la semana y traducimos el mes.
    const m = String(raw).trim().match(/^(?:[^\d,]+,?\s*)?(\d{1,2})\s+([^\s\d.]+)\.?\s+(\d{4})(.*)$/);
    if (m) {
      const mon = MONTH_WORDS[m[2].toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').slice(0, 3)];
      if (mon) d = new Date(`${m[1]} ${mon} ${m[3]}${m[4]}`);
    }
  }
  return d && !isNaN(d.getTime()) ? d.toISOString() : null;
}
// Interpreta un feed RSS 2.0 / RSS 1.0 (RDF) / Atom y devuelve sus noticias
function parseFeed(xml) {
  const items = [];
  const blocks = [
    ...(xml.match(/<item(?:\s[^>]*)?>[\s\S]*?<\/item>/gi) || []),
    ...(xml.match(/<entry(?:\s[^>]*)?>[\s\S]*?<\/entry>/gi) || [])
  ];
  for (const b of blocks) {
    const title = cleanText(getTag(b, 'title'));
    // Enlace: RSS (<link>url</link>), Atom (<link rel="alternate" href="..."/>), Feedburner, guid
    let link = cleanText(getTag(b, 'feedburner:origLink')) || cleanText(getTag(b, 'link'));
    if (!link) {
      const tags = b.match(/<link\b[^>]*>/gi) || [];
      const alt = tags.find(t => /rel=["']alternate["']/i.test(t)) || tags.find(t => !/rel=/i.test(t)) || tags[0];
      const href = alt && (alt.match(/href=["']([^"']+)["']/i) || [])[1];
      if (href) link = decodeEntities(href);
    }
    if (!link) {
      const guid = cleanText(getTag(b, 'guid'));
      if (/^https?:\/\//i.test(guid)) link = guid;
    }
    const dateRaw = cleanText(getTag(b, 'pubDate')) || cleanText(getTag(b, 'dc:date')) ||
                    cleanText(getTag(b, 'published')) || cleanText(getTag(b, 'updated')) ||
                    cleanText(getTag(b, 'a10:updated'));
    const date = parseFeedDate(dateRaw);
    const summary = cleanText(getTag(b, 'description') || getTag(b, 'summary') || getTag(b, 'content:encoded') || getTag(b, 'content'));
    if (title && link) items.push({ title, link, date, summary });
  }
  return items;
}
function looksLikeFeed(text) {
  return /<(rss|feed|rdf:RDF)\b/i.test(String(text || '').slice(0, 3000));
}
function siteBaseUrl(url) {
  let u = String(url || '').trim();
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}
// Busca el RSS de una web: primero los <link rel="alternate"> de la portada,
// luego rutas habituales (/feed/, /rss...). Devuelve { url, count } o null.
async function discoverFeed(siteUrl) {
  const base = siteBaseUrl(siteUrl);
  let origin;
  try { origin = new URL(base).origin; } catch (e) { return null; }
  const candidates = [];
  try {
    const { text } = await fetchDecoded(base, 6000);
    if (looksLikeFeed(text) && parseFeed(text).length) return { url: base, count: parseFeed(text).length };
    const linkTags = text.match(/<link\b[^>]*>/gi) || [];
    for (const t of linkTags) {
      if (!/rel=["']?alternate/i.test(t) || !/(rss|atom)\+xml/i.test(t)) continue;
      const href = (t.match(/href=["']([^"']+)["']/i) || [])[1];
      if (!href || /comments?/i.test(href)) continue;
      try { candidates.push(new URL(decodeEntities(href), base).href); } catch (e) {}
    }
  } catch (e) { /* portada inaccesible: probamos rutas habituales igualmente */ }
  const basePath = base.replace(/\/+$/, '');
  const paths = ['/feed/', '/rss', '/rss.xml', '/feed.xml', '/feeds/all', '/index.xml', '/rss/'];
  if (basePath !== origin) paths.forEach(p => candidates.push(basePath + p)); // ej. /invertia/feed/
  paths.forEach(p => candidates.push(origin + p));
  const unique = [...new Set(candidates)].slice(0, 12);
  const results = await Promise.allSettled(unique.map(async (u) => {
    const { text } = await fetchDecoded(u, 6000);
    if (!looksLikeFeed(text)) throw new Error('no es un feed');
    const n = parseFeed(text).length;
    if (!n) throw new Error('feed vacío');
    return { url: u, count: n };
  }));
  // Respetamos el orden de prioridad: el primero de la lista que funcione
  for (const r of results) if (r.status === 'fulfilled') return r.value;
  return null;
}
async function updateSourceRow(id, patch) {
  await axios.patch(`${SB_URL}/rest/v1/sources?id=eq.${id}`, patch, { headers: sbHeaders });
}
function isProfileUrl(url) { return /linkedin\.com/i.test(String(url || '')); }

// Endpoint: detectar/comprobar los RSS de las fuentes.
// Body opcional: { ids: [..] } para comprobar solo algunas. Si una fuente ya tiene
// rss_url se comprueba esa; si no, se intenta descubrir.
app.post('/api/sources/discover-rss', async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(Number).filter(Boolean) : null;
    let srcs = await sbGet('sources', '?select=id,name,url,rss_url,active');
    srcs = (srcs || []).filter(s => s.url && !isProfileUrl(s.url) && (ids ? ids.includes(s.id) : s.active));
    const checkedAt = new Date().toISOString();
    const results = await Promise.all(srcs.map(async (s) => {
      let found = null;
      if (s.rss_url) {
        try {
          const { text } = await fetchDecoded(s.rss_url, 7000);
          const n = looksLikeFeed(text) ? parseFeed(text).length : 0;
          if (n) found = { url: s.rss_url, count: n };
        } catch (e) { /* lo marcamos como error abajo */ }
        if (!found) {
          await updateSourceRow(s.id, { rss_status: 'error', rss_items: 0, rss_checked_at: checkedAt });
          return { id: s.id, name: s.name, status: 'error', rss_url: s.rss_url };
        }
      } else {
        try { found = await discoverFeed(s.url); } catch (e) { found = null; }
        if (!found) {
          await updateSourceRow(s.id, { rss_status: 'sin_rss', rss_items: 0, rss_checked_at: checkedAt });
          return { id: s.id, name: s.name, status: 'sin_rss' };
        }
      }
      await updateSourceRow(s.id, { rss_url: found.url, rss_status: 'ok', rss_items: found.count, rss_checked_at: checkedAt });
      return { id: s.id, name: s.name, status: 'ok', rss_url: found.url, items: found.count };
    }));
    res.json({ ok: true, checkedAt, results });
  } catch (e) {
    console.error('discover-rss error:', e.response?.data || e.message);
    res.status(500).json({ error: 'No se pudieron comprobar los RSS' });
  }
});

// Lee los RSS de varias fuentes en paralelo y devuelve las noticias de los últimos 7 días
async function readRssPool(rssSources) {
  const nowMs = Date.now();
  const failed = [];
  const perFeed = await Promise.all(rssSources.map(async (s) => {
    try {
      const { text } = await fetchDecoded(s.rss_url, 7000);
      const items = parseFeed(text)
        .filter(it => it.date && (nowMs - new Date(it.date).getTime()) <= RSS_MAX_AGE_MS && new Date(it.date).getTime() <= nowMs + 3600000)
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .slice(0, 15)
        .map(it => ({ ...it, source: s.name }));
      return items;
    } catch (e) {
      failed.push(s);
      return [];
    }
  }));
  // Quitar duplicados exactos de enlace y quedarnos con las 180 más recientes (control de coste)
  const seenLinks = new Set();
  const pool = perFeed.flat()
    .filter(it => { const k = it.link.split('#')[0]; if (seenLinks.has(k)) return false; seenLinks.add(k); return true; })
    .sort((a, b) => new Date(b.date) - new Date(a.date))
    .slice(0, 180)
    .map((it, i) => ({ ...it, id: 'r' + (i + 1) }));
  return { pool, failed };
}

function humanDateEs(iso) {
  try {
    return new Intl.DateTimeFormat('es-ES', { timeZone: 'Europe/Madrid', day: 'numeric', month: 'short' }).format(new Date(iso));
  } catch (e) { return String(iso || '').slice(0, 10); }
}

app.post('/api/search-topics', async (req, res) => {
  const startedAt = Date.now();
  const { sector, sectorId } = req.body;

  // ── Límite: una búsqueda por sector y día natural (se resetea a las 00:00 hora española) ──
  try {
    const rows = await sbGet('rate_limit', `?sector=eq.${encodeURIComponent(sector)}&select=*`);
    if (rows && rows[0]) {
      // Fecha (año-mes-día) en hora española de la última búsqueda y de ahora
      const spainDay = (date) => new Intl.DateTimeFormat('en-CA', {
        timeZone: 'Europe/Madrid', year: 'numeric', month: '2-digit', day: '2-digit'
      }).format(date); // formato YYYY-MM-DD
      const lastDay = spainDay(new Date(rows[0].last_search));
      const todayDay = spainDay(new Date());
      if (lastDay === todayDay) {
        // Ya buscó hoy en esta categoría → bloqueado hasta medianoche
        const nowMadrid = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Madrid' }));
        const hoursLeft = Math.max(1, Math.ceil((24 - nowMadrid.getHours()) - nowMadrid.getMinutes() / 60));
        return res.status(429).json({
          error: 'rate_limited',
          detail: `Ya buscaste en esta categoría hoy. Podrás volver a buscar mañana a partir de las 00:00.`,
          lastSearch: rows[0].last_search,
          hoursLeft
        });
      }
    }
  } catch(e) { console.error('Rate limit check error:', e.response?.data || e.message); }

  // Cargar fuentes activas desde Supabase, filtradas por categoría cuando aplica.
  // Una fuente sin "sectors" asignado se considera válida para CUALQUIER categoría (comportamiento por defecto).
  let srcs = [];
  try {
    const filterQS = sectorId
      ? `?active=eq.true&or=(sectors.is.null,sectors.cs.{${encodeURIComponent(sectorId)}})&select=name,url,rss_url,rss_status`
      : '?active=eq.true&select=name,url,rss_url,rss_status';
    srcs = (await sbGet('sources', filterQS)) || [];
  } catch(e) { console.error('Sources load error:', e.message); }
  srcs = srcs.filter(s => s.url && !isProfileUrl(s.url)); // los perfiles de LinkedIn no tienen RSS ni sirven para site:

  // ── PASO 1: leer los RSS de las fuentes de esta categoría (fechas exactas) ──
  const rssSources = srcs.filter(s => s.rss_url && s.rss_status !== 'error');
  const { pool, failed } = rssSources.length ? await readRssPool(rssSources) : { pool: [], failed: [] };
  const failedNames = new Set(failed.map(s => s.name));

  // Fuentes que se cubren con búsqueda web (sin RSS o con el RSS caído hoy)
  const webSources = srcs.filter(s => !s.rss_url || s.rss_status === 'error' || failedNames.has(s.name));
  const webDomains = [...new Set(
    webSources.map(s => s.url.replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '').trim()).filter(Boolean)
  )];
  const DOMAIN_CHUNK_SIZE = 10;
  const siteQueryGroups = [];
  for (let i = 0; i < webDomains.length; i += DOMAIN_CHUNK_SIZE) {
    siteQueryGroups.push(webDomains.slice(i, i + DOMAIN_CHUNK_SIZE).map(d => 'site:' + d).join(' OR '));
  }

  const headers = {
    'x-api-key': process.env.ANTHROPIC_API_KEY,
    'anthropic-version': '2023-06-01',
    'Content-Type': 'application/json'
  };
  const now = new Date().toISOString();
  const brandList = (sectorId && SECTOR_BRANDS[sectorId]) || DEFAULT_BRANDS;
  const sectorLabel = (sectorId && SECTOR_LABELS[sectorId]) || sector;
  const MIN_RELEVANT = 4; // por debajo de esto, se completa con búsqueda web

  const poolBlock = pool.length
    ? `NOTICIAS DE TUS FUENTES (leídas de sus RSS; fechas exactas y verificadas, todas de los últimos 7 días):
${pool.map(it => `[${it.id}] ${it.date.slice(0, 10)} · ${it.source} · ${it.title}${it.summary ? ' — ' + it.summary.slice(0, 140) : ''}`).join('\n')}`
    : 'NOTICIAS DE TUS FUENTES: no hay noticias recientes en los RSS de esta categoría (o las fuentes no tienen RSS).';

  const webStrategy = `BÚSQUEDA WEB (solo si hace falta, según la regla de arriba):
${siteQueryGroups.length ? `- Primero en las fuentes del usuario que no tienen RSS, una búsqueda por grupo:
${siteQueryGroups.map((g, i) => `  · Búsqueda ${i + 1}: "${sector} (${g})"`).join('\n')}
` : ''}- Después, búsqueda general sobre "${sector}" combinando con nombres como ${brandList.slice(0, 4).join(', ')}.
- Para lo que encuentres en la web: URL real, fecha de publicación verificada (AAAA-MM-DD) y SOLO de los últimos 7 días. Si no puedes verificar la fecha, no lo incluyas.`;

  const userPrompt = `Categoría: ${sectorLabel}.
Marcas y actores de referencia de esta categoría: ${brandList.join(', ')}.
Fecha y hora actual de referencia: ${now}.

${poolBlock}

TAREA:
1. Elige hasta 8 noticias RELEVANTES para la categoría "${sectorLabel}" y útiles para que un experto en distribución audiovisual, OTT, FAST, Pay TV y partnerships opine en LinkedIn. Descarta lo que no tenga lectura de negocio audiovisual (rodajes, festivales, estrenos, famosos, política general, deportes...), aunque venga de una fuente del usuario.
2. Prioriza España/Portugal, pero incluye lo global muy relevante. Ordena por relevancia (la más relevante primero).
3. ANTI-DUPLICADOS: si la misma historia aparece varias veces, inclúyela UNA SOLA VEZ (la versión más completa).
4. REGLA DE BÚSQUEDA WEB: si de la lista de arriba salen ${MIN_RELEVANT} o más noticias relevantes, NO uses la búsqueda web. Solo si salen MENOS DE ${MIN_RELEVANT}, usa web_search para completar hasta 8.

${webStrategy}

FORMATO DE SALIDA: SOLO un array JSON válido (sin backticks, sin texto antes ni después). Si no hay nada relevante, devuelve [].
[{"ref":"r12 o null","title":"titular en español, máx. 13 palabras","why":"por qué importa (1 frase)","engagement":"hot|trending|normal","scope":"espana|global","tags":["t1","t2"],"angle":"ángulo de opinión (1 frase)","published":"texto legible ej. 'Hace 2 días' o '9 jun'","published_date":"AAAA-MM-DD","url":"URL real"}]
- Para noticias de la lista: pon en "ref" su identificador exacto (ej. "r12"); puedes traducir el titular al español. URL y fecha se toman de la lista.
- Para noticias de la búsqueda web: "ref": null, con URL real y "published_date" verificada.

REGLA DE FORMATO CRÍTICA: NO expliques tu razonamiento. Tu respuesta debe EMPEZAR por [ y TERMINAR por ]. Solo el array JSON.`;

  // Presupuesto de búsquedas web (solo se cobran las que realmente se usen)
  const webSearchMaxUses = Math.min(6, Math.max(3, siteQueryGroups.length + 2));
  // Tiempo restante hasta el límite de Vercel (60s), con margen para responder
  const timeLeft = Math.max(20000, 56000 - (Date.now() - startedAt));

  try {
    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: CLAUDE_MODEL,
      max_tokens: 3000,
      thinking: CLAUDE_THINKING,
      tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: webSearchMaxUses }],
      system: 'Eres un editor de contenido del sector audiovisual y streaming. Seleccionas noticias REALES y recientes para que un experto independiente opine en LinkedIn. Usas primero las noticias de las fuentes del usuario (leídas de sus RSS) y solo recurres a la búsqueda web si con ellas no hay suficiente. Nunca inventas URLs ni fechas. FORMATO OBLIGATORIO: tu respuesta final debe ser ÚNICAMENTE un array JSON válido, empezando por [ y terminando por ]. Nunca escribas tu razonamiento en la respuesta.',
      messages: [{ role: 'user', content: userPrompt }]
    }, { headers, timeout: timeLeft });

    const text = response.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
    const webSearchesUsed = (response.data.content || []).filter(b => b.type === 'server_tool_use').length;
    let topics = extractTopics(text);
    if (topics && topics.length) {
      // Las noticias que vienen del RSS toman URL, fecha y medio de la propia fuente (no del modelo)
      const poolById = new Map(pool.map(it => [it.id, it]));
      topics = topics.map(t => {
        const ref = t.ref ? poolById.get(String(t.ref).trim()) : null;
        if (ref) {
          return { ...t, url: ref.link, published_date: ref.date.slice(0, 10), published: humanDateEs(ref.date), source_name: ref.source, origin: 'rss' };
        }
        return { ...t, origin: 'web' };
      });
      // FILTRO DE FRESCURA por código: descartar noticias de más de 7 días
      const nowMs = Date.now();
      const fresh = topics.filter(t => {
        if (!t.published_date) return t.origin === 'rss'; // una noticia web sin fecha verificable no entra
        const d = new Date(t.published_date);
        if (isNaN(d.getTime())) return false;
        return (nowMs - d.getTime()) <= RSS_MAX_AGE_MS + 24 * 3600 * 1000; // +1 día de margen por husos horarios
      });
      // ANTI-DUPLICADOS por código (red de seguridad): descartar títulos muy parecidos
      const norm = s => (s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9 ]/g, '').replace(/\s+/g, ' ').trim();
      const seen = [];
      const deduped = fresh.filter(t => {
        const words = norm(t.title).split(' ').filter(w => w.length > 3);
        if (!words.length) return true;
        // Índice de Jaccard (intersección/unión) para medir similitud entre títulos
        for (const prev of seen) {
          const inter = words.filter(w => prev.includes(w)).length;
          const union = new Set([...words, ...prev]).size;
          if (union && inter / union >= 0.3) return false; // misma noticia → descartar
        }
        seen.push(words);
        return true;
      });
      const mapped = deduped.slice(0, 10).map(t => ({ ...t, source: 'web', scope: t.scope === 'global' ? 'global' : 'espana' }));
      const stats = { rssFeeds: rssSources.length, rssFailed: failed.length, rssItems: pool.length, webSearches: webSearchesUsed };
      console.log('search-topics stats:', JSON.stringify({ sector: sectorId || sector, ...stats, ms: Date.now() - startedAt }));
      if (mapped.length) {
        await persistSearch(sector, mapped, now);
        return res.json({ topics: mapped, searchedAt: now, source: 'web', stats });
      }
      // Todo lo encontrado era viejo → sin novedades frescas.
      // DIAGNÓSTICO: devolvemos también lo que la IA encontró y descartó (título + fecha detectada).
      const discarded = topics.slice(0, 10).map(t => ({ title: t.title, published: t.published, published_date: t.published_date || null }));
      console.error('all_old — descartadas:', JSON.stringify(discarded));
      return res.json({ topics: [], searchedAt: now, source: 'web', empty: true, reason: 'all_old', debugDiscarded: discarded, stats });
    }
    if (topics && topics.length === 0) {
      // La IA respondió correctamente pero no encontró nada relevante
      return res.json({ topics: [], searchedAt: now, source: 'web', empty: true, reason: 'none_relevant',
        stats: { rssFeeds: rssSources.length, rssFailed: failed.length, rssItems: pool.length, webSearches: webSearchesUsed } });
    }
    // La búsqueda respondió pero no pudimos extraer temas
    console.error('No topics parsed. Raw text (first 500):', text.slice(0, 500));
    return res.json({ topics: [], searchedAt: now, source: 'web', empty: true, reason: 'no_parse', debugRawText: text.slice(0, 800) });
  } catch (webErr) {
    const detail = webErr.response?.data?.error?.message || webErr.message;
    console.error('Search failed:', detail);
    const isTimeout = webErr.code === 'ECONNABORTED' || /timeout/i.test(detail || '');
    return res.json({ topics: [], searchedAt: now, source: 'web', empty: true, reason: isTimeout ? 'timeout' : 'error', detail });
  }
});

// Extrae el array de temas de la respuesta, de forma robusta
function extractTopics(text) {
  if (!text) return null;
  let clean = text.replace(/```json/gi, '').replace(/```/g, '').trim();
  // Solo aceptamos arrays de objetos-noticia (con 'title'), no arrays de números tipo [1]
  const isValidTopicArray = (p) => Array.isArray(p) && (p.length === 0 || (typeof p[0] === 'object' && p[0] !== null && 'title' in p[0]));
  // Intento 1: parseo directo
  try { const p = JSON.parse(clean); if (isValidTopicArray(p)) return p; } catch(e) {}
  // Intento 2: probar cada '[' como inicio y cada ']' como fin, quedarnos con un array de noticias no vacío
  for (let start = clean.indexOf('['); start !== -1; start = clean.indexOf('[', start + 1)) {
    for (let end = clean.lastIndexOf(']'); end > start; end = clean.lastIndexOf(']', end - 1)) {
      const candidate = clean.slice(start, end + 1);
      try { const p = JSON.parse(candidate); if (isValidTopicArray(p) && p.length > 0) return p; } catch(e) {}
    }
  }
  return null;
}

// ─── EXPORT (Vercel serverless) ─────────────────────────────────────────────
// En Vercel se exporta la app directamente.
// Para desarrollo local: descomenta las 2 lineas de abajo y ejecuta `node api/index.js`
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`StreamVoice en http://localhost:${PORT}`));

module.exports = app;
