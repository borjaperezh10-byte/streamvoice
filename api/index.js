require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ─── SUPABASE (almacenamiento persistente) ─────────────────────────────────────
const SB_URL = process.env.SUPABASE_URL;
const SB_KEY = process.env.SUPABASE_ANON_KEY;
const sbHeaders = {
  'apikey': SB_KEY,
  'Authorization': `Bearer ${SB_KEY}`,
  'Content-Type': 'application/json'
};
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

// ─── SEGURIDAD DE ACCESO ────────────────────────────────────────────────────
// Verifica la contraseña de acceso a la app
app.post('/api/access', (req, res) => {
  const { password } = req.body;
  if (!process.env.ACCESS_PASSWORD) {
    // Si no se ha configurado contraseña, se permite el acceso (para no bloquear)
    return res.json({ ok: true, noPasswordSet: true });
  }
  if (password === process.env.ACCESS_PASSWORD) {
    return res.json({ ok: true });
  }
  return res.status(403).json({ ok: false, error: 'Contraseña incorrecta' });
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
  const { text, scheduledAt, publishPassword } = req.body;
  if (!text) return res.status(400).json({ error: 'Missing text' });

  // Verificar contraseña de publicación (segunda barrera de seguridad)
  if (process.env.PUBLISH_PASSWORD && publishPassword !== process.env.PUBLISH_PASSWORD) {
    return res.status(403).json({ error: 'wrong_publish_password', detail: 'Contraseña de publicación incorrecta.' });
  }

  // Publish now
  try {
    const result = await publishToLinkedIn(text, req.linkedinSession);
    // Guardar en el historial de publicados
    try {
      await sbUpsert('scheduled_posts', {
        text,
        scheduled_at: new Date().toISOString(),
        status: 'published',
        published_at: new Date().toISOString(),
        linkedin_id: result.linkedinId
      });
    } catch(e) { console.error('No se pudo guardar en historial:', e.message); }
    res.json({ ok: true, status: 'published', linkedinId: result.linkedinId });
  } catch (err) {
    console.error('Publish error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to publish', detail: err.response?.data });
  }
});

// Función reutilizable para publicar en LinkedIn
async function publishToLinkedIn(text, session) {
  const authorId = session.profile?.sub;
  // Detectar si el post contiene una URL → declararla como artículo para que salga el preview
  const urlMatch = text.match(/https?:\/\/[^\s]+/);
  let shareContent;
  if (urlMatch) {
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

// ─── PROGRAMACIÓN DE POSTS ──────────────────────────────────────────────────
// Programar un post para el futuro
app.post('/api/schedule', requireAuth, async (req, res) => {
  const { text, scheduledAt, publishPassword } = req.body;
  if (!text || !scheduledAt) return res.status(400).json({ error: 'Faltan datos' });
  if (process.env.PUBLISH_PASSWORD && publishPassword !== process.env.PUBLISH_PASSWORD) {
    return res.status(403).json({ error: 'wrong_publish_password', detail: 'Contraseña de publicación incorrecta.' });
  }
  if (new Date(scheduledAt) <= new Date()) {
    return res.status(400).json({ error: 'La fecha debe ser futura' });
  }
  try {
    await sbUpsert('scheduled_posts', { text, scheduled_at: scheduledAt, status: 'pending' });
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
  const { text, scheduledAt, publishPassword } = req.body;
  if (process.env.PUBLISH_PASSWORD && publishPassword !== process.env.PUBLISH_PASSWORD) {
    return res.status(403).json({ error: 'wrong_publish_password', detail: 'Contraseña de publicación incorrecta.' });
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
        await axios.patch(`${SB_URL}/rest/v1/scheduled_posts?id=eq.${post.id}`,
          { status: 'published', published_at: new Date().toISOString(), linkedin_id: result.linkedinId },
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
    l100: 'MÁXIMO 100 caracteres. Ultra breve: una o dos frases potentes, como un titular con gancho. NO te extiendas.',
    l300: 'MÁXIMO 300 caracteres (unas 3-4 frases). Muy conciso y directo. NO te extiendas más.',
    l500: 'MÁXIMO 500 caracteres. Breve pero con algo de desarrollo. NO te extiendas más.',
    l700: 'aproximadamente 700 caracteres (ni mucho más ni mucho menos).',
    l1000: 'aproximadamente 1000 caracteres. Desarrollo completo pero sin pasarte de 1100.'
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
  const customSource = req.body.customSource; // { url, text } opcional
  let sourceBlock;
  if (customSource && (customSource.url || customSource.text)) {
    sourceBlock = `El usuario aporta esta fuente para comentar:
${customSource.url ? 'URL: ' + customSource.url : ''}
${customSource.text ? 'Texto/contexto: ' + customSource.text : ''}
Basa el post en esta fuente. Si hay datos o cifras concretas, ÚSALOS.`;
  } else {
    sourceBlock = `Tema: ${topic.title}
Por qué importa: ${topic.why}
Ángulo: ${topic.angle}`;
  }

  try {
    const messages = [{
      role: 'user',
      content: `Perfil del autor: ${profile}

${sourceBlock}

Tono (combina estos matices): ${toneInstruction}
Idioma: ${langInstruction}
Longitud objetivo: ${lengthMap[length] || lengthMap.l500}

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

IMPORTANTE sobre la voz: escribes como analista INDEPENDIENTE del sector. NO hables en nombre de ninguna empresa concreta ni des a entender que representas a una compañía. Comenta la actualidad con criterio propio de experto, como un observador de la industria.

${customSource ? '' : 'Si el tema afecta a España o Portugal, dale especial relevancia a ese ángulo local.'}

⚠️ LONGITUD (regla prioritaria, respétala por encima de todo): ${lengthMap[length] || lengthMap.l500} Cuenta los caracteres del post (sin contar hashtags) y ajústate a ese límite. Si te pasas, recorta hasta cumplirlo. Los hashtags van aparte y no cuentan para el límite.

Solo el texto del post, listo para copiar.`
    }];

    // max_tokens proporcional a la longitud pedida (evita que se alargue de más)
    const tokensByLength = { l100: 150, l300: 300, l500: 450, l700: 600, l1000: 900 };
    const maxTok = tokensByLength[length] || 600;
    // Si hay URL, necesita más tokens porque además lee/procesa la web
    const finalMaxTok = (customSource && customSource.url) ? maxTok + 400 : maxTok;

    const body = {
      model: 'claude-sonnet-4-6',
      max_tokens: finalMaxTok,
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
    // Añadir el enlace real al final del post (genera preview en LinkedIn)
    // Solo si hay URL real: del tema (source web) o del enlace propio del usuario
    let articleUrl = '';
    if (customSource && customSource.url) articleUrl = customSource.url;
    else if (topic && topic.source === 'web' && topic.url) articleUrl = topic.url;
    if (articleUrl && !text.includes(articleUrl)) {
      text = text.trimEnd() + '\n\n' + articleUrl;
    }
    res.json({ text, articleUrl });
  } catch (err) {
    console.error('Generate error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Generation failed', detail: err.response?.data?.error?.message || err.message });
  }
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
      title: 'Tu diferencial: perspectiva de Paramount',
      body: 'Posts que empiezan con "En Paramount hemos visto..." o "Después de 15 años negociando distribución..." generan 3x más engagement que los de opinión genérica. Tu perspectiva insider es tu ventaja.',
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
  const { active } = req.body;
  try {
    await axios.patch(`${SB_URL}/rest/v1/sources?id=eq.${req.params.id}`, { active }, { headers: sbHeaders });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'No se pudo actualizar' }); }
});

app.delete('/api/sources/:id', async (req, res) => {
  try {
    await sbDelete('sources', `?id=eq.${req.params.id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'No se pudo borrar' }); }
});

app.post('/api/search-topics', async (req, res) => {
  const { sector } = req.body;

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

  // Cargar fuentes activas desde Supabase
  let sourcesList = '';
  let sourceDomains = [];
  try {
    const srcs = await sbGet('sources', '?active=eq.true&select=name,url');
    if (srcs && srcs.length) {
      sourcesList = srcs.map(s => s.name + (s.url ? ' ('+s.url+')' : '')).join(', ');
      // Extraer dominios limpios para búsquedas site:
      sourceDomains = srcs
        .filter(s => s.url)
        .map(s => s.url.replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '').trim())
        .filter(Boolean);
    }
  } catch(e) { console.error('Sources load error:', e.message); }

  const headers = {
    'x-api-key': process.env.ANTHROPIC_API_KEY,
    'anthropic-version': '2023-06-01',
    'Content-Type': 'application/json'
  };
  const now = new Date().toISOString();
  const siteQueries = sourceDomains.length
    ? sourceDomains.slice(0, 8).map(d => 'site:' + d).join(' OR ')
    : '';
  const sourcesLine = sourcesList ? `Fuentes prioritarias del usuario: ${sourcesList}.` : '';
  const strategyBlock = siteQueries
    ? `ESTRATEGIA DE BÚSQUEDA (en dos fases):
FASE 1 (prioritaria): Busca PRIMERO dentro de las fuentes del usuario usando el operador site:. Por ejemplo: "${sector} (${siteQueries})" y variantes con nombres concretos (Netflix, Disney, etc.). Empieza siempre por estas fuentes de confianza.
FASE 2 (complemento): Si te queda margen, complementa con una búsqueda web general sobre "${sector}" para captar noticias de otras fuentes.`
    : `Busca en la web noticias recientes sobre "${sector}".`;
  const userPrompt = `Busca las noticias más relevantes y recientes (últimos 7 días) sobre: ${sector}.
Fecha y hora actual de referencia: ${now}.
${sourcesLine}

${strategyBlock}

INSTRUCCIONES:
- Devuelve hasta 8 noticias, ORDENADAS por relevancia (la más relevante primero).
- ANTI-DUPLICADOS: si la misma noticia aparece en varios medios, INCLÚYELA UNA SOLA VEZ. Elige la versión más completa y reciente (la que tenga más detalle, datos o cobertura). No repitas la misma historia con distintas fuentes.
- CRÍTICO: SOLO noticias publicadas en los ÚLTIMOS 7 DÍAS desde la fecha de referencia. Verifica la fecha real de publicación de cada noticia. Si una noticia tiene más de 7 días, NO la incluyas por muy relevante que sea.
- Para cada noticia, incluye su fecha real de publicación en "published_date" en formato exacto AAAA-MM-DD. Si no puedes verificar la fecha, NO incluyas la noticia.
- PRIORIZA España/Portugal, pero INCLUYE globales muy relevantes.
- Marca ámbito: "espana" (mercado ibérico) o "global" (internacional).
- URLs REALES y verificadas. No inventes.
Devuelve SOLO un array JSON válido (sin backticks, sin texto antes ni después). Si no hay nada reciente, devuelve [].
[{"title":"titular español max 13 palabras","why":"por qué importa (1 frase)","engagement":"hot|trending|normal","scope":"espana|global","tags":["t1","t2"],"angle":"ángulo de opinión (1 frase)","published":"texto legible ej 'Hace 2 días' o '9 jun'","published_date":"AAAA-MM-DD","url":"URL real"}]

REGLA DE FORMATO CRÍTICA: NO expliques tu razonamiento ni escribas análisis en texto. NO escribas frases como "Analizando los resultados" ni listas con guiones. Tu respuesta debe EMPEZAR directamente con el carácter [ y TERMINAR con ]. Solo el array JSON, nada más. Si razonas internamente, hazlo en silencio y entrega únicamente el JSON final.`;

  // Búsqueda web (temas reales y frescos de los últimos 7 días)
  try {
    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-6',
      max_tokens: 4000,
      tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 6 }],
      system: 'Eres un editor de contenido del sector audiovisual y streaming. Buscas noticias REALES y recientes con enlaces verificados. Empiezas SIEMPRE buscando dentro de las fuentes prioritarias del usuario (con site:) y luego complementas con búsqueda general. Devuelves hasta 8, ordenadas por relevancia, priorizando España/Portugal pero incluyendo globales relevantes. Nunca inventas URLs. FORMATO OBLIGATORIO: tu respuesta final debe ser ÚNICAMENTE un array JSON válido, empezando por [ y terminando por ]. NUNCA escribas tu razonamiento, análisis ni comentarios en la respuesta; todo ese trabajo hazlo internamente y entrega solo el JSON.',
      messages: [{ role: 'user', content: userPrompt }]
    }, { headers, timeout: 57000 });

    const text = response.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
    let topics = extractTopics(text);
    if (topics && topics.length) {
      // FILTRO DE FRESCURA por código: descartar noticias de más de 7 días
      const maxAgeMs = 7 * 24 * 60 * 60 * 1000;
      const nowMs = Date.now();
      const fresh = topics.filter(t => {
        if (!t.published_date) return true; // si no hay fecha reconocible, no la descartamos aquí (el modelo ya la filtró)
        const d = new Date(t.published_date);
        if (isNaN(d.getTime())) return true; // fecha no parseable → no descartar por código
        return (nowMs - d.getTime()) <= maxAgeMs;
      });
      // ANTI-DUPLICADOS por código (red de seguridad): descartar títulos muy parecidos
      const norm = s => (s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9 ]/g, '').replace(/\s+/g, ' ').trim();
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
      if (mapped.length) {
        await persistSearch(sector, mapped, now);
        return res.json({ topics: mapped, searchedAt: now, source: 'web' });
      }
      // Todo lo encontrado era viejo → sin novedades frescas
      return res.json({ topics: [], searchedAt: now, source: 'web', empty: true, reason: 'all_old' });
    }
    // La búsqueda respondió pero no pudimos extraer temas
    console.error('No topics parsed. Raw text (first 500):', text.slice(0, 500));
    return res.json({ topics: [], searchedAt: now, source: 'web', empty: true, reason: 'no_parse' });
  } catch (webErr) {
    const detail = webErr.response?.data?.error?.message || webErr.message;
    console.error('Web search failed:', detail);
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
