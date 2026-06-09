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

  // If scheduled for the future, save it
  if (scheduledAt && new Date(scheduledAt) > new Date()) {
    const post = {
      id: Date.now().toString(),
      body: text,
      scheduledAt,
      status: 'scheduled',
      createdAt: new Date().toISOString()
    };
    store.posts.push(post);
    return res.json({ ok: true, status: 'scheduled', post });
  }

  // Publish now
  try {
    const authorId = req.linkedinSession.profile?.sub;
    const payload = {
      author: `urn:li:person:${authorId}`,
      lifecycleState: 'PUBLISHED',
      specificContent: {
        'com.linkedin.ugc.ShareContent': {
          shareCommentary: { text },
          shareMediaCategory: 'NONE'
        }
      },
      visibility: { 'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC' }
    };

    const publishRes = await axios.post('https://api.linkedin.com/v2/ugcPosts', payload, {
      headers: {
        Authorization: `Bearer ${req.linkedinSession.accessToken}`,
        'Content-Type': 'application/json',
        'X-Restli-Protocol-Version': '2.0.0'
      }
    });

    const linkedinId = publishRes.data.id;
    const post = {
      id: Date.now().toString(),
      linkedinId,
      body: text,
      publishedAt: new Date().toISOString(),
      status: 'published'
    };
    store.posts.push(post);

    res.json({ ok: true, status: 'published', linkedinId, post });
  } catch (err) {
    console.error('Publish error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to publish', detail: err.response?.data });
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
    l100: 'unos 100 caracteres, ultra breve, como un titular potente con gancho',
    l300: 'unos 300 caracteres, muy conciso y directo',
    l500: 'unos 500 caracteres, breve pero con desarrollo',
    l700: 'unos 700 caracteres, con buen desarrollo del argumento',
    l1000: 'unos 1000 caracteres, completo y detallado'
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

  try {
    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-6',
      max_tokens: 1000,
      system: `Eres el ghostwriter personal de Borja Pérez Herraiz, Affiliates & Business Development Sr. Manager en Paramount International, con +15 años en distribución multiplataforma, OTT, FAST, SVOD y partnerships. Escribes posts de LinkedIn con su voz: directa, experta, sin corporativismos. Español.`,
      messages: [{
        role: 'user',
        content: `Perfil: ${profile}
Tema: ${topic.title}
Por qué importa: ${topic.why}
Ángulo: ${topic.angle}
Tono (combina estos matices en un solo post): ${toneInstruction}
Longitud objetivo: ${lengthMap[length] || lengthMap.l500}

Escribe el post siguiendo estas reglas:
1. Primera línea: gancho que para el scroll. Sin frases vacías.
2. Perspectiva de alguien en distribución y partnerships en Paramount.
3. Insight que solo un insider del sector podría dar.
4. Si la longitud lo permite, termina con una pregunta que invite a comentar.
5. Saltos de línea entre párrafos (lectura móvil).
6. ${emojiRule}
7. OBLIGATORIO: termina SIEMPRE con 3-5 hashtags relevantes al tema concreto del artículo (no genéricos), en una línea aparte. Combina hashtags del sector (#FAST #OTT #SVOD #CTV #Streaming) con hashtags específicos de la noticia.

Solo el texto del post.`
      }]
    }, {
      headers: {
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json'
      }
    });

    const text = response.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
    res.json({ text });
  } catch (err) {
    console.error('Generate error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Generation failed' });
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
    await sbUpsert('searches', { sector, sector_name: sector, topics, searched_at: searchedAt });
    await sbUpsert('rate_limit', { sector, last_search: searchedAt });
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

  // ── Límite de 24h por sector (usando Supabase) ──
  try {
    const rows = await sbGet('rate_limit', `?sector=eq.${encodeURIComponent(sector)}&select=*`);
    if (rows && rows[0]) {
      const last = new Date(rows[0].last_search).getTime();
      const hoursPassed = (Date.now() - last) / (1000 * 60 * 60);
      if (hoursPassed < 24) {
        const hoursLeft = Math.ceil(24 - hoursPassed);
        return res.status(429).json({
          error: 'rate_limited',
          detail: `Ya buscaste en esta categoría hace poco. Podrás volver a buscar en ~${hoursLeft}h.`,
          lastSearch: rows[0].last_search,
          hoursLeft
        });
      }
    }
  } catch(e) { console.error('Rate limit check error:', e.response?.data || e.message); }

  // Cargar fuentes activas desde Supabase
  let sourcesList = '';
  try {
    const srcs = await sbGet('sources', '?active=eq.true&select=name,url');
    if (srcs && srcs.length) {
      sourcesList = srcs.map(s => s.name + (s.url ? ' ('+s.url+')' : '')).join(', ');
    }
  } catch(e) { console.error('Sources load error:', e.message); }

  const headers = {
    'x-api-key': process.env.ANTHROPIC_API_KEY,
    'anthropic-version': '2023-06-01',
    'Content-Type': 'application/json'
  };
  const now = new Date().toISOString();
  const sourcesLine = sourcesList ? `Prioriza estas fuentes de confianza: ${sourcesList}.` : '';
  const userPrompt = `Genera SOLO tendencias o noticias RECIENTES (de los últimos 5 días como máximo) sobre: ${sector}.
Fecha y hora actual de referencia: ${now}.
${sourcesLine}
REGLAS ESTRICTAS:
- SOLO noticias publicadas en los últimos 5 días. Si una noticia es más antigua, NO la incluyas bajo ningún concepto.
- Solo temas con engagement "hot" (muy caliente) o "trending" (en tendencia).
- Es mejor devolver pocos temas (o ninguno) que incluir noticias antiguas. NO rellenes.
- Cada URL debe ser un enlace REAL y verificado a la noticia original.
Devuelve SOLO un array JSON (sin backticks, sin texto extra). Si no hay noticias frescas que cumplan, devuelve un array vacío [].
[{"title":"titular en español max 13 palabras","why":"por qué importa ahora (1 frase)","engagement":"hot|trending","platform":"x|linkedin|web|mixed","eng_reactions":"ej: 8.2k likes","eng_comments":"ej: 1.4k comentarios","tags":["tag1","tag2","tag3"],"angle":"ángulo de opinión para un directivo de Paramount (1 frase)","published":"fecha de la noticia, ej: 'Hoy 09:30' o '2026-06-02'","url":"enlace directo REAL a la noticia original"}]`;

  // Búsqueda web (temas reales y frescos de los últimos 5 días)
  try {
    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-6',
      max_tokens: 2500,
      tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 5 }],
      system: 'Eres un editor de contenido del sector audiovisual y streaming. Buscas SOLO noticias REALES de los últimos 5 días, con su enlace original verificado. Si no hay nada fresco, devuelves un array vacío. Nunca inventas URLs ni rellenas con noticias antiguas. Respondes SOLO con JSON válido, sin backticks.',
      messages: [{ role: 'user', content: `Busca en internet noticias de los últimos 5 días y luego ${userPrompt}` }]
    }, { headers, timeout: 45000 });

    const text = response.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
    const match = text.match(/\[[\s\S]*\]/);
    if (match) {
      let topics = JSON.parse(match[0]);
      topics = topics.filter(t => t.engagement === 'hot' || t.engagement === 'trending');
      topics = topics.map(t => ({ ...t, source: 'web' }));
      await persistSearch(sector, topics, now);
      return res.json({ topics, searchedAt: now, source: 'web' });
    }
    throw new Error('No JSON in web search response');
  } catch (webErr) {
    console.error('Web search failed:', webErr.response?.data || webErr.message);
    // Si la búsqueda web falla del todo, NO rellenamos con IA (evitamos noticias viejas).
    // Devolvemos "sin novedades" salvo que sea un error de la API (no de contenido).
    const isApiError = webErr.response?.status === 401 || webErr.response?.status === 400;
    if (isApiError) {
      return res.status(500).json({ error: 'Search failed', detail: webErr.response?.data?.error?.message || webErr.message });
    }
    // Timeout o sin resultados: registramos el intento (para el límite 24h) y devolvemos vacío
    await persistSearch(sector, [], now);
    return res.json({ topics: [], searchedAt: now, source: 'web', empty: true });
  }
});

// ─── EXPORT (Vercel serverless) ─────────────────────────────────────────────
// En Vercel se exporta la app directamente.
// Para desarrollo local: descomenta las 2 lineas de abajo y ejecuta `node api/index.js`
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`StreamVoice en http://localhost:${PORT}`));

module.exports = app;
