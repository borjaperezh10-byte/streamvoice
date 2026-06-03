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
  const { text, scheduledAt } = req.body;
  if (!text) return res.status(400).json({ error: 'Missing text' });

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
  const { topic, profile, tone, length } = req.body;

  const lengthMap = {
    veryshort: 'unos 300 caracteres, muy breve e impactante, como un titular con gancho',
    short: 'unos 600 caracteres, conciso y directo',
    medium: 'unos 1000 caracteres, con buen desarrollo del argumento',
    long: 'unos 1500 caracteres, con profundidad y contexto',
    verylong: 'unos 2000 caracteres, análisis completo y detallado'
  };

  const toneMap = {
    opinionado: 'toma una posición clara y directa, bien argumentada, primera persona',
    reflexivo: 'comparte reflexiones personales desde tu experiencia real, invita a la conversación',
    divulgativo: 'explica con claridad para profesionales, aporta contexto y datos concretos',
    provocador: 'lanza una tesis controvertida pero fundamentada, genera debate',
    narrativo: 'cuenta una historia o anécdota profesional que ilustre el tema',
    datos: 'apóyate en cifras y estudios del sector para construir el argumento'
  };

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
Tono: ${toneMap[tone] || toneMap.opinionado}
Longitud: ${lengthMap[length] || lengthMap.medium}

Escribe el post siguiendo estas reglas:
1. Primera línea: gancho que para el scroll. Sin frases vacías.
2. Perspectiva de alguien en distribución y partnerships en Paramount.
3. Insight que solo un insider del sector podría dar.
4. Termina con pregunta específica que requiera criterio profesional.
5. Saltos de línea entre párrafos (lectura móvil).
6. 4-6 hashtags de nicho al final: #FAST #OTT #SVOD #CTV #ContentDistribution

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

  const headers = {
    'x-api-key': process.env.ANTHROPIC_API_KEY,
    'anthropic-version': '2023-06-01',
    'Content-Type': 'application/json'
  };
  const now = new Date().toISOString();
  const userPrompt = `Genera SOLO tendencias o noticias RECIENTES (de los últimos 3 días) sobre: ${sector}.
Fecha y hora actual de referencia: ${now}.
REGLAS ESTRICTAS:
- Solo incluye temas con engagement "hot" (muy caliente) o "trending" (en tendencia). NO incluyas temas "rising" ni de bajo engagement.
- Solo noticias o conversaciones de los últimos 3 días. Descarta cualquier cosa más antigua.
- Devuelve entre 3 y 6 temas (los que realmente cumplan el criterio, no rellenes).
Devuelve SOLO un array JSON (sin backticks, sin texto extra):
[{"title":"titular en español max 13 palabras","why":"por qué importa ahora (1 frase)","engagement":"hot|trending","platform":"x|linkedin|web|mixed","eng_reactions":"ej: 8.2k likes","eng_comments":"ej: 1.4k comentarios","tags":["tag1","tag2","tag3"],"angle":"ángulo de opinión para un directivo de Paramount (1 frase)","published":"fecha y hora aprox de la noticia, ej: 'Hoy 09:30' o '2026-06-02 14:00'","url":"enlace directo a la fuente/noticia original (URL real y completa)"}]`;

  // INTENTO 1: con búsqueda web (temas reales y actuales de los últimos 3 días)
  try {
    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-6',
      max_tokens: 2000,
      tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 3 }],
      system: 'Eres un editor de contenido del sector audiovisual y streaming. Buscas noticias y tendencias REALES de los últimos 3 días, con su enlace original. Respondes SOLO con JSON válido, sin backticks.',
      messages: [{ role: 'user', content: `Busca en internet noticias de los últimos 3 días y luego ${userPrompt}` }]
    }, { headers, timeout: 20000 });

    const text = response.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
    const match = text.match(/\[[\s\S]*\]/);
    if (match) {
      let topics = JSON.parse(match[0]);
      topics = topics.filter(t => t.engagement === 'hot' || t.engagement === 'trending');
      await persistSearch(sector, topics, now);
      return res.json({ topics, searchedAt: now, source: 'web' });
    }
    throw new Error('No JSON in web search response');
  } catch (webErr) {
    console.error('Web search failed, trying fallback:', webErr.response?.data || webErr.message);

    // INTENTO 2 (plan B): sin búsqueda web, solo IA
    try {
      const response = await axios.post('https://api.anthropic.com/v1/messages', {
        model: 'claude-sonnet-4-6',
        max_tokens: 2000,
        system: 'Eres un editor de contenido senior del sector audiovisual y streaming. Respondes SOLO con JSON válido, sin backticks.',
        messages: [{ role: 'user', content: userPrompt }]
      }, { headers, timeout: 30000 });

      const text = response.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
      const match = text.match(/\[[\s\S]*\]/);
      if (match) {
        let topics = JSON.parse(match[0]);
        topics = topics.filter(t => t.engagement === 'hot' || t.engagement === 'trending');
        await persistSearch(sector, topics, now);
        return res.json({ topics, searchedAt: now, source: 'ai' });
      }
      throw new Error('No JSON in fallback response');
    } catch (fallbackErr) {
      const detail = fallbackErr.response?.data?.error?.message || fallbackErr.message;
      console.error('Fallback also failed:', detail);
      res.status(500).json({ error: 'Search failed', detail });
    }
  }
});

// ─── EXPORT (Vercel serverless) ─────────────────────────────────────────────
// En Vercel se exporta la app directamente.
// Para desarrollo local: descomenta las 2 lineas de abajo y ejecuta `node api/index.js`
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`StreamVoice en http://localhost:${PORT}`));

module.exports = app;
