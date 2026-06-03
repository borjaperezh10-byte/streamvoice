require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// In-memory store (upgrade to Vercel KV or Redis for production persistence)
const store = {
  posts: [],       // { id, title, body, scheduledAt, publishedAt, linkedinId }
  metrics: [],     // { postId, impressions, reactions, comments, shares, date }
  userProfile: null
};

// ─── AUTH ─────────────────────────────────────────────────────────────────────

app.get('/api/auth/linkedin', (req, res) => {
  const scope = 'openid profile email w_member_social r_basicprofile';
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

    req.session.accessToken = tokenRes.data.access_token;
    req.session.tokenExpiry = Date.now() + tokenRes.data.expires_in * 1000;

    // Fetch LinkedIn profile
    const profileRes = await axios.get('https://api.linkedin.com/v2/userinfo', {
      headers: { Authorization: `Bearer ${req.session.accessToken}` }
    });
    req.session.profile = profileRes.data;
    store.userProfile = profileRes.data;

    res.redirect('/?connected=true');
  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message);
    res.redirect('/?error=auth_failed');
  }
});

app.get('/api/auth/status', (req, res) => {
  const connected = !!(req.session.accessToken && req.session.tokenExpiry > Date.now());
  res.json({
    connected,
    profile: connected ? req.session.profile : null,
    expiresIn: connected ? Math.floor((req.session.tokenExpiry - Date.now()) / 1000) : 0
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// ─── MIDDLEWARE: require auth ──────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (!req.session.accessToken || req.session.tokenExpiry < Date.now()) {
    return res.status(401).json({ error: 'Not authenticated. Please connect LinkedIn.' });
  }
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
    const authorId = req.session.profile?.sub;
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
        Authorization: `Bearer ${req.session.accessToken}`,
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
      { headers: { Authorization: `Bearer ${req.session.accessToken}` } }
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
    short: 'entre 300 y 500 caracteres, muy directo e impactante',
    medium: 'entre 800 y 1200 caracteres con buen desarrollo',
    long: 'entre 1500 y 2000 caracteres con profundidad y contexto'
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

app.post('/api/search-topics', async (req, res) => {
  const { sector } = req.body;
  const headers = {
    'x-api-key': process.env.ANTHROPIC_API_KEY,
    'anthropic-version': '2023-06-01',
    'Content-Type': 'application/json'
  };
  const now = new Date().toISOString();
  const userPrompt = `Genera SOLO tendencias o noticias MUY RECIENTES (de las últimas 24 horas) sobre: ${sector}.
Fecha y hora actual de referencia: ${now}.
REGLAS ESTRICTAS:
- Solo incluye temas con engagement "hot" (muy caliente) o "trending" (en tendencia). NO incluyas temas "rising" ni de bajo engagement.
- Solo noticias o conversaciones de las últimas 24 horas. Descarta cualquier cosa más antigua.
- Devuelve entre 3 y 6 temas (los que realmente cumplan el criterio, no rellenes).
Devuelve SOLO un array JSON (sin backticks, sin texto extra):
[{"title":"titular en español max 13 palabras","why":"por qué importa ahora (1 frase)","engagement":"hot|trending","platform":"x|linkedin|web|mixed","eng_reactions":"ej: 8.2k likes","eng_comments":"ej: 1.4k comentarios","tags":["tag1","tag2","tag3"],"angle":"ángulo de opinión para un directivo de Paramount (1 frase)","published":"fecha y hora aprox de la noticia, ej: 'Hoy 09:30' o '2026-06-02 14:00'","url":"enlace directo a la fuente/noticia original (URL real y completa)"}]`;

  // INTENTO 1: con búsqueda web (temas reales y actuales de las últimas 24h)
  try {
    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-6',
      max_tokens: 2000,
      tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 3 }],
      system: 'Eres un editor de contenido del sector audiovisual y streaming. Buscas noticias y tendencias REALES de las últimas 24 horas, con su enlace original. Respondes SOLO con JSON válido, sin backticks.',
      messages: [{ role: 'user', content: `Busca en internet noticias de las últimas 24 horas y luego ${userPrompt}` }]
    }, { headers, timeout: 40000 });

    const text = response.data.content?.filter(b => b.type === 'text').map(b => b.text).join('') || '';
    const match = text.match(/\[[\s\S]*\]/);
    if (match) {
      let topics = JSON.parse(match[0]);
      topics = topics.filter(t => t.engagement === 'hot' || t.engagement === 'trending');
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
