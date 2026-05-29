# StreamVoice — LinkedIn Assistant para Borja Pérez Herraiz

## Deploy en 30-45 minutos

### Paso 1 — Subir a GitHub

```bash
git init
git add .
git commit -m "StreamVoice v1.0"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/streamvoice.git
git push -u origin main
```

### Paso 2 — Crear app LinkedIn (10 min)

1. Ve a https://developer.linkedin.com/apps
2. Clic en "Create app"
3. Rellena: App name = "StreamVoice", LinkedIn Page = tu empresa o perfil
4. En "Products" solicita: **Share on LinkedIn** y **Sign In with LinkedIn using OpenID Connect**
5. En "Auth" → Authorized redirect URLs añade:
   - `https://TU-APP.vercel.app/api/auth/callback`
   - `http://localhost:3000/api/auth/callback` (para desarrollo local)
6. Copia el **Client ID** y **Client Secret**

### Paso 3 — Deploy en Vercel (5 min)

1. Ve a https://vercel.com y conecta con tu cuenta GitHub
2. "New Project" → importa el repo `streamvoice`
3. En "Environment Variables" añade:

| Variable | Valor |
|---|---|
| `ANTHROPIC_API_KEY` | Tu API key de Anthropic |
| `LINKEDIN_CLIENT_ID` | Del paso 2 |
| `LINKEDIN_CLIENT_SECRET` | Del paso 2 |
| `LINKEDIN_REDIRECT_URI` | `https://TU-APP.vercel.app/api/auth/callback` |
| `SESSION_SECRET` | Cualquier string largo y aleatorio |

4. Clic "Deploy" — Vercel te da una URL tipo `streamvoice-xxx.vercel.app`
5. Actualiza `LINKEDIN_REDIRECT_URI` con la URL real y re-despliega

### Paso 4 — Primera conexión

1. Abre tu URL de Vercel
2. Clic en "Conectar LinkedIn"
3. Autoriza la app
4. ¡Listo! Ya puedes publicar directamente desde StreamVoice

---

## Desarrollo local

```bash
npm install
cp .env.example .env
# Edita .env con tus claves
node api/index.js
# Abre http://localhost:3000
```

## Actualizar la app

Cualquier push a `main` en GitHub dispara un redeploy automático en Vercel.

```bash
git add .
git commit -m "tu mensaje"
git push
```

---

## Endpoints disponibles

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/auth/linkedin` | Inicia OAuth con LinkedIn |
| GET | `/api/auth/callback` | Callback OAuth |
| GET | `/api/auth/status` | Estado de la sesión |
| POST | `/api/publish` | Publicar o programar un post |
| GET | `/api/posts` | Listar todos los posts |
| GET | `/api/metrics/:id` | Métricas de un post |
| GET | `/api/metrics` | Todas las métricas |
| GET | `/api/tips` | Tips personalizados |
| GET | `/api/best-times` | Mejores momentos para publicar |
| POST | `/api/generate` | Generar post con IA |
| POST | `/api/search-topics` | Buscar tendencias del sector |

## Próximos pasos opcionales

- **Base de datos persistente**: Cambiar el store en memoria por Vercel KV o PlanetScale
- **Notificaciones**: Añadir email con Resend cuando llega el momento de publicar
- **Analytics avanzado**: Dashboard con Chart.js mostrando evolución del engagement
- **Dominio propio**: Añadir `streamvoice.borjaph.com` en Vercel (gratis)
