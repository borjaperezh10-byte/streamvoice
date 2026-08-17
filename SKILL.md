---
name: streamvoice
description: Contexto y reglas de StreamVoice, proyecto personal de Borja (asistente editorial de LinkedIn para el sector audiovisual/streaming). Consulta esta skill SIEMPRE que trabajes en este repo — backend api/index.js, frontend public/index.html, esquema de Supabase, o cualquier cambio de producto — antes de escribir código, generar contenido de ejemplo, o tocar la base de datos. Es especialmente crítica para la "regla de oro" de voz editorial (nunca mencionar a Paramount) y para las convenciones de migraciones en Supabase.
---

# StreamVoice

Asistente editorial de LinkedIn para el sector audiovisual/streaming. Proyecto **personal** de Borja Pérez, que trabaja en Affiliates & Business Development en Paramount — **StreamVoice no está afiliado a Paramount**.

## Qué hace la app

1. Busca tendencias/noticias del sector streaming-TV (`/api/search-topics`, con Claude + web search en dos fases: fuentes propias vía `site:` + búsqueda general).
2. Genera borradores de posts de LinkedIn a partir de una noticia o de un enlace/texto propio (`/api/generate`), con tono(s) seleccionables (38 combinables) y longitud configurable.
3. Permite editar el borrador y la vista previa antes de publicar.
4. Publica inmediatamente o programa publicación vía LinkedIn OAuth (`/api/publish`, `/api/schedule` + cron-job.org llamando a `/api/cron/publish-due`).
5. Guarda historial de búsquedas, borradores generados y posts publicados/programados.

## Regla de oro (innegociable, revisar en TODO contenido generado)

Borja habla como **analista independiente del sector audiovisual, desde su propia experiencia** — nunca en nombre de, citando, o dando voz a Paramount. Ningún prompt, tip, plantilla o texto de ejemplo debe sugerir frases tipo *"En Paramount hemos visto..."*, *"mi empresa..."* o exponer información interna de Paramount. Si detectas algo así en el código (prompts de generación, tips estáticos, ejemplos), señálalo aunque no te lo pidan explícitamente — es el fallo más grave posible en este proyecto.

> Pendiente conocido: el tip estático en `/api/tips` ("Tu diferencial: perspectiva de Paramount") contradice esta regla. No genera contenido real (es un tip de UI, no un prompt de IA), pero debe corregirse cuando Borja lo pida.

## Stack

- **Frontend**: `public/index.html` — HTML/CSS/JS vanilla en un solo archivo (~830 líneas), sin framework ni build step.
- **Backend**: `api/index.js` — Express, desplegado como función serverless en Vercel (`vercel.json` reescribe `/api/*` → `api/index.js`, `maxDuration: 60`).
- **Base de datos**: Supabase (proyecto `streamvoice`, id `hraankfpllzxiquglkhb`, región `eu-central-1`).
- **Auth de publicación**: LinkedIn OAuth, sesión persistida en la tabla `sessions` (fila fija `id='borja-main'`, single-user).
- **Generación/búsqueda**: Claude (`claude-sonnet-4-6`) vía API de Anthropic, con web search para encontrar tendencias.
- **Programación de publicaciones**: cron-job.org (externo y gratuito) llama periódicamente a `/api/cron/publish-due`.
- **PWA**: `manifest.json` básico (nombre, iconos, colores).

## Esquema real de Supabase (tablas existentes)

- `sessions` — token OAuth de LinkedIn, fila única `borja-main`. **El token caduca cada ~60 días aprox.**, hay que reautenticar manualmente.
- `scheduled_posts` — posts programados pendientes de publicar.
- `searches` — historial de búsquedas de tendencias.
- `sources` — fuentes de búsqueda gestionables (activar/desactivar, añadir propias).
- `rate_limit` — límite de generación por sector y día natural en hora española (`Europe/Madrid`).
- `draft_history` — historial de borradores generados (texto, tono, nº de caracteres, noticia/fuente de origen), se guarda automáticamente en cada generación.

### Convenciones al crear/editar tablas

- PKs: `gen_random_uuid()`.
- Arrays/objetos: `jsonb` (no columnas separadas ni tablas relacionadas para datos simples como listas de tonos).
- Si hay consultas "más reciente primero": índice `DESC` sobre `created_at`.
- **DDL (crear/alterar tablas) → usar `Supabase:apply_migration` con nombre de migración descriptivo**, nunca `execute_sql` para DDL — es el método fiable comprobado en este proyecto. `execute_sql` sí vale para SELECT/INSERT/DELETE puntuales de verificación o datos.
- Antes de crear una tabla nueva, comprobar con `Supabase:list_projects` que se está apuntando al proyecto `streamvoice` (hay otro proyecto personal de Borja, `seguimiento-nutricional`, en la misma cuenta — no mezclar).

## Convenciones de código ya presentes en `api/index.js`

- Parseo de JSON de respuestas de Claude: robusto ante formatos inesperados, con `isValidTopicArray` para validar que el array de temas tiene la forma correcta antes de usarlo.
- Anti-duplicados de temas: similitud de Jaccard, umbral `0.3`.
- Frescura de noticias: se descartan temas con más de 7 días, filtrado en código (no en el prompt).
- Longitud de posts: `lengthMap` con instrucciones imperativas al final del prompt (las instrucciones de formato funcionan mejor al final, no al principio).
- `max_tokens` proporcional a la longitud solicitada, para no gastar de más.
- Un único modelo en todo el backend: `claude-sonnet-4-6` (no mezclar versiones entre `/api/generate` y `/api/search-topics`).

## Cómo trabajar con Borja en este proyecto

- **Comunicación siempre en español.**
- Tono profesional pero cercano.
- Prefiere pasos muy granulares: explicar qué se va a hacer y, si hay varias formas razonables de hacerlo, preguntar antes de tocar código o infraestructura (especialmente si implica escribir en Supabase real o desplegar).
- Probar todo lo posible antes de entregar (sintaxis, lógica, y si es posible contra la base de datos real con datos de prueba que luego se borran) y ser explícito sobre qué se probó y qué no se pudo probar.
- Priorizar herramientas gratuitas (de ahí cron-job.org en vez de un scheduler de pago).
- Entregar los archivos modificados completos (no solo el diff) listos para sustituir en el repo y desplegar.
