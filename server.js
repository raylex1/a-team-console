const express = require('express');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const OIDCStrategy = require('passport-openid-connect').Strategy;
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const z = require('zod');
const { execSync } = require('child_process');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);
const fs = require('fs');

const app = express();
const BASE_URL = process.env.BASE_URL || 'https://polymetis.app';

// --- PostgreSQL ---
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: false }) : null;
if (pool) {
  pool.query('SELECT NOW()').then(() => console.log('PostgreSQL connected')).catch(e => console.log('PostgreSQL error:', e.message));
  pool.query(`CREATE TABLE IF NOT EXISTS api_usage (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMPTZ DEFAULT NOW(),
    agent TEXT NOT NULL,
    model TEXT NOT NULL,
    mode TEXT DEFAULT 'quick',
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    thinking_tokens INTEGER DEFAULT 0,
    search_count INTEGER DEFAULT 0,
    cost_usd NUMERIC(10,6) DEFAULT 0,
    job_id TEXT,
    duration_ms INTEGER DEFAULT 0,
    context TEXT
  )`).then(() => console.log('api_usage table ready')).catch(e => console.log('api_usage table error:', e.message));
}

// --- API Cost Tracking ---
const PRICING = {
  'claude-sonnet-4-20250514':    { input: 3.00,  output: 15.00 },
  'claude-opus-4-6':             { input: 5.00,  output: 25.00 },
  'claude-sonnet-4-5-20250929':  { input: 3.00,  output: 15.00 },
  'o3-deep-research-2025-06-26': { input: 10.00, output: 40.00 },
  'gpt-4o':                      { input: 2.50,  output: 10.00 },
  'gpt-4o-mini':                 { input: 0.15,  output: 0.60  },
  'gemini-2.5-flash-preview-04-17': { input: 0.15, output: 0.60 },
  'gemini-2.5-flash-lite':       { input: 0.10,  output: 0.40  },
  'deep-research-pro-preview-12-2025': { input: 1.25, output: 10.00 },  // Gemini Pro-class deep research
  'grok-4-1-fast':               { input: 0.20,  output: 0.50  },  // same as 4.1 Fast variants
  'grok-4-1-fast-non-reasoning': { input: 0.20,  output: 0.50  },
  'grok-4-1-fast-reasoning':     { input: 0.20,  output: 0.50  },
};

function calcCost(model, inputTokens, outputTokens) {
  const p = PRICING[model] || { input: 5.00, output: 25.00 };
  return ((inputTokens / 1_000_000) * p.input) + ((outputTokens / 1_000_000) * p.output);
}

async function trackUsage({ agent, model, mode, input_tokens, output_tokens, thinking_tokens, search_count, job_id, duration_ms, context }) {
  const cost = calcCost(model, input_tokens || 0, (output_tokens || 0) + (thinking_tokens || 0));
  const record = { agent, model, mode: mode || 'quick', input_tokens: input_tokens || 0, output_tokens: output_tokens || 0, thinking_tokens: thinking_tokens || 0, search_count: search_count || 0, cost_usd: cost, job_id: job_id || null, duration_ms: duration_ms || 0, context: context || null };
  
  console.log(`💰 ${agent}/${model} [${mode}]: ${input_tokens || 0}in + ${output_tokens || 0}out + ${thinking_tokens || 0}think = ${cost.toFixed(4)}`);
  
  if (pool) {
    try {
      await pool.query(
        'INSERT INTO api_usage (agent, model, mode, input_tokens, output_tokens, thinking_tokens, search_count, cost_usd, job_id, duration_ms, context) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
        [record.agent, record.model, record.mode, record.input_tokens, record.output_tokens, record.thinking_tokens, record.search_count, record.cost_usd, record.job_id, record.duration_ms, record.context]
      );
    } catch (e) { console.log('Usage tracking error:', e.message); }
  }
  return record;
}

app.set('trust proxy', 1);
app.use(express.json());

// --- Session ---
app.use(session({
  name: 'ateam.sid',
  store: pool ? new pgSession({ pool, tableName: 'session', createTableIfMissing: true }) : undefined,
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: BASE_URL.startsWith('https'),
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Normalize all users to { id, name, email, avatar, provider }
passport.serializeUser((user, done) => {
  if (user && user.data && typeof user.serialize === 'function') {
    const info = user.data;
    return done(null, {
      id: info.sub || info.id,
      name: info.name || info.preferred_username || 'User',
      email: info.email || null,
      avatar: info.picture || null,
      provider: 'microsoft'
    });
  }
  done(null, user);
});
passport.deserializeUser((obj, done) => done(null, obj));

// --- OAuth strategies ---
const oauthConfigured = !!(
  (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) ||
  (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET)
);

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: BASE_URL + '/auth/google/callback'
  }, (accessToken, refreshToken, profile, done) => {
    done(null, {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value,
      avatar: profile.photos?.[0]?.value,
      provider: 'google'
    });
  }));
}

if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
  passport.use('microsoft', new OIDCStrategy({
    issuerHost: 'https://login.microsoftonline.com/common/v2.0',
    client_id: process.env.MICROSOFT_CLIENT_ID,
    client_secret: process.env.MICROSOFT_CLIENT_SECRET,
    redirect_uri: BASE_URL + '/auth/microsoft/callback',
    scope: 'openid profile email',
    response_type: 'code'
  }));
}

// --- Email whitelist ---
function isEmailAllowed(email) {
  const allowed = process.env.ALLOWED_EMAILS;
  if (!allowed) return true; // no whitelist = allow all
  const list = allowed.split(',').map(e => e.trim().toLowerCase());
  return list.includes((email || '').toLowerCase());
}

// --- Agent configurations ---
const AGENTS = {
  claude: {
    name: 'Claude',
    role: 'Principal Architect & Team Lead',
    provider: 'anthropic',
    systemPrompt: `You are Claude, the Principal Architect and Team Lead of the A-Team AI consulting squad. You are advising an enterprise infrastructure architect with 30+ years of experience who is building an automated SOXL trading system.

Your personality and style:
- Write in flowing prose paragraphs, NEVER bullet points or numbered lists
- Think architecturally — draw analogies to infrastructure concepts (VMware, Kubernetes, ESXi, vSphere)
- Be direct and honest, never sycophantic
- You are the team lead — synthesize different perspectives, acknowledge when others raise good points
- When you disagree, say so clearly and explain why
- You care about doing things right: risk management, proper testing, lab-first approaches
- Keep responses focused and under 200 words unless the topic demands more`
  },
  chatgpt: {
    name: 'ChatGPT',
    role: 'Financial Research Analyst',
    provider: 'openai',
    systemPrompt: `You are ChatGPT, the Financial Research Analyst on the A-Team AI consulting squad. You are advising an enterprise infrastructure architect with 30+ years of experience who is building an automated SOXL trading system.

Your personality and style:
- Be comprehensive and cite specific data points, tools, and platforms
- Show enthusiasm for the research but stay grounded in facts
- You favor practical, no-code/low-code solutions that work TODAY
- You recommended TradersPost + TradeStation + TradingView for the trading system
- You believe in starting fast and iterating rather than over-engineering
- Acknowledge risks honestly but focus on actionable paths forward
- Keep responses focused and under 200 words unless the topic demands more`
  },
  gemini: {
    name: 'Gemini',
    role: 'Data Analyst & Ranker',
    provider: 'google',
    systemPrompt: `You are Gemini, the Data Analyst and Ranker on the A-Team AI consulting squad. You are advising an enterprise infrastructure architect with 30+ years of experience who is building an automated SOXL trading system.

Your personality and style:
- Be concise and data-forward
- Use comparison tables and scoring matrices when relevant
- Be quantitative — assign scores, percentages, rankings
- When comparing options, create a clear rubric
- Cut through ambiguity with numbers and structured analysis
- You are neutral and evidence-based, not emotionally attached to any solution
- If data is insufficient, say so rather than speculate
- Keep responses focused and under 200 words unless the topic demands more`
  },
  grok: {
    name: 'Grok',
    role: "Devil's Advocate & Risk Analyst",
    provider: 'xai',
    systemPrompt: `You are Grok, the Devil's Advocate and Risk Analyst on the A-Team AI consulting squad. You are advising an enterprise infrastructure architect with 30+ years of experience who is building an automated SOXL trading system.

Your personality and style:
- Be irreverent, punchy, and contrarian
- Use casual language, no formal formatting, no bullet points, no headers
- Challenge assumptions and poke holes in plans
- If everyone agrees, find the flaw they are missing
- Drop uncomfortable truths that others are too polite to say
- Use humor and sarcasm but always with a real point underneath
- You are the one who says "yeah but what if it all goes wrong?"
- Call out when something is overcomplicated or when simpler solutions exist
- Keep responses short and punchy — under 150 words.`
  }
};

// API call functions for each provider
async function callAnthropic(systemPrompt, userMessage) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY not configured');

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      system: systemPrompt,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{ role: 'user', content: userMessage }]
    })
  });

  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  trackUsage({ agent: 'claude', model: 'claude-sonnet-4-20250514', mode: 'quick', input_tokens: data.usage?.input_tokens, output_tokens: data.usage?.output_tokens, search_count: data.content?.filter(b => b.type === 'web_search_tool_result')?.length || 0 });
  return data.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
}

async function callOpenAI(systemPrompt, userMessage) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new Error('OPENAI_API_KEY not configured');

  const res = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      tools: [{ type: 'web_search_preview' }],
      input: [
        { role: 'developer', content: systemPrompt },
        { role: 'user', content: userMessage }
      ]
    })
  });

  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  const msg = data.output.find(o => o.type === 'message');
  if (!msg) throw new Error('No message in OpenAI response');
  trackUsage({ agent: 'chatgpt', model: 'gpt-4o-mini', mode: 'quick', input_tokens: data.usage?.input_tokens, output_tokens: data.usage?.output_tokens });
  return msg.content.filter(c => c.type === 'output_text').map(c => c.text).join('\n');
}

async function callGoogle(systemPrompt, userMessage) {
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) throw new Error('GOOGLE_AI_API_KEY not configured');

  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ parts: [{ text: userMessage }] }],
      tools: [{ google_search: {} }],
      generationConfig: { maxOutputTokens: 1000 }
    })
  });

  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  trackUsage({ agent: 'gemini', model: 'gemini-2.5-flash-lite', mode: 'quick', input_tokens: data.usageMetadata?.promptTokenCount, output_tokens: data.usageMetadata?.candidatesTokenCount });
  return data.candidates[0].content.parts.map(p => p.text || '').join('\n');
}

async function callXAI(systemPrompt, userMessage) {
  const apiKey = process.env.XAI_API_KEY;
  if (!apiKey) throw new Error('XAI_API_KEY not configured');

  const res = await fetch('https://api.x.ai/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: 'grok-4-1-fast-non-reasoning',
      input: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userMessage }
      ],
      tools: [
        { type: 'web_search' },
        { type: 'x_search' },
        { type: 'code_execution' }
      ]
    })
  });

  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  const msg = data.output.find(o => o.type === 'message');
  if (!msg) throw new Error('No message in xAI response');
  trackUsage({ agent: 'grok', model: 'grok-4-1-fast-non-reasoning', mode: 'quick', input_tokens: data.usage?.input_tokens, output_tokens: data.usage?.output_tokens });
  return msg.content.filter(c => c.type === 'output_text').map(c => c.text).join('\n');
}

// Provider routing (quick mode — used by web UI)
const PROVIDERS = {
  anthropic: callAnthropic,
  openai: callOpenAI,
  google: callGoogle,
  xai: callXAI
};

// --- Deep Research call functions (used by MCP tools) ---

async function callAnthropicDeep(systemPrompt, userMessage) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY not configured');

  const researchEnhancement = '\nIMPORTANT: This is a DEEP RESEARCH query. Use web search extensively — search multiple times to gather comprehensive information. Refine your queries based on initial results. Cross-reference multiple sources. Provide citations. Be thorough — this is a research report, not a quick answer.';

  async function tryModel(model) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      signal: AbortSignal.timeout(300000),
      body: JSON.stringify({
        model,
        max_tokens: 46000,  // must exceed budget_tokens (30K thinking + 16K output)
        thinking: { type: 'enabled', budget_tokens: 30000 },
        system: systemPrompt + researchEnhancement,
        tools: [{ type: 'web_search_20250305', name: 'web_search' }],
        messages: [{ role: 'user', content: userMessage }]
      })
    });
    return res.json();
  }

  let data = await tryModel('claude-opus-4-6');
  if (data.error) {
    console.log('Opus unavailable, falling back to Sonnet 4.5:', data.error.message);
    data = await tryModel('claude-sonnet-4-5-20250929');
    if (data.error) throw new Error(data.error.message);
  }
  const thinkTokens = data.usage?.cache_creation_input_tokens || 0;
  trackUsage({ agent: 'claude', model: data.model || 'claude-opus-4-6', mode: 'deep', input_tokens: data.usage?.input_tokens, output_tokens: data.usage?.output_tokens, thinking_tokens: thinkTokens, search_count: data.content?.filter(b => b.type === 'web_search_tool_result')?.length || 0 });
  return data.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
}

async function callOpenAIDeep(systemPrompt, userMessage) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new Error('OPENAI_API_KEY not configured');

  try {
    // Create background deep research request
    const createRes = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'o3-deep-research-2025-06-26',
        input: [
          { role: 'developer', content: systemPrompt },
          { role: 'user', content: userMessage }
        ],
        background: true,
        tools: [{ type: 'web_search_preview' }]
      })
    });

    const createData = await createRes.json();
    if (createData.error) throw new Error(createData.error.message);
    const responseId = createData.id;
    console.log(`OpenAI deep research started: ${responseId}`);

    // Poll every 10s, max 10 minutes
    const startTime = Date.now();
    while (Date.now() - startTime < 10 * 60 * 1000) {
      await new Promise(r => setTimeout(r, 10000));
      const pollRes = await fetch(`https://api.openai.com/v1/responses/${responseId}`, {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      });
      const poll = await pollRes.json();
      if (poll.error) throw new Error(poll.error.message);

      if (poll.status === 'completed') {
        const msg = poll.output.filter(o => o.type === 'message').pop();
        if (!msg) throw new Error('No message in deep research output');
        trackUsage({ agent: 'chatgpt', model: 'o3-deep-research-2025-06-26', mode: 'deep', input_tokens: poll.usage?.input_tokens, output_tokens: poll.usage?.output_tokens, duration_ms: Date.now() - startTime });
        return msg.content.filter(c => c.type === 'output_text').map(c => c.text).join('\n');
      }
      if (poll.status === 'failed') throw new Error('Deep research failed');
      if (poll.status === 'incomplete') {
        const msg = poll.output.filter(o => o.type === 'message').pop();
        if (msg) return msg.content.filter(c => c.type === 'output_text').map(c => c.text).join('\n') + '\n\n[Deep research incomplete]';
        throw new Error('Deep research incomplete with no output');
      }
      if (poll.status !== 'queued' && poll.status !== 'in_progress') {
        throw new Error(`Unexpected status: ${poll.status}`);
      }
      console.log(`OpenAI deep research polling... status: ${poll.status}`);
    }
    throw new Error('Deep research timed out after 10 minutes');
  } catch (err) {
    // Fallback to gpt-4o with web search
    console.log('OpenAI deep research failed, falling back to gpt-4o:', err.message);
    const res = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: 'gpt-4o',
        tools: [{ type: 'web_search_preview' }],
        input: [
          { role: 'developer', content: systemPrompt },
          { role: 'user', content: userMessage }
        ]
      })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error.message);
    const msg = data.output.find(o => o.type === 'message');
    if (!msg) throw new Error('No message in OpenAI fallback response');
    trackUsage({ agent: 'chatgpt', model: 'gpt-4o', mode: 'deep-fallback', input_tokens: data.usage?.input_tokens, output_tokens: data.usage?.output_tokens });
    return msg.content.filter(c => c.type === 'output_text').map(c => c.text).join('\n');
  }
}

async function callGoogleDeep(systemPrompt, userMessage) {
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) throw new Error('GOOGLE_AI_API_KEY not configured');

  try {
    // Create deep research via Interactions API
    const createRes = await fetch('https://generativelanguage.googleapis.com/v1beta/interactions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey
      },
      body: JSON.stringify({
        agent: 'deep-research-pro-preview-12-2025',
        input: systemPrompt + '\n\n' + userMessage,
        background: true
      })
    });

    const createData = await createRes.json();
    if (createData.error) throw new Error(createData.error.message);
    const interactionId = createData.id;
    console.log(`Google deep research started: ${interactionId}`);

    // Poll every 10s, max 10 minutes
    const startTime = Date.now();
    while (Date.now() - startTime < 10 * 60 * 1000) {
      await new Promise(r => setTimeout(r, 10000));
      const pollRes = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/interactions/${interactionId}`,
        { headers: { 'x-goog-api-key': apiKey } }
      );
      const poll = await pollRes.json();
      if (poll.error) throw new Error(poll.error.message);

      if (poll.status === 'completed') {
        if (!poll.outputs || !poll.outputs.length) throw new Error('No outputs in deep research');
        trackUsage({ agent: 'gemini', model: 'deep-research-pro-preview-12-2025', mode: 'deep', duration_ms: Date.now() - startTime });
        return poll.outputs.filter(o => o.type === 'text').map(o => o.text).join('\n');
      }
      if (poll.status === 'failed' || poll.status === 'cancelled') {
        throw new Error(`Deep research ${poll.status}`);
      }
      console.log(`Google deep research polling... status: ${poll.status}`);
    }
    throw new Error('Deep research timed out after 10 minutes');
  } catch (err) {
    // Fallback to gemini-2.5-flash-lite with Google Search grounding
    console.log('Google deep research failed, falling back to gemini-2.5-flash-lite:', err.message);
    return callGoogle(systemPrompt, userMessage);
  }
}

async function callXAIDeep(systemPrompt, userMessage) {
  const apiKey = process.env.XAI_API_KEY;
  if (!apiKey) throw new Error('XAI_API_KEY not configured');

  const researchEnhancement = '\nIMPORTANT: This is a DEEP RESEARCH query. Use ALL available tools: web_search for comprehensive web research, x_search for real-time discussions and expert opinions, code_execution for calculations or data analysis. Search multiple times, refine, dig deeper. Cite sources. Be thorough.';

  const res = await fetch('https://api.x.ai/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    signal: AbortSignal.timeout(300000),
    body: JSON.stringify({
      model: 'grok-4-1-fast-reasoning',
      input: [
        { role: 'system', content: systemPrompt + researchEnhancement },
        { role: 'user', content: userMessage }
      ],
      tools: [{ type: 'web_search' }]
    })
  });

  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  const msg = data.output.find(o => o.type === 'message');
  if (!msg) throw new Error('No message in xAI response');
  trackUsage({ agent: 'grok', model: 'grok-4-1-fast-reasoning', mode: 'deep', input_tokens: data.usage?.input_tokens, output_tokens: data.usage?.output_tokens });
  return msg.content.filter(c => c.type === 'output_text').map(c => c.text).join('\n');
}

// Deep provider routing (used by MCP tools in deep mode)
const DEEP_PROVIDERS = {
  anthropic: callAnthropicDeep,
  openai: callOpenAIDeep,
  google: callGoogleDeep,
  xai: callXAIDeep
};

// Model name maps for fallback notifications
const DEEP_MODEL_NAMES = {
  anthropic: 'Claude Opus 4.6 (Deep Think + Multi-Search)',
  openai: 'o3-deep-research-2025-06-26',
  google: 'Gemini Deep Research',
  xai: 'Grok 4.1 Reasoning + DeepSearch'
};

const QUICK_MODEL_NAMES = {
  anthropic: 'Claude Sonnet 4',
  openai: 'GPT-4o Mini',
  google: 'Gemini 2.5 Flash Lite',
  xai: 'Grok 4.1 Fast Non-Reasoning'
};

// --- In-memory job store for async deep research ---
const deepJobs = new Map();

// Clean up jobs older than 1 hour
setInterval(() => {
  const cutoff = Date.now() - 60 * 60 * 1000;
  for (const [id, job] of deepJobs) {
    if (job.createdAt < cutoff) deepJobs.delete(id);
  }
}, 10 * 60 * 1000);

const modeSchema = z.enum(['quick', 'deep']).default('deep').describe('quick = fast models (immediate response), deep = deep research with extended thinking and web search (returns job ID, poll with get_research_results)');

// Run a deep research job in the background (fire-and-forget)
function startDeepJob(toolName, query, agentIds, agentModes, consolidatorMode) {
  // agentModes: { claude: 'deep', chatgpt: 'quick', ... } — if not provided, all deep
  // consolidatorMode: 'quick' | 'deep' — if not provided, defaults to 'deep'
  const modeMap = agentModes || {};
  const synthMode = consolidatorMode || 'deep';
  const jobId = crypto.randomUUID();
  const job = {
    id: jobId,
    tool: toolName,
    query,
    status: 'researching',
    agentIds,
    agentModes: modeMap,
    consolidatorMode: synthMode,
    results: {},
    errors: {},
    modes: {},
    costs: {},
    synthesis: null,
    synthesisCost: null,
    createdAt: Date.now(),
    completedAt: null
  };
  deepJobs.set(jobId, job);

  // Fire and forget — runs in background
  (async () => {
    try {
      // Call all requested agents in parallel, respecting per-agent mode
      await Promise.all(agentIds.map(async (id) => {
        const agent = AGENTS[id];
        const requestedMode = modeMap[id] || 'deep';
        const agentStart = Date.now();
        
        if (requestedMode === 'quick') {
          // Quick mode — use fast provider directly
          try {
            const callFn = PROVIDERS[agent.provider];
            job.results[id] = await callFn(agent.systemPrompt, query);
            job.modes[id] = 'quick';
            console.log(`Job ${jobId}: ${id} completed (quick)`);
          } catch (err) {
            job.modes[id] = 'failed';
            job.errors[id] = err.message;
            console.log(`Job ${jobId}: ${id} quick failed: ${err.message}`);
          }
        } else {
          // Deep mode — try deep, fall back to quick
          try {
            const callFn = DEEP_PROVIDERS[agent.provider];
            job.results[id] = await callFn(agent.systemPrompt, query);
            job.modes[id] = 'deep';
            console.log(`Job ${jobId}: ${id} completed (deep)`);
          } catch (deepErr) {
            console.log(`Job ${jobId}: ${id} deep failed: ${deepErr.message}, falling back to quick`);
            try {
              const quickFn = PROVIDERS[agent.provider];
              job.results[id] = await quickFn(agent.systemPrompt, query);
              job.modes[id] = 'fallback';
              job.errors[id] = deepErr.message;
              console.log(`Job ${jobId}: ${id} completed (fallback to quick)`);
            } catch (quickErr) {
              job.modes[id] = 'failed';
              job.errors[id] = `Deep: ${deepErr.message} | Quick: ${quickErr.message}`;
              console.log(`Job ${jobId}: ${id} both failed: ${quickErr.message}`);
            }
          }
        }
        
        // Capture cost from last usage entry for this agent
        if (pool) {
          try {
            const { rows } = await pool.query('SELECT cost_usd, input_tokens, output_tokens FROM api_usage WHERE agent = $1 ORDER BY ts DESC LIMIT 1', [id]);
            if (rows[0]) job.costs[id] = { cost: parseFloat(rows[0].cost_usd), input: rows[0].input_tokens, output: rows[0].output_tokens };
          } catch (e) { /* ignore */ }
        }
      }));

      // If team consult, run synthesis
      if (agentIds.length > 1) {
        job.status = 'synthesizing';
        console.log(`Job ${jobId}: all agents complete, starting ${synthMode} synthesis...`);
        const allResponses = agentIds
          .filter(id => job.results[id])
          .map(id => `${AGENTS[id].name} (${AGENTS[id].role}):\n${job.results[id]}`)
          .join('\n\n');
        try {
          const synthPrompt = `You are a senior research analyst producing a comprehensive synthesis report. You have received research reports from four independent AI analysts on the same topic. Your job is to produce a DEFINITIVE synthesis that a decision-maker can act on.

YOUR MANDATE:
1. VERIFY: Use web search to fact-check the most important claims from each report. Flag any data points that conflict between reports or cannot be verified.
2. CROSS-REFERENCE: Identify where multiple analysts independently reached the same conclusion (high confidence) vs where they disagree (needs investigation).
3. FILL GAPS: If all four reports missed something important, research it yourself and add it.
4. RESOLVE CONFLICTS: When reports contradict each other, determine which is correct using primary sources.
5. SYNTHESIZE: Produce a unified analysis that is MORE valuable than any individual report alone.

OUTPUT FORMAT:
Start with "SYNTHESIS REPORT" as a header, then:
Executive Summary (2-3 paragraphs with key findings, recommendation, confidence level),
Areas of Consensus (what most analysts agree on with verified data),
Key Disagreements and Resolution (conflicts found and which source is correct),
Critical Gaps Identified (what was missed plus your own research to fill them),
Risk Factors and Uncertainties (what we still do not know),
Final Recommendation (clear, actionable, with reasoning),
Sources consulted during synthesis verification.

Write in authoritative prose. Be thorough. This synthesis should be the ONLY document the decision-maker needs to read. Aim for 1500-3000 words depending on topic complexity.`;
          if (synthMode === 'deep') {
            job.synthesis = await callOpenAIDeep(synthPrompt, `ORIGINAL QUESTION: ${query}\n\n--- ANALYST REPORTS ---\n\n${allResponses}`);
          } else {
            const quickSynthPrompt = `You are the Principal Architect synthesizing analyst reports. Provide a clear synthesis: identify consensus, highlight disagreements and which side has stronger evidence, note gaps, give your recommendation. Write in authoritative prose, 500-800 words. Start with "SYNTHESIS:" on its own line.`;
            job.synthesis = await callAnthropicDeep(quickSynthPrompt, `ORIGINAL QUESTION: ${query}\n\n--- ANALYST REPORTS ---\n\n${allResponses}`);
          }
        } catch (e) {
          console.log(`Job ${jobId}: synthesis failed (${e.message}), falling back...`);
          try {
            const fallbackPrompt = `You are the Principal Architect synthesizing research reports. Provide a comprehensive synthesis: identify consensus, resolve conflicts, highlight gaps, give a clear recommendation. Write in authoritative prose, 800-1500 words. Start with "SYNTHESIS REPORT" header.`;
            job.synthesis = await callAnthropicDeep(fallbackPrompt, `ORIGINAL QUESTION: ${query}\n\n--- ANALYST REPORTS ---\n\n${allResponses}`);
          } catch (e2) { job.synthesis = `Synthesis error: ${e2.message}`; }
        }
        // Capture synthesis cost
        if (pool) {
          try {
            const { rows } = await pool.query("SELECT cost_usd, input_tokens, output_tokens FROM api_usage WHERE agent IN ('chatgpt','claude') ORDER BY ts DESC LIMIT 1");
            if (rows[0]) job.synthesisCost = { cost: parseFloat(rows[0].cost_usd), input: rows[0].input_tokens, output: rows[0].output_tokens };
          } catch (e) { /* ignore */ }
        }
      }

      job.status = 'completed';
      job.completedAt = Date.now();
      const elapsed = ((job.completedAt - job.createdAt) / 1000).toFixed(1);
      console.log(`Job ${jobId}: completed in ${elapsed}s`);
    } catch (e) {
      job.status = 'failed';
      job.completedAt = Date.now();
      console.error(`Job ${jobId}: fatal error:`, e.message);
    }
  })();

  return jobId;
}

// Format a completed job into a text response with mode indicators
function formatJobResults(job) {
  const parts = job.agentIds.map(id => {
    const agent = AGENTS[id];
    const header = `## ${agent.name} (${agent.role})`;
    const mode = job.modes[id];
    if (mode === 'failed' || !job.results[id]) {
      return `${header}\n❌ FAILED: ${job.errors[id] || 'No response'}`;
    }
    if (mode === 'fallback') {
      const quickModel = QUICK_MODEL_NAMES[agent.provider];
      return `${header}\n⚠️ Fell back to quick mode — Reason: ${job.errors[id]}\n🔄 Using: ${quickModel}\n\n${job.results[id]}`;
    }
    const deepModel = DEEP_MODEL_NAMES[agent.provider];
    return `${header}\n🔬 Deep Research (${deepModel})\n\n${job.results[id]}`;
  });
  if (job.synthesis) parts.push(`## Synthesis\n${job.synthesis}`);
  return parts.join('\n\n');
}

// --- MCP Server ---
function createMcpServer() {
  const server = new McpServer({ name: 'a-team-console', version: '5.6.0' });

  // Helper: call a single agent synchronously (quick mode only)
  async function consultAgentQuick(agentId, query) {
    const agent = AGENTS[agentId];
    const callFn = PROVIDERS[agent.provider];
    return callFn(agent.systemPrompt, query);
  }

  // --- consult_team ---
  server.registerTool('consult_team', {
    title: 'Consult A-Team',
    description: 'Consult all 4 AI agents (Claude, ChatGPT, Gemini, Grok) and get a synthesis. Quick mode returns immediately. Deep mode starts background research and returns a job_id — use get_research_results to retrieve results.',
    inputSchema: z.object({
      query: z.string().describe('The question or topic to consult the team about'),
      mode: modeSchema
    })
  }, async ({ query, mode }) => {
    if (mode === 'deep') {
      const jobId = startDeepJob('consult_team', query, ['claude', 'chatgpt', 'gemini', 'grok']);
      return { content: [{ type: 'text', text: `Deep research started. Job ID: ${jobId}\n\nAll 4 agents (Claude, ChatGPT, Gemini, Grok) are researching in background. This typically takes 5-10 minutes.\n\nUse get_research_results with job_id "${jobId}" to check progress and retrieve results.` }] };
    }

    // Quick mode — synchronous
    console.log('consult_team called in quick mode');
    const results = {};
    const errors = {};
    const agentIds = ['claude', 'chatgpt', 'gemini', 'grok'];
    await Promise.all(agentIds.map(async (id) => {
      try { results[id] = await consultAgentQuick(id, query); }
      catch (e) { errors[id] = e.message; }
    }));

    const allResponses = agentIds
      .filter(id => results[id])
      .map(id => `${AGENTS[id].name} (${AGENTS[id].role}):\n${results[id]}`)
      .join('\n\n');

    let synthesis = '';
    try {
      const synthPrompt = `You are the Principal Architect synthesizing four analyst reports. Provide a clear, comprehensive synthesis: identify consensus, highlight important disagreements and which side has stronger evidence, note gaps, and give your recommendation. Write in authoritative prose paragraphs. Aim for 500-800 words. Start with "SYNTHESIS:" on its own line.`;
      synthesis = await callAnthropicDeep(synthPrompt, query + '\n\nTeam responses:\n' + allResponses);
    } catch (e) { synthesis = `Synthesis error: ${e.message}`; }

    const parts = agentIds.map(id => {
      const header = `## ${AGENTS[id].name} (${AGENTS[id].role})`;
      return results[id] ? `${header}\n${results[id]}` : `${header}\nError: ${errors[id]}`;
    });
    parts.push(`## Synthesis\n${synthesis}`);
    return { content: [{ type: 'text', text: parts.join('\n\n') }] };
  });

  // --- Individual agent tools ---
  const agentTools = [
    { id: 'claude', tool: 'consult_claude', title: 'Consult Claude', desc: 'Consult Claude (Anthropic) — Principal Architect & Team Lead. Deep mode uses Claude Opus with 30K-token extended thinking and unlimited multi-step web search.' },
    { id: 'chatgpt', tool: 'consult_chatgpt', title: 'Consult ChatGPT', desc: 'Consult ChatGPT (OpenAI) — Financial Research Analyst. Deep mode uses o3-deep-research-2025-06-26 with background web research, reasoning summaries, and code interpreter.' },
    { id: 'gemini', tool: 'consult_gemini', title: 'Consult Gemini', desc: 'Consult Gemini (Google) — Data Analyst & Ranker. Deep mode uses Gemini Deep Research agent.' },
    { id: 'grok', tool: 'consult_grok', title: 'Consult Grok', desc: "Consult Grok (xAI) — Devil's Advocate & Risk Analyst. Deep mode uses Grok 4.1 Fast Reasoning with web search, X search, and code execution (full DeepSearch)." }
  ];

  for (const at of agentTools) {
    server.registerTool(at.tool, {
      title: at.title,
      description: at.desc + ' Quick mode returns immediately. Deep mode returns a job_id — use get_research_results to retrieve results.',
      inputSchema: z.object({
        query: z.string().describe(`The question to ask ${AGENTS[at.id].name}`),
        mode: modeSchema
      })
    }, async ({ query, mode }) => {
      if (mode === 'deep') {
        const jobId = startDeepJob(at.tool, query, [at.id]);
        return { content: [{ type: 'text', text: `Deep research started. Job ID: ${jobId}\n\n${AGENTS[at.id].name} is researching in background. This may take a few minutes.\n\nUse get_research_results with job_id "${jobId}" to check progress and retrieve results.` }] };
      }
      const response = await consultAgentQuick(at.id, query);
      return { content: [{ type: 'text', text: response }] };
    });
  }

  // --- get_research_results ---
  server.registerTool('get_research_results', {
    title: 'Get Research Results',
    description: 'Check the status of a deep research job and retrieve results when ready. Use the job_id returned by any consult tool in deep mode.',
    inputSchema: z.object({
      job_id: z.string().describe('The job ID returned by a deep mode consult tool')
    })
  }, async ({ job_id }) => {
    const job = deepJobs.get(job_id);
    if (!job) {
      return { content: [{ type: 'text', text: `Job not found: ${job_id}\n\nThe job may have expired (results are kept for 1 hour) or the server may have restarted.` }] };
    }

    if (job.status === 'synthesizing') {
    const results = {};
    for (const id of job.agentIds) {
      results[id] = {
        response: job.results[id] || null,
        mode: job.modes[id] || null,
        error: job.errors[id] || null
      };
    }
    return res.json({ status: 'synthesizing', elapsed, results, costs: job.costs || {}, progress: Object.fromEntries(job.agentIds.map(id => [id, { status: 'done', mode: job.modes[id] }])) });
  }

  if (job.status === 'researching') {
      const elapsed = ((Date.now() - job.createdAt) / 1000).toFixed(0);
      const done = Object.keys(job.results).length;
      const failed = Object.keys(job.errors).length;
      const total = job.agentIds.length;
      const pending = total - done - failed;

      let progress = `Research in progress (${elapsed}s elapsed)\n\n`;
      progress += `Agents: ${done}/${total} completed`;
      if (failed > 0) progress += `, ${failed} failed`;
      if (pending > 0) progress += `, ${pending} still working`;
      progress += '\n\n';

      for (const id of job.agentIds) {
        if (job.results[id]) {
          const modeLabel = job.modes[id] === 'fallback' ? '⚠️ Fell back to quick' : '🔬 Deep';
          progress += `- ${AGENTS[id].name}: Done (${modeLabel})\n`;
        } else if (job.modes[id] === 'failed') {
          progress += `- ${AGENTS[id].name}: ❌ Failed\n`;
        } else {
          progress += `- ${AGENTS[id].name}: Researching...\n`;
        }
      }

      if (job.agentIds.length > 1) progress += `- Synthesis: Waiting for all agents\n`;
      progress += `\nCheck again in a minute or two.`;

      return { content: [{ type: 'text', text: progress }] };
    }

    if (job.status === 'completed') {
      const elapsed = ((job.completedAt - job.createdAt) / 1000).toFixed(1);
      const header = `Deep research completed in ${elapsed}s\nTool: ${job.tool} | Query: "${job.query.substring(0, 100)}"\n\n`;
      return { content: [{ type: 'text', text: header + formatJobResults(job) }] };
    }

    return { content: [{ type: 'text', text: `Job ${job_id} status: ${job.status}` }] };
  });

  // --- run_command ---
  server.registerTool('run_command', {
    title: 'Run Command',
    description: 'Execute a bash command on the server and return stdout/stderr. 30 second timeout.',
    inputSchema: z.object({
      command: z.string().describe('The bash command to execute')
    })
  }, async ({ command }) => {
    try {
      const stdout = execSync(command, { timeout: 30000, encoding: 'utf-8', maxBuffer: 1024 * 1024 });
      return { content: [{ type: 'text', text: stdout || '(no output)' }] };
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      return { content: [{ type: 'text', text: `Exit code: ${e.status}\n${output || e.message}` }], isError: true };
    }
  });

  // --- read_file ---
  server.registerTool('read_file', {
    title: 'Read File',
    description: 'Read the contents of a file and return it as text.',
    inputSchema: z.object({
      path: z.string().describe('The file path to read')
    })
  }, async ({ path: filePath }) => {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return { content: [{ type: 'text', text: content }] };
    } catch (e) {
      return { content: [{ type: 'text', text: `Error reading file: ${e.message}` }], isError: true };
    }
  });

  // --- write_file ---
  server.registerTool('write_file', {
    title: 'Write File',
    description: 'Write content to a file. Creates the file if it does not exist, overwrites if it does.',
    inputSchema: z.object({
      path: z.string().describe('The file path to write to'),
      content: z.string().describe('The content to write')
    })
  }, async ({ path: filePath, content }) => {
    try {
      fs.writeFileSync(filePath, content, 'utf-8');
      return { content: [{ type: 'text', text: `File written: ${filePath}` }] };
    } catch (e) {
      return { content: [{ type: 'text', text: `Error writing file: ${e.message}` }], isError: true };
    }
  });


  // --- journal_read: Read persistent memory ---
  server.registerTool('journal_read', {
    title: 'Read Journal',
    description: 'Read persistent memory entries from the database. Call this at the start of every new session to orient yourself. Returns all key-value pairs stored across sessions.',
    inputSchema: z.object({
      key: z.string().optional().describe('Optional specific key to read. Omit to read all entries.')
    })
  }, async ({ key }) => {
    if (!pool) return { content: [{ type: 'text', text: 'No database configured' }], isError: true };
    try {
      let res;
      if (key) {
        res = await pool.query('SELECT key, value, updated_at FROM journal WHERE key = $1', [key]);
      } else {
        res = await pool.query('SELECT key, value, updated_at FROM journal ORDER BY id');
      }
      if (res.rows.length === 0) return { content: [{ type: 'text', text: key ? 'Key not found: ' + key : 'Journal is empty' }] };
      const entries = res.rows.map(r => r.key + ': ' + r.value + ' (updated: ' + r.updated_at.toISOString().substring(0, 16) + ')').join('\n');
      return { content: [{ type: 'text', text: entries }] };
    } catch (e) {
      return { content: [{ type: 'text', text: 'DB error: ' + e.message }], isError: true };
    }
  });

  // --- journal_write: Write persistent memory ---
  server.registerTool('journal_write', {
    title: 'Write Journal',
    description: 'Write or update a persistent memory entry in the database. Use this to save important context, decisions, session summaries, and anything the next session should know.',
    inputSchema: z.object({
      key: z.string().describe('The key name (e.g. last_session, architecture, next_priorities)'),
      value: z.string().describe('The value to store')
    })
  }, async ({ key, value }) => {
    if (!pool) return { content: [{ type: 'text', text: 'No database configured' }], isError: true };
    try {
      await pool.query(
        'INSERT INTO journal (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()',
        [key, value]
      );
      return { content: [{ type: 'text', text: 'Saved: ' + key }] };
    } catch (e) {
      return { content: [{ type: 'text', text: 'DB error: ' + e.message }], isError: true };
    }
  });

  return server;
}

// =====================================================
// ROUTES
// =====================================================

// --- Unprotected: Health check ---
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// --- Unprotected: Auth routes ---
app.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) return res.redirect('/login');
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    if (!isEmailAllowed(req.user?.email)) {
      return req.logout(() => res.redirect('/denied'));
    }
    res.redirect('/');
  }
);

app.get('/auth/microsoft', (req, res, next) => {
  if (!process.env.MICROSOFT_CLIENT_ID) return res.redirect('/login');
  passport.authenticate('microsoft')(req, res, next);
});

app.get('/auth/microsoft/callback',
  passport.authenticate('microsoft', { callback: true, failureRedirect: '/login' }),
  (req, res) => {
    if (!isEmailAllowed(req.user?.email)) {
      return req.logout(() => res.redirect('/denied'));
    }
    res.redirect('/');
  }
);

app.get('/auth/logout', (req, res) => {
  let done = false;
  const finish = () => { if (!done) { done = true; res.clearCookie('ateam.sid'); res.redirect('/login'); } };
  setTimeout(finish, 5000);
  req.logout(function(err) {
    if (err) return finish();
    req.session.destroy(function() { finish(); });
  });
});

// --- Unprotected: Login page ---
app.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// --- Unprotected: Access denied page ---
app.get('/denied', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'denied.html'));
});

// --- Unprotected: User info ---
app.get('/api/me', (req, res) => {
  if (req.isAuthenticated()) return res.json(req.user);
  res.status(401).json({ error: 'Not authenticated' });
});

// --- Unprotected: MCP endpoints ---
app.post('/mcp', async (req, res) => {
  const server = createMcpServer();
  try {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    res.on('close', () => { transport.close(); server.close(); });
  } catch (err) {
    console.error('MCP error:', err);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
    }
  }
});

app.get('/mcp', (req, res) => {
  res.writeHead(405).end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null }));
});

app.delete('/mcp', (req, res) => {
  res.writeHead(405).end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null }));
});

// --- Auth middleware: protect everything below ---
app.use((req, res, next) => {
  if (!oauthConfigured) return next();
  if (req.isAuthenticated()) return next();
  if (req.path.startsWith('/sniper')) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
});

// --- Protected: Static files ---
app.use(express.static(path.join(__dirname, 'public')));

// --- Protected: API routes ---
app.get('/api/health', (req, res) => {
  const keys = {
    anthropic: !!process.env.ANTHROPIC_API_KEY,
    openai: !!process.env.OPENAI_API_KEY,
    google: !!process.env.GOOGLE_AI_API_KEY,
    xai: !!process.env.XAI_API_KEY
  };
  res.json({ status: 'ok', providers: keys });
});

app.post('/api/consult', async (req, res) => {
  try {
    const { agentId, query, priorResponses, mode, agentModes, activeAgents, consolidatorMode } = req.body;

    // Team mode (deep or mixed): start background job with per-agent config
    if (mode === 'team') {
      const agents = activeAgents || ['claude', 'chatgpt', 'gemini', 'grok'];
      const modes = agentModes || {};
      const consMode = consolidatorMode || 'quick';
      const jobId = startDeepJob('web_consult', query, agents, modes, consMode);
      return res.json({ jobId });
    }

    // Legacy deep mode: all agents deep
    if (mode === 'deep') {
      const jobId = startDeepJob('web_consult', query, ['claude', 'chatgpt', 'gemini', 'grok']);
      return res.json({ jobId });
    }

    // Quick mode (default)
    const agent = AGENTS[agentId];
    if (!agent) return res.status(400).json({ error: 'Unknown agent' });

    const contextMsg = priorResponses
      ? `\n\nHere is what the other consultants have said so far:\n${priorResponses}\n\nNow give YOUR perspective on the user's question. Agree or disagree with the others as you see fit.`
      : '';

    const callFn = PROVIDERS[agent.provider];
    const response = await callFn(agent.systemPrompt, query + contextMsg);

    res.json({ agentId, response });
  } catch (err) {
    console.error(`Agent error:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/synthesize', async (req, res) => {
  try {
    const { query, allResponses, mode } = req.body;
    let response;
    
    if (mode === 'deep') {
      const synthPrompt = `You are a senior research analyst producing a comprehensive synthesis report from four independent AI analysts. VERIFY claims via web search, CROSS-REFERENCE findings, FILL GAPS with your own research, RESOLVE CONFLICTS using primary sources, and SYNTHESIZE into a definitive analysis. Include: Executive Summary, Areas of Consensus, Key Disagreements and Resolution, Critical Gaps, Risk Factors, Final Recommendation, and Sources. Write in authoritative prose, 1500-3000 words. Start with "SYNTHESIS REPORT" header.`;
      response = await callOpenAIDeep(synthPrompt, `ORIGINAL QUESTION: ${query}\n\n--- ANALYST REPORTS ---\n\n${allResponses}`);
    } else {
      const synthPrompt = `You are the Principal Architect synthesizing analyst reports. Provide a clear, comprehensive synthesis: identify consensus, highlight important disagreements, note gaps, give your recommendation. Write in authoritative prose, 500-800 words. Start with "SYNTHESIS:" on its own line.`;
      response = await callAnthropicDeep(synthPrompt, `ORIGINAL QUESTION: ${query}\n\n--- ANALYST REPORTS ---\n\n${allResponses}`);
    }
    res.json({ response });
  } catch (err) {
    console.error('Synthesis error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/results/:jobId', (req, res) => {
  const job = deepJobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  const elapsed = +((Date.now() - job.createdAt) / 1000).toFixed(0);

  if (job.status === 'researching') {
    const progress = {};
    for (const id of job.agentIds) {
      if (job.results[id]) progress[id] = { status: 'done', mode: job.modes[id] };
      else if (job.modes[id] === 'failed') progress[id] = { status: 'failed', error: job.errors[id] };
      else progress[id] = { status: 'researching' };
    }
    return res.json({ status: 'researching', elapsed, progress, costs: job.costs || {} });
  }

  if (job.status === 'completed') {
    const results = {};
    for (const id of job.agentIds) {
      results[id] = {
        response: job.results[id] || null,
        mode: job.modes[id] || null,
        error: job.errors[id] || null
      };
    }
    return res.json({
      status: 'completed',
      elapsed: +((job.completedAt - job.createdAt) / 1000).toFixed(1),
      results,
      synthesis: job.synthesis,
      costs: job.costs || {},
      synthesisCost: job.synthesisCost || null,
      consolidatorMode: job.consolidatorMode || 'deep'
    });
  }

  res.json({ status: job.status, elapsed });
});

// --- Cost Estimation ---
app.post('/api/estimate', (req, res) => {
  const { query, agentModes, consolidatorMode } = req.body;
  // Estimate tokens from query length (rough: 1 token ≈ 4 chars)
  const queryTokens = Math.ceil((query || '').length / 4);
  
  const ESTIMATES = {
    claude:  { quick: { input: 2200 + queryTokens, output: 500,  model: 'claude-sonnet-4-20250514' },
               deep:  { input: 5000 + queryTokens, output: 46000, model: 'claude-opus-4-6' } },  // 16K response + 30K thinking
    chatgpt: { quick: { input: 500 + queryTokens,  output: 500,  model: 'gpt-4o-mini' },
               deep:  { input: 2000 + queryTokens,  output: 5000, model: 'o3-deep-research-2025-06-26' } },
    gemini:  { quick: { input: 200 + queryTokens,   output: 500,  model: 'gemini-2.5-flash-lite' },
               deep:  { input: 2000 + queryTokens,  output: 8000, model: 'deep-research-pro-preview-12-2025' } },
    grok:    { quick: { input: 2500 + queryTokens,  output: 500,  model: 'grok-4-1-fast-non-reasoning' },
               deep:  { input: 5000 + queryTokens,  output: 5000, model: 'grok-4-1-fast-reasoning' } }
  };
  
  const SYNTH_ESTIMATES = {
    quick: { input: 12000, output: 4000, model: 'claude-opus-4-6' },  // ingests all quick responses
    deep:  { input: 150000, output: 8000, model: 'o3-deep-research-2025-06-26' }  // ingests all deep responses
  };
  
  const modes = agentModes || {};
  const estimates = {};
  let total = 0;
  
  for (const [agent, mode] of Object.entries(modes)) {
    if (mode === 'off') { estimates[agent] = { cost: 0, mode: 'off' }; continue; }
    const est = ESTIMATES[agent]?.[mode] || ESTIMATES[agent]?.quick;
    if (est) {
      const cost = calcCost(est.model, est.input, est.output);
      estimates[agent] = { cost: +cost.toFixed(6), mode, model: est.model, input: est.input, output: est.output };
      total += cost;
    }
  }
  
  // Consolidator estimate (only if 2+ agents active)
  const activeCount = Object.values(modes).filter(m => m !== 'off').length;
  const consMode = consolidatorMode || 'quick';
  let synthEstimate = null;
  if (activeCount > 1) {
    const se = SYNTH_ESTIMATES[consMode];
    const synthCost = calcCost(se.model, se.input * (activeCount / 4), se.output);
    synthEstimate = { cost: +synthCost.toFixed(6), mode: consMode, model: se.model };
    total += synthCost;
  }
  
  res.json({ estimates, consolidator: synthEstimate, total: +total.toFixed(6) });
});

// --- API Usage & Cost Tracking ---
app.get('/api/usage', async (req, res) => {
  if (!pool) return res.json({ error: 'No database' });
  try {
    const { rows: summary } = await pool.query(`
      SELECT 
        agent,
        mode,
        COUNT(*) as calls,
        SUM(input_tokens) as total_input,
        SUM(output_tokens) as total_output,
        SUM(thinking_tokens) as total_thinking,
        SUM(search_count) as total_searches,
        ROUND(SUM(cost_usd)::numeric, 4) as total_cost,
        ROUND(AVG(cost_usd)::numeric, 4) as avg_cost_per_call,
        ROUND(AVG(duration_ms)::numeric, 0) as avg_duration_ms
      FROM api_usage
      GROUP BY agent, mode
      ORDER BY total_cost DESC
    `);
    
    const { rows: today } = await pool.query(`
      SELECT 
        ROUND(SUM(cost_usd)::numeric, 4) as today_cost,
        COUNT(*) as today_calls
      FROM api_usage
      WHERE ts >= CURRENT_DATE
    `);
    
    const { rows: total } = await pool.query(`
      SELECT 
        ROUND(SUM(cost_usd)::numeric, 4) as total_cost,
        COUNT(*) as total_calls,
        SUM(input_tokens) as total_input_tokens,
        SUM(output_tokens) as total_output_tokens,
        MIN(ts) as tracking_since
      FROM api_usage
    `);
    
    const { rows: recent } = await pool.query(`
      SELECT agent, model, mode, input_tokens, output_tokens, thinking_tokens, 
             ROUND(cost_usd::numeric, 4) as cost, duration_ms, context,
             to_char(ts AT TIME ZONE 'America/New_York', 'MM/DD HH12:MI AM') as time_est
      FROM api_usage 
      ORDER BY ts DESC 
      LIMIT 20
    `);
    
    res.json({ summary, today: today[0], total: total[0], recent });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// =====================================================
// PUGOVKA SHIFT SNIPER v1.0 — Built by Superman 🎯
// =====================================================
const sniper = {
  token: null, mfaToken: null, tokenIssuedAt: null, isPolling: false,
  lastPoll: null, lastError: null, shiftsFound: 0, shiftsClaimed: 0,
  claimLog: [], status: 'AWAITING_AUTH', pollTimer: null,
  config: {
    email: 'e.culicova@gmail.com', password: 'Pugovka21!',
    userId: 51858669, accountId: 416877,
    targets: { 679251:'New York City', 820177:'New Jersey', 4181321:'Long Island', 4181326:'New York North' },
    pollInterval: 10000, loginHost: 'api.login.wheniwork.com', apiHost: 'api.wheniwork.com'
  }
};

function sniperLog(msg) {
  const ts = new Date().toLocaleString('en-US', { timeZone: 'America/New_York' });
  const entry = `[${ts}] ${msg}`;
  console.log('SNIPER: ' + entry);
  sniper.claimLog.unshift(entry);
  if (sniper.claimLog.length > 200) sniper.claimLog.length = 200;
}

function sniperApi(host, path, method, headers, body) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: host, path, method, headers: headers || {} };
    const req = require('https').request(opts, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch(e) { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

function sniperHeaders() {
  return {
    'Authorization': sniper.token, 'W-Token': sniper.token,
    'W-UserId': String(sniper.config.userId), 'W-Date-Format': 'iso',
    'Content-Type': 'application/json',
    'Origin': 'https://appx.wheniwork.com', 'Referer': 'https://appx.wheniwork.com/'
  };
}

async function sniperLogin() {
  sniperLog('Starting login...');
  try {
    const res = await sniperApi(sniper.config.loginHost, '/login', 'POST',
      { 'content-type': 'application/json' },
      JSON.stringify({ email: sniper.config.email, password: sniper.config.password }));
    if (res.data?.errors?.[0]?.code === 'MFA_CODE_REQUIRED') {
      sniper.mfaToken = res.data.data.mfa_token;
      sniper.status = 'AWAITING_MFA';
      sniperLog('MFA required — waiting for code');
      return { needsMfa: true };
    } else if (res.data?.data?.token) {
      sniper.token = res.data.data.token;
      sniper.tokenIssuedAt = Date.now();
      sniper.status = 'ACTIVE';
      sniperLog('Logged in (no MFA)');
      startSniperPolling();
      return { success: true };
    }
    sniper.status = 'ERROR'; sniper.lastError = JSON.stringify(res.data);
    return { error: res.data };
  } catch(e) { sniper.status = 'ERROR'; sniper.lastError = e.message; return { error: e.message }; }
}

async function sniperMfa(code) {
  sniperLog('Submitting MFA code: ' + code);
  try {
    const res = await sniperApi(sniper.config.loginHost, '/enter/' + code, 'GET',
      { 'Authorization': 'Bearer ' + sniper.mfaToken, 'content-type': 'application/json' });
    if (res.status === 200) {
      const tokenStr = JSON.stringify(res.data);
      const tokenMatch = tokenStr.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
      if (tokenMatch || res.data?.data?.token) {
        sniper.token = res.data?.data?.token || tokenMatch[0];
        sniper.tokenIssuedAt = Date.now();
        sniper.status = 'ACTIVE';
        sniperLog('MFA verified — SNIPER ACTIVE!');
        startSniperPolling();
        return { success: true };
      }
    }
    sniper.lastError = 'MFA failed: ' + JSON.stringify(res.data).substring(0, 200);
    sniperLog(sniper.lastError);
    return { error: sniper.lastError };
  } catch(e) { sniper.lastError = e.message; return { error: e.message }; }
}

function startSniperPolling() {
  if (sniper.isPolling) return;
  sniper.isPolling = true;
  sniperLog('SNIPER ACTIVATED — polling every ' + (sniper.config.pollInterval/1000) + 's');
  sniperPoll();
  sniper.pollTimer = setInterval(sniperPoll, sniper.config.pollInterval);
}

function stopSniperPolling() {
  sniper.isPolling = false;
  if (sniper.pollTimer) clearInterval(sniper.pollTimer);
  sniper.status = 'PAUSED';
  sniperLog('Sniper PAUSED');
}

async function sniperPoll() {
  try {
    const now = new Date();
    const start = now.toISOString();
    const end = new Date(now.getTime() + 90*24*60*60*1000).toISOString();
    const path = `/2/shifts?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}&all_locations=true&include_allopen=true&include_swaps=true&unpublished=false&include_objects=false&limit_by_rules=true&role=employee&trim_openshifts=false`;
    const res = await sniperApi(sniper.config.apiHost, path, 'GET', sniperHeaders());
    if (res.status === 401) { sniperLog('Token expired — need re-auth'); sniper.status = 'AWAITING_AUTH'; stopSniperPolling(); return; }
    if (res.status !== 200 || !res.data?.shifts) { sniper.lastError = 'Poll failed: ' + res.status; return; }
    sniper.lastPoll = new Date().toISOString();
    const open = res.data.shifts.filter(s => s.is_open && s.user_id === 0 && sniper.config.targets[s.location_id]);
    sniper.shiftsFound = open.length;
    if (open.length > 0) {
      sniperLog('FOUND ' + open.length + ' OPEN SHIFT(S)!');
      for (const shift of open) await sniperClaim(shift);
    }
  } catch(e) { sniper.lastError = 'Poll error: ' + e.message; }
}

async function sniperClaim(shift) {
  const loc = sniper.config.targets[shift.location_id] || 'Unknown';
  sniperLog('SNIPING shift ' + shift.id + ' at ' + loc + ' (' + shift.start_time + ' - ' + shift.end_time + ')');
  try {
    const claimData = Object.assign({}, shift, { user_id: sniper.config.userId });
    const res = await sniperApi(sniper.config.apiHost,
      '/2/shifts/' + shift.id + '?assign_openshift_instances=true',
      'PUT', sniperHeaders(), JSON.stringify(claimData));
    if (res.status === 200) {
      sniper.shiftsClaimed++;
      sniperLog('SHIFT CLAIMED! ' + loc + ' | ' + shift.start_time + ' -> ' + shift.end_time);
    } else {
      sniperLog('Claim failed (' + res.status + '): ' + JSON.stringify(res.data).substring(0, 300));
    }
  } catch(e) { sniperLog('Claim error: ' + e.message); }
}

// Sniper Web UI
const SNIPER_HTML = `<!DOCTYPE html><html><head><title>Pugovka Shift Sniper</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;padding:20px}.c{max-width:700px;margin:0 auto}h1{color:#ff4081;margin-bottom:5px;font-size:28px}.sub{color:#888;margin-bottom:30px}.card{background:#1a1a1a;border-radius:12px;padding:20px;margin-bottom:16px;border:1px solid #333}.st{font-size:20px;font-weight:bold;padding:15px;text-align:center;border-radius:8px;margin-bottom:20px}.st.a{background:#1b5e20;color:#4caf50;border:1px solid #4caf50}.st.w{background:#4a3800;color:#ffc107;border:1px solid #ffc107}.st.e{background:#4a0000;color:#f44336;border:1px solid #f44336}.st.p{background:#1a237e;color:#5c6bc0;border:1px solid #5c6bc0}input{width:100%;padding:14px;font-size:24px;text-align:center;border-radius:8px;border:2px solid #555;background:#222;color:#fff;letter-spacing:8px;margin:10px 0}button{width:100%;padding:14px;font-size:18px;font-weight:bold;border-radius:8px;border:none;cursor:pointer;margin:5px 0}.bp{background:#ff4081;color:#fff}.bp:hover{background:#e91e63}.bd{background:#f44336;color:#fff}.bs{background:#4caf50;color:#fff}.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin:15px 0}.stat{text-align:center;padding:10px;background:#222;border-radius:8px}.stat .n{font-size:28px;font-weight:bold;color:#ff4081}.stat .l{font-size:12px;color:#888;margin-top:4px}.log{max-height:400px;overflow-y:auto;font-family:monospace;font-size:12px;padding:10px;background:#111;border-radius:8px}.log div{padding:3px 0;border-bottom:1px solid #1a1a1a}.tg{display:flex;flex-wrap:wrap;gap:8px}.t{background:#222;padding:6px 12px;border-radius:20px;font-size:13px;border:1px solid #444}#msg{text-align:center;padding:10px;margin:10px 0;border-radius:8px;display:none}</style></head><body><div class="c"><h1>Pugovka Shift Sniper</h1><p class="sub">Built by Superman for Pugovka</p><div id="sb" class="st w">Loading...</div><div id="mfa" class="card" style="display:none"><h3>Enter MFA Code</h3><p style="color:#888;margin:8px 0">Check Katya's phone for the 6-digit code</p><input type="text" id="mc" maxlength="6" placeholder="000000" autocomplete="off"><button class="bp" onclick="doMfa()">Submit Code</button><div id="msg"></div></div><div id="auth" class="card" style="display:none"><button class="bp" onclick="doLogin()">Login &amp; Start Sniper</button></div><div id="ctrl" class="card" style="display:none"><button class="bd" onclick="doStop()" id="stopB">Pause Sniper</button><button class="bs" onclick="doResume()" id="resB" style="display:none">Resume Sniper</button></div><div class="card"><h3>Stats</h3><div class="stats"><div class="stat"><div class="n" id="cl">0</div><div class="l">Shifts Claimed</div></div><div class="stat"><div class="n" id="fo">0</div><div class="l">Open Now</div></div><div class="stat"><div class="n" id="lp">-</div><div class="l">Last Poll</div></div></div></div><div class="card"><h3>Target Locations</h3><div class="tg" style="margin-top:10px"><span class="t">New York City</span><span class="t">New Jersey</span><span class="t">Long Island</span><span class="t">New York North</span></div></div><div class="card"><h3>Activity Log</h3><div class="log" id="lg"></div></div></div><script>async function tick(){try{const r=await fetch('/sniper/api/status');const d=await r.json();document.getElementById('cl').textContent=d.shiftsClaimed;document.getElementById('fo').textContent=d.shiftsFound;document.getElementById('lp').textContent=d.lastPoll?new Date(d.lastPoll).toLocaleTimeString():'-';const b=document.getElementById('sb'),m=document.getElementById('mfa'),a=document.getElementById('auth'),c=document.getElementById('ctrl');if(d.status==='ACTIVE'){b.className='st a';b.textContent='SNIPER ACTIVE';m.style.display='none';a.style.display='none';c.style.display='block';document.getElementById('stopB').style.display='block';document.getElementById('resB').style.display='none'}else if(d.status==='AWAITING_MFA'){b.className='st w';b.textContent='WAITING FOR MFA CODE';m.style.display='block';a.style.display='none';c.style.display='none'}else if(d.status==='AWAITING_AUTH'){b.className='st w';b.textContent='NEED TO LOGIN';m.style.display='none';a.style.display='block';c.style.display='none'}else if(d.status==='PAUSED'){b.className='st p';b.textContent='SNIPER PAUSED';m.style.display='none';a.style.display='none';c.style.display='block';document.getElementById('stopB').style.display='none';document.getElementById('resB').style.display='block'}else{b.className='st e';b.textContent='ERROR: '+(d.lastError||'Unknown');a.style.display='block';m.style.display='none'}document.getElementById('lg').innerHTML=d.log.map(l=>'<div>'+l+'</div>').join('')}catch(e){}}async function doLogin(){await fetch('/sniper/api/login',{method:'POST'});tick()}async function doMfa(){const c=document.getElementById('mc').value.trim();if(c.length!==6)return;const r=await fetch('/sniper/api/mfa',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code:c})});const d=await r.json();const m=document.getElementById('msg');m.style.display='block';m.textContent=d.success?'Authenticated!':'Failed: '+(d.error||'');m.style.background=d.success?'#1b5e20':'#4a0000';m.style.color=d.success?'#4caf50':'#f44336';tick()}async function doStop(){await fetch('/sniper/api/stop',{method:'POST'});tick()}async function doResume(){await fetch('/sniper/api/resume',{method:'POST'});tick()}document.getElementById('mc').addEventListener('input',function(e){if(e.target.value.length===6)doMfa()});tick();setInterval(tick,3000)</script></body></html>`;

// Sniper Routes (unprotected — needs to work without OAuth)
app.get('/sniper', (req, res) => { res.writeHead(200, {'Content-Type':'text/html'}); res.end(SNIPER_HTML); });
app.get('/sniper/api/status', (req, res) => {
  res.json({ status: sniper.status, isPolling: sniper.isPolling, lastPoll: sniper.lastPoll,
    lastError: sniper.lastError, shiftsFound: sniper.shiftsFound, shiftsClaimed: sniper.shiftsClaimed,
    tokenAge: sniper.tokenIssuedAt ? Math.round((Date.now()-sniper.tokenIssuedAt)/3600000)+'h' : null,
    log: sniper.claimLog.slice(0, 50) });
});
app.post('/sniper/api/login', async (req, res) => { res.json(await sniperLogin()); });
app.post('/sniper/api/mfa', async (req, res) => {
  try { res.json(await sniperMfa(req.body.code)); } catch(e) { res.json({error:e.message}); }
});
app.post('/sniper/api/stop', (req, res) => { stopSniperPolling(); res.json({success:true}); });
app.post('/sniper/api/resume', (req, res) => {
  if (sniper.token) { startSniperPolling(); sniper.status = 'ACTIVE'; }
  res.json({success:true});
});

sniperLog('Pugovka Shift Sniper loaded — visit /sniper to activate');

// --- Protected: Catch-all SPA ---
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
const httpServer = app.listen(PORT, () => {
  console.log(`A-Team Console v5.7.1 running on port ${PORT}`);
  console.log('OAuth:', oauthConfigured ? 'enabled' : 'disabled (open access)');
  console.log('Email whitelist:', process.env.ALLOWED_EMAILS ? 'enabled' : 'disabled (allow all)');
  console.log('Providers configured:', {
    anthropic: !!process.env.ANTHROPIC_API_KEY,
    openai: !!process.env.OPENAI_API_KEY,
    google: !!process.env.GOOGLE_AI_API_KEY,
    xai: !!process.env.XAI_API_KEY
  });
  console.log('MCP endpoint: /mcp (deep research mode available)');
});
// 15 minute timeout to accommodate deep research polling
httpServer.timeout = 15 * 60 * 1000;
httpServer.headersTimeout = 15 * 60 * 1000 + 1000;
