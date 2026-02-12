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
        max_tokens: 16000,
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
function startDeepJob(toolName, query, agentIds) {
  const jobId = crypto.randomUUID();
  const job = {
    id: jobId,
    tool: toolName,
    query,
    status: 'researching',
    agentIds,
    results: {},
    errors: {},
    modes: {},
    synthesis: null,
    createdAt: Date.now(),
    completedAt: null
  };
  deepJobs.set(jobId, job);

  // Fire and forget — runs in background
  (async () => {
    try {
      // Call all requested agents in parallel (deep → quick fallback)
      await Promise.all(agentIds.map(async (id) => {
        const agent = AGENTS[id];
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
      }));

      // If team consult, run synthesis
      if (agentIds.length > 1) {
        const allResponses = agentIds
          .filter(id => job.results[id])
          .map(id => `${AGENTS[id].name} (${AGENTS[id].role}):\n${job.results[id]}`)
          .join('\n\n');
        try {
          const synthPrompt = `You are Claude, the Principal Architect. You just heard from all four A-Team members (including yourself). Now provide a brief SYNTHESIS that:
- Identifies where the team agrees
- Highlights the most important disagreements
- Gives your architectural recommendation as team lead
- Is honest about remaining uncertainties

Write in prose paragraphs, no bullet points. Keep it under 150 words. Start with "SYNTHESIS:" on its own line.`;
          job.synthesis = await callAnthropic(synthPrompt, query + '\n\nTeam responses:\n' + allResponses);
        } catch (e) { job.synthesis = `Synthesis error: ${e.message}`; }
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
  const server = new McpServer({ name: 'a-team-console', version: '5.1.1' });

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
      const synthPrompt = `You are Claude, the Principal Architect. You just heard from all four A-Team members (including yourself). Now provide a brief SYNTHESIS that:
- Identifies where the team agrees
- Highlights the most important disagreements
- Gives your architectural recommendation as team lead
- Is honest about remaining uncertainties

Write in prose paragraphs, no bullet points. Keep it under 150 words. Start with "SYNTHESIS:" on its own line.`;
      synthesis = await callAnthropic(synthPrompt, query + '\n\nTeam responses:\n' + allResponses);
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
    const { agentId, query, priorResponses, mode } = req.body;

    // Deep mode: start background job for all agents
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
    const { query, allResponses } = req.body;

    const synthPrompt = `You are Claude, the Principal Architect. You just heard from all four A-Team members (including yourself). Now provide a brief SYNTHESIS that:
- Identifies where the team agrees
- Highlights the most important disagreements
- Gives your architectural recommendation as team lead
- Is honest about remaining uncertainties

Write in prose paragraphs, no bullet points. Keep it under 150 words. Start with "SYNTHESIS:" on its own line.`;

    const response = await callAnthropic(synthPrompt, query + '\n\nTeam responses:\n' + allResponses);
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
    return res.json({ status: 'researching', elapsed, progress });
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
      synthesis: job.synthesis
    });
  }

  res.json({ status: job.status, elapsed });
});

// --- Protected: Catch-all SPA ---
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
const httpServer = app.listen(PORT, () => {
  console.log(`A-Team Console v5.3.0 running on port ${PORT}`);
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
