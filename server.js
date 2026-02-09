const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const z = require('zod');
const app = express();

app.use(express.json());

// --- Password gate ---
const AUTH_SECRET = crypto.randomBytes(32).toString('hex');

function makeToken() {
  return crypto.createHmac('sha256', AUTH_SECRET).update(process.env.APP_PASSWORD || '').digest('hex');
}

// Auth endpoint
app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (!process.env.APP_PASSWORD) return res.status(500).json({ error: 'APP_PASSWORD not configured' });
  if (password === process.env.APP_PASSWORD) {
    res.cookie('auth_token', makeToken(), { httpOnly: true, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 });
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Wrong password' });
});

// Middleware: protect everything except /api/auth
app.use((req, res, next) => {
  if (req.path === '/api/auth' || req.path === '/mcp') return next();
  if (!process.env.APP_PASSWORD) return next(); // no password set = open access
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, v] = c.trim().split('=');
    if (k) cookies[k] = v;
  });
  if (cookies.auth_token === makeToken()) return next();
  // For API calls, return 401
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  // For page loads, serve the login page
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

// Agent configurations with their real API endpoints
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
      tools: [{ type: 'web_search' }]
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

  async function tryModel(model) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      signal: AbortSignal.timeout(120000),
      body: JSON.stringify({
        model,
        max_tokens: 16000,
        thinking: { type: 'enabled', budget_tokens: 10000 },
        system: systemPrompt,
        tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 5 }],
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
        model: 'o3-deep-research',
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

  const res = await fetch('https://api.x.ai/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    signal: AbortSignal.timeout(120000),
    body: JSON.stringify({
      model: 'grok-4-1-fast',
      input: [
        { role: 'system', content: systemPrompt },
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

// Health check
app.get('/api/health', (req, res) => {
  const keys = {
    anthropic: !!process.env.ANTHROPIC_API_KEY,
    openai: !!process.env.OPENAI_API_KEY,
    google: !!process.env.GOOGLE_AI_API_KEY,
    xai: !!process.env.XAI_API_KEY
  };
  res.json({ status: 'ok', providers: keys });
});

// Consult a single agent
app.post('/api/consult', async (req, res) => {
  try {
    const { agentId, query, priorResponses } = req.body;
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

// Synthesis endpoint (always uses Claude)
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

// --- MCP Server (Streamable HTTP transport) ---
const modeSchema = z.enum(['quick', 'deep']).default('deep').describe('quick = fast models, deep = deep research with extended thinking and web research (default)');

function createMcpServer() {
  const server = new McpServer({ name: 'a-team-console', version: '4.0.0' });

  // Helper: call a single agent by ID, respecting mode
  async function consultAgent(agentId, query, mode) {
    const agent = AGENTS[agentId];
    const providers = mode === 'deep' ? DEEP_PROVIDERS : PROVIDERS;
    const callFn = providers[agent.provider];
    return callFn(agent.systemPrompt, query);
  }

  server.registerTool('consult_team', {
    title: 'Consult A-Team',
    description: 'Consult all 4 AI agents (Claude, ChatGPT, Gemini, Grok) and get a synthesis. Returns all 5 responses. Deep mode uses extended thinking, deep research, and web search — may take several minutes.',
    inputSchema: z.object({
      query: z.string().describe('The question or topic to consult the team about'),
      mode: modeSchema
    })
  }, async ({ query, mode }) => {
    console.log(`consult_team called in ${mode} mode`);
    const results = {};
    const errors = {};
    const agentIds = ['claude', 'chatgpt', 'gemini', 'grok'];
    await Promise.all(agentIds.map(async (id) => {
      try { results[id] = await consultAgent(id, query, mode); }
      catch (e) { errors[id] = e.message; }
    }));

    const allResponses = agentIds
      .filter(id => results[id])
      .map(id => `${AGENTS[id].name} (${AGENTS[id].role}):\n${results[id]}`)
      .join('\n\n');

    // Synthesis always uses quick Claude (summarizing, not researching)
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

  server.registerTool('consult_claude', {
    title: 'Consult Claude',
    description: 'Consult Claude (Anthropic) — Principal Architect & Team Lead. Deep mode uses Claude Opus with extended thinking and web search.',
    inputSchema: z.object({
      query: z.string().describe('The question to ask Claude'),
      mode: modeSchema
    })
  }, async ({ query, mode }) => {
    const response = await consultAgent('claude', query, mode);
    return { content: [{ type: 'text', text: response }] };
  });

  server.registerTool('consult_chatgpt', {
    title: 'Consult ChatGPT',
    description: 'Consult ChatGPT (OpenAI) — Financial Research Analyst. Deep mode uses o3-deep-research with background web research — may take several minutes.',
    inputSchema: z.object({
      query: z.string().describe('The question to ask ChatGPT'),
      mode: modeSchema
    })
  }, async ({ query, mode }) => {
    const response = await consultAgent('chatgpt', query, mode);
    return { content: [{ type: 'text', text: response }] };
  });

  server.registerTool('consult_gemini', {
    title: 'Consult Gemini',
    description: 'Consult Gemini (Google) — Data Analyst & Ranker. Deep mode uses Gemini Deep Research agent — may take several minutes.',
    inputSchema: z.object({
      query: z.string().describe('The question to ask Gemini'),
      mode: modeSchema
    })
  }, async ({ query, mode }) => {
    const response = await consultAgent('gemini', query, mode);
    return { content: [{ type: 'text', text: response }] };
  });

  server.registerTool('consult_grok', {
    title: 'Consult Grok',
    description: "Consult Grok (xAI) — Devil's Advocate & Risk Analyst. Deep mode uses Grok 4.1 Fast with agentic web search.",
    inputSchema: z.object({
      query: z.string().describe('The question to ask Grok'),
      mode: modeSchema
    })
  }, async ({ query, mode }) => {
    const response = await consultAgent('grok', query, mode);
    return { content: [{ type: 'text', text: response }] };
  });

  return server;
}

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

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
const httpServer = app.listen(PORT, () => {
  console.log(`A-Team Console v4.0 running on port ${PORT}`);
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
