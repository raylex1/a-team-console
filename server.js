const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());
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
      max_tokens: 1000,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }]
    })
  });

  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  return data.content.map(b => b.text || '').join('\n');
}

async function callOpenAI(systemPrompt, userMessage) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new Error('OPENAI_API_KEY not configured');

  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      max_tokens: 1000,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userMessage }
      ]
    })
  });

  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  return data.choices[0].message.content;
}

async function callGoogle(systemPrompt, userMessage) {
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) throw new Error('GOOGLE_AI_API_KEY not configured');

  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ parts: [{ text: userMessage }] }],
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

  const res = await fetch('https://api.x.ai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: 'grok-3-mini-fast',
      max_tokens: 1000,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userMessage }
      ]
    })
  });

  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  return data.choices[0].message.content;
}

// Provider routing
const PROVIDERS = {
  anthropic: callAnthropic,
  openai: callOpenAI,
  google: callGoogle,
  xai: callXAI
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

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`A-Team Console v3.0 running on port ${PORT}`);
  console.log('Providers configured:', {
    anthropic: !!process.env.ANTHROPIC_API_KEY,
    openai: !!process.env.OPENAI_API_KEY,
    google: !!process.env.GOOGLE_AI_API_KEY,
    xai: !!process.env.XAI_API_KEY
  });
});
