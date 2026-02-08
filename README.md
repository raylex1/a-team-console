# A-Team Console v3.0

4 AI consultants providing multi-perspective analysis for the SOXL automated trading system.

## Agents
- **Claude** (Anthropic) — Principal Architect & Team Lead
- **ChatGPT** (OpenAI) — Financial Research Analyst
- **Gemini** (Google) — Data Analyst & Ranker
- **Grok** (xAI) — Devil's Advocate & Risk Analyst

## Environment Variables
Set these in your hosting platform (Railway, etc.):

```
ANTHROPIC_API_KEY=your-key-here
OPENAI_API_KEY=your-key-here
GOOGLE_AI_API_KEY=your-key-here
XAI_API_KEY=your-key-here
```

## Deploy to Railway
1. Connect this repo to Railway
2. Add environment variables in the Variables tab
3. Railway auto-detects Node.js and runs `npm start`

## Local Development
```bash
npm install
ANTHROPIC_API_KEY=xxx OPENAI_API_KEY=xxx GOOGLE_AI_API_KEY=xxx XAI_API_KEY=xxx npm start
```

Visit http://localhost:3000
