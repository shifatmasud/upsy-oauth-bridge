# Upsy OAuth Bridge

Cloudflare Worker that completes Upsy OAuth authorization-code flow with PKCE, stores OAuth tokens in a Durable Object, refreshes tokens, and proxies MCP requests to https://upsy.ai/connect.

## Deploy
npx wrangler deploy

## Connect
Open /auth/start on the deployed Worker and authorize Upsy. After the callback completes, configure an MCP client to use /mcp.

## Endpoints
- GET /health — health and OAuth token-store status
- GET /auth/start — starts OAuth authorization
- GET /oauth/callback — OAuth callback
- POST /mcp — proxies MCP requests to Upsy

## Security note
The /mcp endpoint has no bridge-level authentication. Anyone who can reach the URL may attempt to use the connected Upsy session and its granted permissions. Restrict access at the client or network layer before using with sensitive integrations.
