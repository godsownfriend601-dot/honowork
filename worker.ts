import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";

export interface Env {
  CLIENT_ID: string;
  TENANT_ID: string; // or "common"
}

const GRAPH_API = "https://graph.microsoft.com/v1.0";

const app = new Hono();

/* ================= SESSION STORE ================= */
/* NOTE: In production, move this to Durable Objects */
const sessions = new Map<string, any>();

/* ================= ROUTES ================= */

app.get("/health", c => c.text("OK"));

/* -------- AUTH LOGIN -------- */

app.get("/auth/login", async c => {
  const verifier = generateVerifier();
  const challenge = await generateChallenge(verifier);
  const sid = crypto.randomUUID();

  sessions.set(sid, { verifier });

  setCookie(c, "sid", sid, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
  });

  const authorizeUrl = new URL(
    `https://login.microsoftonline.com/${c.env.TENANT_ID}/oauth2/v2.0/authorize`,
  );

  authorizeUrl.searchParams.set("client_id", c.env.CLIENT_ID);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("redirect_uri", getRedirectUri(c));
  authorizeUrl.searchParams.set("response_mode", "query");
  authorizeUrl.searchParams.set(
    "scope",
    "openid profile email offline_access User.Read",
  );
  authorizeUrl.searchParams.set("code_challenge", challenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  return c.redirect(authorizeUrl.toString());
});

/* -------- AUTH CALLBACK -------- */

app.get("/auth/callback", async c => {
  const code = c.req.query("code");
  const sid = getCookie(c, "sid");

  if (!code || !sid || !sessions.has(sid)) {
    return c.text("Invalid session", 400);
  }

  const { verifier } = sessions.get(sid);

  const tokenRes = await fetch(
    `https://login.microsoftonline.com/${c.env.TENANT_ID}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: c.env.CLIENT_ID,
        grant_type: "authorization_code",
        code,
        redirect_uri: getRedirectUri(c),
        code_verifier: verifier,
      }),
    },
  );

  const token = await tokenRes.json();

  sessions.set(sid, { token });

  return c.json({ authenticated: true });
});

/* -------- GRAPH API PROXY -------- */

app.all("/api/*", async c => {
  const sid = getCookie(c, "sid");
  if (!sid || !sessions.has(sid)) {
    return c.text("Unauthorized", 401);
  }

  const { token } = sessions.get(sid);

  const graphUrl =
    GRAPH_API +
    c.req.path.replace("/api", "") +
    (c.req.url.includes("?") ? "?" + c.req.url.split("?")[1] : "");

  const graphReq = new Request(graphUrl, {
    method: c.req.method,
    headers: {
      ...Object.fromEntries(c.req.raw.headers),
      Authorization: `Bearer ${token.access_token}`,
    },
    body: c.req.method === "GET" ? undefined : c.req.raw.body,
  });

  return fetch(graphReq);
});

export default app;

/* ================= HELPERS ================= */

function generateVerifier(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

async function generateChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function getRedirectUri(c: any): string {
  return `${new URL(c.req.url).origin}/auth/callback`;
}
