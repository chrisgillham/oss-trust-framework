// .github/scripts/quorum-engine.js
//
// Simple Majority Quorum — Discord Implementation
// ─────────────────────────────────────────────────────────────────────────────
// Integrates with dep-trust-check.yml to gate blocked/quarantined packages
// behind a configurable human quorum before allowing a PR merge exception.
//
// Flow:
//   1. Trust check returns outcome = 'blocked' or 'quarantined'
//   2. This engine posts a quorum request embed to a configured Discord channel
//   3. Quorum members react with ✅ (approve override) or ❌ (deny override)
//   4. On simple majority (>50% of quorum) or deadline expiry the engine:
//      - Updates the Discord embed with the final verdict
//      - Appends a full audit record to Google Sheets
//      - Posts the result back to the GitHub PR as a comment
//      - Exits 0 (override approved) or 1 (override denied / expired)
//
// Configuration — all tunable via environment variables or quorum-config.json:
//   QUORUM_MEMBERS          Comma-separated Discord user IDs eligible to vote
//   QUORUM_THRESHOLD        Fraction required for approval (default 0.5 = >50%)
//   QUORUM_DEADLINE_HOURS   Hours before vote expires (default 24)
//   DISCORD_BOT_TOKEN       Bot token with SEND_MESSAGES + ADD_REACTIONS + READ_MESSAGE_HISTORY
//   DISCORD_CHANNEL_ID      Channel where quorum embeds are posted
//   DISCORD_GUILD_ID        Guild (server) ID
//   SHEETS_CREDENTIALS      Base64-encoded Google service account JSON
//   SHEETS_SPREADSHEET_ID   Spreadsheet to append audit rows to
//   SHEETS_SHEET_NAME       Tab name (default "QuorumAuditLog")
//   PR_TITLE                Pull request title — surfaced in embed as update reason
//   PR_BODY                 Pull request body — surfaced in embed as update reason
//
// Audit record schema (one row per quorum event):
//   quorum_id | package | version | ecosystem | trust_outcome | update_reason |
//   initiated_at | deadline | quorum_size | threshold | approve_count | deny_count |
//   abstain_count | final_verdict | decided_at | decided_by | voter_detail |
//   discord_message_id | github_pr | run_id | override_rationale

"use strict";

const https   = require("https");
const fs      = require("fs");
const crypto  = require("crypto");

// ── Config ────────────────────────────────────────────────────────────────────

function loadConfig() {
  // Prefer quorum-config.json committed to repo; fall back to env vars.
  let fileConfig = {};
  const configPath = ".github/quorum-config.json";
  if (fs.existsSync(configPath)) {
    fileConfig = JSON.parse(fs.readFileSync(configPath, "utf8"));
  }

  const memberString = process.env.QUORUM_MEMBERS || fileConfig.members?.join(",") || "";
  const members = memberString
    .split(",")
    .map((m) => m.trim())
    .filter(Boolean);

  if (members.length === 0) {
    throw new Error(
      "QUORUM_MEMBERS is empty. Set it to a comma-separated list of Discord user IDs."
    );
  }

  return {
    members,                                                    // Discord user ID strings
    threshold:     parseFloat(process.env.QUORUM_THRESHOLD    || fileConfig.threshold    || "0.5"),
    deadlineHours: parseInt(  process.env.QUORUM_DEADLINE_HOURS || fileConfig.deadlineHours || "24", 10),
    discord: {
      token:      requireEnv("DISCORD_BOT_TOKEN"),
      channelId:  requireEnv("DISCORD_CHANNEL_ID"),
      guildId:    requireEnv("DISCORD_GUILD_ID"),
    },
    sheets: {
      credentials:    process.env.SHEETS_CREDENTIALS      || null,  // base64 JSON
      spreadsheetId:  process.env.SHEETS_SPREADSHEET_ID   || null,
      sheetName:      process.env.SHEETS_SHEET_NAME        || "QuorumAuditLog",
    },
    github: {
      token:    requireEnv("GITHUB_TOKEN"),
      repo:     process.env.GITHUB_REPOSITORY || "",
      prNumber: process.env.PR_NUMBER         || "",
      runId:    process.env.GITHUB_RUN_ID      || "",
      serverUrl: process.env.GITHUB_SERVER_URL || "https://github.com",
      // PR title + body are passed in as env vars by the workflow.
      // Together they form the stated reason for the dependency update —
      // exactly what quorum members need to make an informed vote.
      prTitle:  process.env.PR_TITLE || "",
      prBody:   process.env.PR_BODY  || "",
    },
  };
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Required environment variable ${name} is not set`);
  return v;
}

// ── Minimal HTTPS helper ──────────────────────────────────────────────────────

function request(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        const parsed = data ? JSON.parse(data) : {};
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode} from ${options.hostname}${options.path}: ${data}`));
        } else {
          resolve(parsed);
        }
      });
    });
    req.on("error", reject);
    if (body) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

// ── Discord API ───────────────────────────────────────────────────────────────

class DiscordClient {
  constructor(token, channelId, guildId) {
    this.token     = token;
    this.channelId = channelId;
    this.guildId   = guildId;
  }

  _opts(method, path, hasBody) {
    return {
      hostname: "discord.com",
      path:     `/api/v10${path}`,
      method,
      headers: {
        Authorization:  `Bot ${this.token}`,
        "Content-Type": "application/json",
        "User-Agent":   "QuorumBot/1.0 (dep-trust-check)",
      },
    };
  }

  post(path, body)   { return request(this._opts("POST",  path, true),  body); }
  patch(path, body)  { return request(this._opts("PATCH", path, true),  body); }
  get(path)          { return request(this._opts("GET",   path, false)); }
  put(path)          { return request(this._opts("PUT",   path, false)); }
  delete(path)       { return request(this._opts("DELETE",path, false)); }

  // Post an embed message to the configured channel
  async postEmbed(embed) {
    return this.post(`/channels/${this.channelId}/messages`, { embeds: [embed] });
  }

  // Update an existing embed message
  async updateEmbed(messageId, embed) {
    return this.patch(`/channels/${this.channelId}/messages/${messageId}`, { embeds: [embed] });
  }

  // Add a reaction to a message (bot adds both ✅ and ❌ as vote anchors)
  async addReaction(messageId, emoji) {
    // Emoji must be URL-encoded for standard Unicode emoji
    const encoded = encodeURIComponent(emoji);
    return this.put(`/channels/${this.channelId}/messages/${messageId}/reactions/${encoded}/@me`);
  }

  // Get all reactions for a given emoji on a message
  async getReactions(messageId, emoji) {
    const encoded = encodeURIComponent(emoji);
    return this.get(`/channels/${this.channelId}/messages/${messageId}/reactions/${encoded}?limit=100`);
  }

  // Resolve a user ID to a username for audit display
  async getUser(userId) {
    try {
      return await this.get(`/users/${userId}`);
    } catch {
      return { id: userId, username: userId };
    }
  }

  // Fetch guild member display names for the quorum roster
  async getMember(userId) {
    try {
      return await this.get(`/guilds/${this.guildId}/members/${userId}`);
    } catch {
      return { user: { id: userId, username: userId }, nick: null };
    }
  }
}

// ── Embed builders ────────────────────────────────────────────────────────────

const COLOR = {
  PENDING:  0xF59E0B,   // amber
  APPROVED: 0x22C55E,   // green
  DENIED:   0xEF4444,   // red
  EXPIRED:  0x6B7280,   // grey
  BLOCKED:  0xDC2626,   // dark red  (trust outcome)
  QUARANTINE: 0xF97316, // orange    (trust outcome)
};

// Build a concise update-reason string from PR title + body.
// Discord embed field values are capped at 1024 chars; we truncate body
// to 800 chars so the combined value stays well inside that limit.
function buildUpdateReason(prTitle, prBody) {
  const title = (prTitle || "").trim();
  const body  = (prBody  || "").trim();

  if (!title && !body) return "_No PR title or description provided._";

  const parts = [];
  if (title) parts.push(`**${title}**`);
  if (body) {
    // Strip markdown images and HTML comments which add noise without context
    const cleaned = body
      .replace(/<!--[\s\S]*?-->/g, "")
      .replace(/!\[.*?\]\(.*?\)/g, "")
      .trim();
    if (cleaned) {
      parts.push(cleaned.length > 800 ? cleaned.slice(0, 797) + "…" : cleaned);
    }
  }
  return parts.join("\n\n");
}

function pendingEmbed(quorumId, pkg, version, ecosystem, trustOutcome, cfg, deadlineIso, prUrl) {
  const needed       = requiredVotes(cfg.members.length, cfg.threshold);
  const roster       = cfg.members.map((id) => `<@${id}>`).join("  ");
  const updateReason = buildUpdateReason(cfg.github.prTitle, cfg.github.prBody);

  return {
    title: `🔐 Quorum Override Request — \`${pkg}@${version}\``,
    color: trustOutcome === "blocked" ? COLOR.BLOCKED : COLOR.QUARANTINE,
    description: [
      `The OSS Trust Framework flagged **\`${pkg}@${version}\`** (${ecosystem}) as **\`${trustOutcome.toUpperCase()}\`**.`,
      `A **simple majority** quorum is required to override and allow this dependency into the PR.`,
    ].join("\n"),
    fields: [
      // ── Update reason first — most important context for voters ──────────
      {
        name:  "📝 Reason for update",
        value: updateReason,
        inline: false,
      },
      // ── Package and vote metadata ────────────────────────────────────────
      { name: "Quorum ID",      value: `\`${quorumId}\``,                     inline: true  },
      { name: "Trust Outcome",  value: `\`${trustOutcome.toUpperCase()}\``,   inline: true  },
      { name: "Ecosystem",      value: `\`${ecosystem}\``,                    inline: true  },
      { name: "PR",             value: prUrl || "n/a",                        inline: true  },
      { name: "Quorum Size",    value: `${cfg.members.length} eligible`,      inline: true  },
      { name: "Votes Needed",   value: `${needed} to approve or deny`,        inline: true  },
      { name: "Deadline",       value: `<t:${isoToUnix(deadlineIso)}:R>`,     inline: true  },
      {
        name:  "How to vote",
        value: "React with ✅ to **approve** the override, or ❌ to **deny** it.\nOnly votes from the quorum roster below are counted.",
        inline: false,
      },
      { name: "Eligible voters", value: roster || "None configured", inline: false },
    ],
    footer: { text: "HITL Quorum Framework · Simple Majority (>50%) · Chris Gillham" },
    timestamp: new Date().toISOString(),
  };
}

function resolvedEmbed(quorumId, pkg, version, ecosystem, trustOutcome, verdict,
                        tally, voterLines, decidedAt, cfg) {
  const icon         = verdict === "APPROVED" ? "✅" : verdict === "DENIED" ? "🚫" : "⏱️";
  const color        = verdict === "APPROVED" ? COLOR.APPROVED : verdict === "DENIED" ? COLOR.DENIED : COLOR.EXPIRED;
  const updateReason = buildUpdateReason(cfg.github.prTitle, cfg.github.prBody);

  return {
    title: `${icon} Quorum ${verdict} — \`${pkg}@${version}\``,
    color,
    fields: [
      { name: "📝 Reason for update", value: updateReason,                        inline: false },
      { name: "Quorum ID",            value: `\`${quorumId}\``,                   inline: true  },
      { name: "Final Verdict",        value: `\`${verdict}\``,                    inline: true  },
      { name: "Trust Outcome",        value: `\`${trustOutcome.toUpperCase()}\``, inline: true  },
      { name: "✅ Approve",           value: `${tally.approve}`,                  inline: true  },
      { name: "❌ Deny",              value: `${tally.deny}`,                     inline: true  },
      { name: "⬜ Abstain",           value: `${tally.abstain}`,                  inline: true  },
      { name: "Voter detail",         value: voterLines.join("\n") || "None",     inline: false },
    ],
    footer: { text: `Decided at ${decidedAt} · HITL Quorum Framework · Chris Gillham` },
    timestamp: decidedAt,
  };
}

// ── Quorum logic ──────────────────────────────────────────────────────────────

function requiredVotes(quorumSize, threshold) {
  // Smallest integer > threshold × size  (strict majority)
  return Math.floor(quorumSize * threshold) + 1;
}

function isoToUnix(iso) {
  return Math.floor(new Date(iso).getTime() / 1000);
}

async function collectVotes(discord, messageId, quorumMembers) {
  const [approvers, deniers] = await Promise.all([
    discord.getReactions(messageId, "✅"),
    discord.getReactions(messageId, "❌"),
  ]);

  // Filter out the bot's own seed reactions; only count quorum members
  const memberSet  = new Set(quorumMembers);
  const approveIds = (approvers || []).filter((u) => !u.bot && memberSet.has(u.id)).map((u) => u.id);
  const denyIds    = (deniers   || []).filter((u) => !u.bot && memberSet.has(u.id)).map((u) => u.id);

  // Deduplicate — a user who reacted both ways counts as deny (more conservative)
  const denySet    = new Set(denyIds);
  const filteredApproveIds = approveIds.filter((id) => !denySet.has(id));

  const abstainIds = quorumMembers.filter(
    (id) => !filteredApproveIds.includes(id) && !denyIds.includes(id)
  );

  return {
    approve:    filteredApproveIds.length,
    deny:       denyIds.length,
    abstain:    abstainIds.length,
    approveIds: filteredApproveIds,
    denyIds,
    abstainIds,
  };
}

function evaluateVotes(tally, quorumSize, threshold) {
  const needed = requiredVotes(quorumSize, threshold);
  if (tally.approve >= needed) return "APPROVED";
  if (tally.deny    >= needed) return "DENIED";
  return null;   // no majority yet
}

// ── Poll loop ─────────────────────────────────────────────────────────────────
// GitHub Actions jobs have a 6-hour default timeout; we poll until majority
// or deadline, then exit so the job doesn't run forever.

async function pollUntilDecision(discord, messageId, quorumId, pkg, version,
                                  ecosystem, trustOutcome, cfg, deadline, prUrl) {
  const POLL_INTERVAL_MS = 30_000;   // check every 30 seconds
  const quorumSize = cfg.members.length;

  console.log(`[QUORUM] ${quorumId} — polling for votes on message ${messageId}`);
  console.log(`[QUORUM] Quorum size: ${quorumSize} | Threshold: ${cfg.threshold} | Deadline: ${deadline}`);

  while (new Date() < new Date(deadline)) {
    await sleep(POLL_INTERVAL_MS);

    const tally  = await collectVotes(discord, messageId, cfg.members);
    const verdict = evaluateVotes(tally, quorumSize, cfg.threshold);

    console.log(
      `[QUORUM] ${quorumId} tally — ✅ ${tally.approve} ❌ ${tally.deny} ⬜ ${tally.abstain}` +
      (verdict ? ` → ${verdict}` : " → pending")
    );

    if (verdict) {
      return { verdict, tally, decidedAt: new Date().toISOString() };
    }
  }

  // Deadline reached with no majority — treat as DENIED (fail closed)
  const tally = await collectVotes(discord, messageId, cfg.members);
  console.log(`[QUORUM] ${quorumId} — deadline reached without majority. Failing closed.`);
  return { verdict: "EXPIRED", tally, decidedAt: new Date().toISOString() };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Voter detail lines (for embed + audit) ────────────────────────────────────

async function buildVoterLines(discord, tally) {
  const lines = [];
  for (const id of tally.approveIds) {
    const u = await discord.getUser(id);
    lines.push(`✅ ${u.username} (${id})`);
  }
  for (const id of tally.denyIds) {
    const u = await discord.getUser(id);
    lines.push(`❌ ${u.username} (${id})`);
  }
  for (const id of tally.abstainIds) {
    const u = await discord.getUser(id);
    lines.push(`⬜ ${u.username} (${id}) — abstained`);
  }
  return lines;
}

// ── Google Sheets audit log ───────────────────────────────────────────────────

async function appendAuditRow(cfg, row) {
  if (!cfg.sheets.credentials || !cfg.sheets.spreadsheetId) {
    console.log("[QUORUM] Sheets credentials not configured — skipping audit log write");
    return;
  }

  // Decode service account JSON from base64 env var
  const serviceAccount = JSON.parse(
    Buffer.from(cfg.sheets.credentials, "base64").toString("utf8")
  );

  const token = await getServiceAccountToken(serviceAccount, [
    "https://www.googleapis.com/auth/spreadsheets",
  ]);

  const range  = `${cfg.sheets.sheetName}!A:T`;
  const values = [Object.values(row)];

  const body = JSON.stringify({ values });
  const opts = {
    hostname: "sheets.googleapis.com",
    path:     `/v4/spreadsheets/${cfg.sheets.spreadsheetId}/values/${encodeURIComponent(range)}:append` +
              `?valueInputOption=RAW&insertDataOption=INSERT_ROWS`,
    method:  "POST",
    headers: {
      Authorization:  `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  };

  await request(opts, body);
  console.log(`[QUORUM] Audit row appended to Sheets: ${cfg.sheets.spreadsheetId}`);
}

// Minimal JWT / service-account token flow (no external deps)
async function getServiceAccountToken(sa, scopes) {
  const now = Math.floor(Date.now() / 1000);
  const header  = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({
    iss:   sa.client_email,
    scope: scopes.join(" "),
    aud:   "https://oauth2.googleapis.com/token",
    iat:   now,
    exp:   now + 3600,
  }));

  const sigInput  = `${header}.${payload}`;
  const sign      = crypto.createSign("RSA-SHA256");
  sign.update(sigInput);
  const signature = sign.sign(sa.private_key, "base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

  const jwt  = `${sigInput}.${signature}`;
  const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;

  const resp = await request({
    hostname: "oauth2.googleapis.com",
    path:     "/token",
    method:   "POST",
    headers:  { "Content-Type": "application/x-www-form-urlencoded" },
  }, body);

  return resp.access_token;
}

function base64url(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ── GitHub PR comment ─────────────────────────────────────────────────────────

async function postGitHubResult(cfg, pkg, version, verdict, tally, quorumId, messageId) {
  if (!cfg.github.prNumber || !cfg.github.repo) return;

  const [owner, repo] = cfg.github.repo.split("/");
  const icon = { APPROVED: "✅", DENIED: "🚫", EXPIRED: "⏱️" }[verdict] ?? "❓";
  const discordUrl = `https://discord.com/channels/${process.env.DISCORD_GUILD_ID}/${process.env.DISCORD_CHANNEL_ID}/${messageId}`;

  const marker = `<!-- quorum:${quorumId} -->`;
  const body   = [
    marker,
    `## ${icon} Quorum ${verdict} — \`${pkg}@${version}\``,
    `| Field | Value |`,
    `|-------|-------|`,
    `| Quorum ID | \`${quorumId}\` |`,
    `| Verdict | \`${verdict}\` |`,
    `| ✅ Approve | ${tally.approve} |`,
    `| ❌ Deny | ${tally.deny} |`,
    `| ⬜ Abstain | ${tally.abstain} |`,
    `| Discord thread | [View vote](${discordUrl}) |`,
    `| Run | [${cfg.github.runId}](${cfg.github.serverUrl}/${cfg.github.repo}/actions/runs/${cfg.github.runId}) |`,
    verdict === "APPROVED"
      ? "\n> ⚠️ **Override approved.** This dependency was flagged by OSS Trust Framework but quorum voted to allow it."
      : "\n> 🚫 **Override denied.** This dependency remains blocked.",
  ].join("\n");

  // Check for existing quorum comment to update
  const listOpts = {
    hostname: "api.github.com",
    path:     `/repos/${owner}/${repo}/issues/${cfg.github.prNumber}/comments?per_page=100`,
    method:   "GET",
    headers: {
      Authorization:  `Bearer ${cfg.github.token}`,
      Accept:         "application/vnd.github+json",
      "User-Agent":   "QuorumBot/1.0",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  };

  let existingId = null;
  try {
    const comments = await request(listOpts);
    const found = comments.find((c) => c.body?.includes(marker));
    if (found) existingId = found.id;
  } catch { /* best-effort */ }

  const ghPath = existingId
    ? `/repos/${owner}/${repo}/issues/comments/${existingId}`
    : `/repos/${owner}/${repo}/issues/${cfg.github.prNumber}/comments`;

  const ghOpts = {
    hostname: "api.github.com",
    path:     ghPath,
    method:   existingId ? "PATCH" : "POST",
    headers: {
      Authorization:  `Bearer ${cfg.github.token}`,
      Accept:         "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent":   "QuorumBot/1.0",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  };

  await request(ghOpts, JSON.stringify({ body }));
  console.log(`[QUORUM] GitHub PR comment ${existingId ? "updated" : "posted"}`);
}

// ── Main entry point ──────────────────────────────────────────────────────────

async function main() {
  // trust-result.json written by the oss-trust check step
  const trustResult = JSON.parse(fs.readFileSync("trust-result.json", "utf8"));
  const { package: pkg, version, ecosystem, outcome: trustOutcome } = trustResult;

  if (!["blocked", "quarantined"].includes(trustOutcome)) {
    console.log(`[QUORUM] Trust outcome is '${trustOutcome}' — no quorum required. Exiting 0.`);
    process.exit(0);
  }

  const cfg      = loadConfig();
  const discord  = new DiscordClient(cfg.discord.token, cfg.discord.channelId, cfg.discord.guildId);
  const quorumId = `QR-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
  const deadline = new Date(Date.now() + cfg.deadlineHours * 3_600_000).toISOString();
  const prUrl    = cfg.github.prNumber
    ? `${cfg.github.serverUrl}/${cfg.github.repo}/pull/${cfg.github.prNumber}`
    : null;

  // Build the update reason once — used in both embeds and the audit row
  const updateReason = buildUpdateReason(cfg.github.prTitle, cfg.github.prBody);
  console.log(`[QUORUM] Update reason: ${updateReason.slice(0, 120).replace(/\n/g, " ")}`);

  // ── 1. Post quorum request embed ─────────────────────────────────────────
  console.log(`[QUORUM] ${quorumId} — posting quorum request for ${pkg}@${version}`);
  const message = await discord.postEmbed(
    pendingEmbed(quorumId, pkg, version, ecosystem, trustOutcome, cfg, deadline, prUrl)
  );
  const messageId = message.id;

  // ── 2. Bot seeds both vote reactions so members can one-click react ───────
  await discord.addReaction(messageId, "✅");
  await sleep(500);   // brief pause to avoid rate-limit
  await discord.addReaction(messageId, "❌");
  console.log(`[QUORUM] Seed reactions posted. Message ID: ${messageId}`);

  // ── 3. Poll until majority or deadline ───────────────────────────────────
  const { verdict, tally, decidedAt } = await pollUntilDecision(
    discord, messageId, quorumId, pkg, version, ecosystem, trustOutcome, cfg, deadline, prUrl
  );

  // ── 4. Resolve voter display names ───────────────────────────────────────
  const voterLines = await buildVoterLines(discord, tally);

  // ── 5. Update Discord embed with final verdict ────────────────────────────
  await discord.updateEmbed(
    messageId,
    resolvedEmbed(quorumId, pkg, version, ecosystem, trustOutcome,
                  verdict, tally, voterLines, decidedAt, cfg)
  );
  console.log(`[QUORUM] Discord embed updated: ${verdict}`);

  // ── 6. Append audit record to Google Sheets ───────────────────────────────
  const auditRow = {
    quorum_id:          quorumId,
    package:            pkg,
    version,
    ecosystem,
    trust_outcome:      trustOutcome,
    update_reason:      updateReason.replace(/\n+/g, " | ").slice(0, 500), // flatten for Sheets
    initiated_at:       new Date().toISOString(),
    deadline,
    quorum_size:        cfg.members.length,
    threshold:          cfg.threshold,
    approve_count:      tally.approve,
    deny_count:         tally.deny,
    abstain_count:      tally.abstain,
    final_verdict:      verdict,
    decided_at:         decidedAt,
    decided_by:         verdict === "EXPIRED" ? "DEADLINE" : "QUORUM_VOTE",
    voter_detail:       voterLines.join(" | "),
    discord_message_id: messageId,
    github_pr:          prUrl || "",
    run_id:             cfg.github.runId,
    override_rationale: verdict === "APPROVED"
      ? `Quorum override: ${tally.approve}/${cfg.members.length} approved`
      : `Override rejected or expired: ${tally.deny} deny, ${tally.abstain} abstain`,
  };

  await appendAuditRow(cfg, auditRow);

  // ── 7. Post final result to GitHub PR ────────────────────────────────────
  await postGitHubResult(cfg, pkg, version, verdict, tally, quorumId, messageId);

  // ── 8. Exit code drives workflow gate ─────────────────────────────────────
  if (verdict === "APPROVED") {
    console.log(`[QUORUM] ✅ Override APPROVED for ${pkg}@${version}. Exiting 0.`);
    process.exit(0);
  } else {
    console.log(`[QUORUM] 🚫 Override ${verdict} for ${pkg}@${version}. Exiting 1.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("[QUORUM] Fatal error:", err);
  process.exit(1);
});
