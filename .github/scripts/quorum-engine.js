// .github/scripts/quorum-engine.js
//
// Multi-Platform Quorum Engine — Discord · MS Teams · Slack
// ─────────────────────────────────────────────────────────────────────────────
// Integrates with dep-trust-check.yml to gate blocked/quarantined packages
// behind a configurable human quorum. Supports three notification platforms,
// selected via QUORUM_PLATFORM (or quorum-config.json → platform).
//
// Voting mechanisms by platform:
//   Discord — bot adds ✅ ❌ reactions; engine polls GET /reactions every 30 s
//   Teams   — Adaptive Card with ✅ ❌ Action.Submit buttons; votes arrive via
//             incoming webhook callback posted to TEAMS_VOTE_WEBHOOK_URL
//   Slack   — Block Kit message with ✅ ❌ buttons; votes arrive via
//             Slack interactivity callback posted to SLACK_VOTE_WEBHOOK_URL
//
// Environment variables — all platforms:
//   QUORUM_PLATFORM         discord | teams | slack  (default: discord)
//   QUORUM_MEMBERS          Comma-separated member IDs eligible to vote
//                           Discord: numeric user IDs
//                           Teams: AAD Object IDs (GUID format)
//                           Slack: Slack member IDs (Uxxxxxxxx format)
//   QUORUM_THRESHOLD        Float 0.0–1.0  (default 0.5)
//   QUORUM_DEADLINE_HOURS   Integer        (default 24)
//   GITHUB_TOKEN            GitHub API token
//   SHEETS_CREDENTIALS      Base64-encoded Google service account JSON
//   SHEETS_SPREADSHEET_ID   Spreadsheet ID for audit log
//   SHEETS_SHEET_NAME       Tab name (default "QuorumAuditLog")
//   PR_TITLE / PR_BODY      PR context surfaced in vote message
//   PKG_REGISTRY_URL        Source registry URL
//
// Discord-specific:
//   DISCORD_BOT_TOKEN       Bot token (SEND_MESSAGES, ADD_REACTIONS, etc.)
//   DISCORD_CHANNEL_ID      Channel ID for quorum messages
//   DISCORD_GUILD_ID        Server ID
//
// Teams-specific:
//   TEAMS_WEBHOOK_URL       Incoming webhook URL for the approval channel
//   TEAMS_VOTE_WEBHOOK_URL  URL that receives Action.Submit vote payloads
//                           (your Azure Function / Logic App endpoint)
//   TEAMS_TENANT_ID         Azure AD tenant ID (for @mention resolution)
//
// Slack-specific:
//   SLACK_BOT_TOKEN         Bot token (chat:write, users:read)
//   SLACK_CHANNEL_ID        Channel ID for quorum messages
//   SLACK_VOTE_WEBHOOK_URL  URL that receives button-click interactivity payloads
//                           (your Slack app's Request URL endpoint)
//
// Audit record schema (one row per quorum event):
//   quorum_id | package | version | ecosystem | source_repository |
//   platform | notification_message_id |
//   trust_level | trust_level_score |
//   sig_status | sig_algorithm | sig_strength | sig_key_id |
//   chk_status | chk_algorithm |
//   flag_typosquatting | flag_behavior_change | flag_author_reputation | flag_provenance |
//   trust_deductions | trust_outcome | update_reason | initiated_at | deadline |
//   quorum_size | threshold | approve_count | deny_count | abstain_count |
//   final_verdict | decided_at | decided_by | voter_detail |
//   notification_message_id | github_pr | run_id | override_rationale

"use strict";

const https  = require("https");
const http   = require("http");
const fs     = require("fs");
const crypto = require("crypto");
const url    = require("url");

// ── Config ────────────────────────────────────────────────────────────────────

function loadConfig() {
  let fileConfig = {};
  const configPath = ".github/quorum-config.json";
  if (fs.existsSync(configPath)) {
    fileConfig = JSON.parse(fs.readFileSync(configPath, "utf8"));
  }

  const platform = (
    process.env.QUORUM_PLATFORM ||
    fileConfig.platform ||
    "discord"
  ).toLowerCase();

  if (!["discord", "teams", "slack"].includes(platform)) {
    throw new Error(`Invalid QUORUM_PLATFORM '${platform}'. Must be: discord | teams | slack`);
  }

  const memberString = process.env.QUORUM_MEMBERS || fileConfig.members?.join(",") || "";
  const members = memberString.split(",").map((m) => m.trim()).filter(Boolean);

  if (members.length === 0) {
    throw new Error("QUORUM_MEMBERS is empty.");
  }

  const base = {
    platform,
    members,
    threshold:     parseFloat(process.env.QUORUM_THRESHOLD      || fileConfig.threshold      || "0.5"),
    deadlineHours: parseInt(  process.env.QUORUM_DEADLINE_HOURS || fileConfig.deadlineHours  || "24", 10),
    sheets: {
      credentials:   process.env.SHEETS_CREDENTIALS    || null,
      spreadsheetId: process.env.SHEETS_SPREADSHEET_ID || null,
      sheetName:     process.env.SHEETS_SHEET_NAME      || "QuorumAuditLog",
    },
    github: {
      token:       requireEnv("GITHUB_TOKEN"),
      repo:        process.env.GITHUB_REPOSITORY || "",
      prNumber:    process.env.PR_NUMBER         || "",
      runId:       process.env.GITHUB_RUN_ID     || "",
      serverUrl:   process.env.GITHUB_SERVER_URL || "https://github.com",
      prTitle:     process.env.PR_TITLE          || "",
      prBody:      process.env.PR_BODY           || "",
      registryUrl: process.env.PKG_REGISTRY_URL  || "",
    },
  };

  // ── Platform-specific config ──────────────────────────────────────────────
  if (platform === "discord") {
    base.discord = {
      token:     requireEnv("DISCORD_BOT_TOKEN"),
      channelId: requireEnv("DISCORD_CHANNEL_ID"),
      guildId:   requireEnv("DISCORD_GUILD_ID"),
    };
  } else if (platform === "teams") {
    base.teams = {
      webhookUrl:      requireEnv("TEAMS_WEBHOOK_URL"),
      voteWebhookUrl:  requireEnv("TEAMS_VOTE_WEBHOOK_URL"),
      tenantId:        process.env.TEAMS_TENANT_ID || "",
    };
  } else if (platform === "slack") {
    base.slack = {
      token:           requireEnv("SLACK_BOT_TOKEN"),
      channelId:       requireEnv("SLACK_CHANNEL_ID"),
      voteWebhookUrl:  requireEnv("SLACK_VOTE_WEBHOOK_URL"),
    };
  }

  return base;
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Required environment variable ${name} is not set`);
  return v;
}

// ── HTTPS / HTTP helper ───────────────────────────────────────────────────────

function httpRequest(options, body) {
  return new Promise((resolve, reject) => {
    const isHttps = options.protocol !== "http:";
    const lib     = isHttps ? https : http;
    const req = lib.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        let parsed = {};
        try { parsed = data ? JSON.parse(data) : {}; } catch { parsed = { raw: data }; }
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode} ${options.hostname}${options.path}: ${data.slice(0,300)}`));
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

function httpsOpts(method, hostname, path, extraHeaders) {
  return {
    hostname, path, method,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform Adapters
// Each adapter implements:
//   postVoteRequest(cfg, payload)  → { messageId, threadUrl }
//   updateWithVerdict(cfg, messageId, payload) → void
//   collectVotes(cfg, messageId, quorumMembers, voteStore) → { approve, deny, abstain, ... }
//   resolveVoterName(cfg, memberId) → string
// ─────────────────────────────────────────────────────────────────────────────

// ── Discord Adapter ───────────────────────────────────────────────────────────

const DiscordAdapter = {

  _opts(method, path, token) {
    return httpsOpts(method, "discord.com", `/api/v10${path}`, {
      Authorization: `Bot ${token}`,
      "User-Agent":  "QuorumBot/2.0 (oss-trust-framework)",
    });
  },

  async postVoteRequest(cfg, payload) {
    const { token, channelId } = cfg.discord;
    const msg = await httpRequest(
      this._opts("POST", `/channels/${channelId}/messages`, token),
      { embeds: [payload.embed] }
    );
    // Seed ✅ and ❌ reactions as vote anchors
    for (const emoji of ["✅", "❌"]) {
      await httpRequest(
        this._opts("PUT",
          `/channels/${channelId}/messages/${msg.id}/reactions/${encodeURIComponent(emoji)}/@me`,
          token
        )
      );
      await sleep(300);
    }
    const threadUrl = `https://discord.com/channels/${cfg.discord.guildId}/${channelId}/${msg.id}`;
    return { messageId: msg.id, threadUrl };
  },

  async updateWithVerdict(cfg, messageId, payload) {
    const { token, channelId } = cfg.discord;
    await httpRequest(
      this._opts("PATCH", `/channels/${channelId}/messages/${messageId}`, token),
      { embeds: [payload.embed] }
    );
  },

  async collectVotes(cfg, messageId, quorumMembers) {
    const { token, channelId } = cfg.discord;

    const fetchReactions = async (emoji) => {
      const enc = encodeURIComponent(emoji);
      return httpRequest(
        this._opts("GET", `/channels/${channelId}/messages/${messageId}/reactions/${enc}?limit=100`, token)
      );
    };

    const [approvers, deniers] = await Promise.all([
      fetchReactions("✅"),
      fetchReactions("❌"),
    ]);

    const memberSet  = new Set(quorumMembers);
    const approveIds = (approvers || []).filter((u) => !u.bot && memberSet.has(u.id)).map((u) => u.id);
    const denyIds    = (deniers   || []).filter((u) => !u.bot && memberSet.has(u.id)).map((u) => u.id);
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
  },

  async resolveVoterName(cfg, memberId) {
    try {
      const user = await httpRequest(
        this._opts("GET", `/users/${memberId}`, cfg.discord.token)
      );
      return user.username || memberId;
    } catch { return memberId; }
  },
};

// ── MS Teams Adapter ──────────────────────────────────────────────────────────
//
// Teams uses Adaptive Cards with Action.Submit buttons. When a member clicks
// ✅ or ❌, Teams POSTs a payload to TEAMS_VOTE_WEBHOOK_URL (an Azure Function
// or Logic App). The engine polls that endpoint every 30 s to read accumulated
// votes from a shared vote store (JSON file or the endpoint itself).
//
// Vote store contract: GET {voteWebhookUrl}/votes?quorum_id={id}
//   Response: { votes: [ { member_id, vote, voted_at }, ... ] }
//
// POST to voteWebhookUrl (from Teams button click):
//   { quorum_id, member_id, vote: "approve" | "deny", member_name }

const TeamsAdapter = {

  async postVoteRequest(cfg, payload) {
    const { webhookUrl, voteWebhookUrl } = cfg.teams;
    const card = buildTeamsCard(payload, voteWebhookUrl);

    const parsed = new url.URL(webhookUrl);
    await httpRequest(
      httpsOpts("POST", parsed.hostname, parsed.pathname + parsed.search),
      card
    );

    // Teams incoming webhooks don't return a message ID — use quorum_id as stable key
    const messageId = payload.quorumId;
    const threadUrl = webhookUrl;   // Deep link not available via incoming webhook
    return { messageId, threadUrl };
  },

  async updateWithVerdict(cfg, messageId, payload) {
    // Post a follow-up card to the channel; incoming webhooks can't edit prior messages
    const { webhookUrl, voteWebhookUrl } = cfg.teams;
    const card = buildTeamsVerdictCard(payload);
    const parsed = new url.URL(webhookUrl);
    await httpRequest(
      httpsOpts("POST", parsed.hostname, parsed.pathname + parsed.search),
      card
    ).catch((err) => console.warn(`[QUORUM][teams] Verdict card post failed: ${err.message}`));
  },

  async collectVotes(cfg, messageId, quorumMembers, voteStore) {
    // Primary: use in-process voteStore populated by the local webhook server
    // Fallback: query the remote vote endpoint
    let votes = [];

    if (voteStore && voteStore[messageId]) {
      votes = voteStore[messageId];
    } else {
      try {
        const { voteWebhookUrl } = cfg.teams;
        const parsed = new url.URL(`${voteWebhookUrl}/votes?quorum_id=${encodeURIComponent(messageId)}`);
        const data   = await httpRequest(httpsOpts("GET", parsed.hostname, parsed.pathname + parsed.search));
        votes = data.votes || [];
      } catch (e) {
        console.warn(`[QUORUM][teams] Vote fetch failed: ${e.message}`);
      }
    }

    return tallyVotes(votes, quorumMembers);
  },

  async resolveVoterName(cfg, memberId) {
    // Names arrive in the vote payload from Teams; return memberId as fallback
    return memberId;
  },
};

// ── Slack Adapter ─────────────────────────────────────────────────────────────
//
// Slack uses Block Kit messages with ✅ ❌ buttons. When a member clicks a
// button, Slack POSTs an interactivity payload to SLACK_VOTE_WEBHOOK_URL.
// The engine runs a local HTTP listener on port 3000 to capture these
// callbacks and accumulates them in an in-process vote store.
//
// Slack interactivity payload key fields:
//   user.id, user.name, actions[0].action_id ("approve" | "deny"),
//   actions[0].value (quorum_id)

const SlackAdapter = {

  async postVoteRequest(cfg, payload) {
    const { token, channelId } = cfg.slack;
    const blocks = buildSlackBlocks(payload);

    const msg = await httpRequest(
      httpsOpts("POST", "slack.com", "/api/chat.postMessage", {
        Authorization: `Bearer ${token}`,
      }),
      { channel: channelId, blocks, text: `Quorum vote: ${payload.pkg}@${payload.version}` }
    );

    if (!msg.ok) throw new Error(`Slack chat.postMessage failed: ${msg.error}`);
    const messageId = msg.ts;   // Slack message timestamp = stable ID
    const threadUrl = `https://slack.com/archives/${channelId}/p${messageId.replace(".", "")}`;
    return { messageId, threadUrl };
  },

  async updateWithVerdict(cfg, messageId, payload) {
    const { token, channelId } = cfg.slack;
    const blocks = buildSlackVerdictBlocks(payload);

    // Update the original message in-place via chat.update
    await httpRequest(
      httpsOpts("POST", "slack.com", "/api/chat.update", {
        Authorization: `Bearer ${token}`,
      }),
      { channel: channelId, ts: messageId, blocks, text: `Quorum ${payload.verdict}: ${payload.pkg}@${payload.version}` }
    ).catch((err) => console.warn(`[QUORUM][slack] Message update failed: ${err.message}`));
  },

  async collectVotes(cfg, messageId, quorumMembers, voteStore) {
    const votes = voteStore?.[messageId] || [];
    return tallyVotes(votes, quorumMembers);
  },

  async resolveVoterName(cfg, memberId) {
    try {
      const { token } = cfg.slack;
      const data = await httpRequest(
        httpsOpts("GET", "slack.com", `/api/users.info?user=${memberId}`, {
          Authorization: `Bearer ${token}`,
        })
      );
      return data.ok ? (data.user?.real_name || data.user?.name || memberId) : memberId;
    } catch { return memberId; }
  },
};

// ── Platform selector ─────────────────────────────────────────────────────────

function getAdapter(platform) {
  return { discord: DiscordAdapter, teams: TeamsAdapter, slack: SlackAdapter }[platform];
}

// ─────────────────────────────────────────────────────────────────────────────
// Vote tally helper (shared by Teams and Slack webhook-based adapters)
// votes: [ { member_id, vote: "approve"|"deny", member_name? }, ... ]
// ─────────────────────────────────────────────────────────────────────────────

function tallyVotes(votes, quorumMembers) {
  const memberSet = new Set(quorumMembers);
  // Latest vote per member wins (handles vote changes)
  const latestPerMember = {};
  for (const v of votes) {
    if (memberSet.has(v.member_id)) {
      latestPerMember[v.member_id] = v;
    }
  }

  const approveIds = [], denyIds = [];
  for (const [id, v] of Object.entries(latestPerMember)) {
    if (v.vote === "approve") approveIds.push(id);
    else denyIds.push(id);
  }

  const denySet = new Set(denyIds);
  const filteredApproveIds = approveIds.filter((id) => !denySet.has(id));
  const abstainIds = quorumMembers.filter(
    (id) => !filteredApproveIds.includes(id) && !denySet.has(id)
  );

  return {
    approve:    filteredApproveIds.length,
    deny:       denyIds.length,
    abstain:    abstainIds.length,
    approveIds: filteredApproveIds,
    denyIds,
    abstainIds,
    rawVotes:   Object.values(latestPerMember),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Local webhook server (Teams & Slack push-based voting)
// Listens on PORT (default 3000) for incoming vote payloads.
// Returns a { voteStore, server } pair. Caller closes server when done.
// ─────────────────────────────────────────────────────────────────────────────

function startVoteServer(platform, quorumId) {
  const voteStore = {};   // { messageId → [ { member_id, vote, member_name, voted_at } ] }
  const PORT = parseInt(process.env.VOTE_SERVER_PORT || "3000", 10);

  const server = http.createServer((req, res) => {
    if (req.method !== "POST") { res.writeHead(200).end("OK"); return; }

    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        let vote;
        if (platform === "slack") {
          // Slack sends application/x-www-form-urlencoded with a "payload" field
          const params  = new url.URLSearchParams(body);
          const payload = JSON.parse(params.get("payload") || "{}");
          const action  = payload.actions?.[0];
          if (!action) { res.writeHead(200).end(); return; }

          const msgQuorumId = action.value;
          const memberId    = payload.user?.id || "";
          const memberName  = payload.user?.name || memberId;
          const voteValue   = action.action_id;   // "approve" or "deny"

          if (msgQuorumId && memberId && ["approve", "deny"].includes(voteValue)) {
            const key = msgQuorumId;
            voteStore[key] = voteStore[key] || [];
            // Remove prior vote from same member then append new one
            voteStore[key] = voteStore[key].filter((v) => v.member_id !== memberId);
            voteStore[key].push({ member_id: memberId, vote: voteValue, member_name: memberName, voted_at: new Date().toISOString() });
            console.log(`[QUORUM][slack] Vote recorded: ${memberName} → ${voteValue} on ${key}`);
          }
          // Slack expects 200 immediately to dismiss loading state
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ response_type: "ephemeral", text: `Vote recorded: ${voteValue}` }));

        } else if (platform === "teams") {
          const payload = JSON.parse(body);
          const { quorum_id: qid, member_id, vote: voteValue, member_name } = payload;
          if (qid && member_id && ["approve", "deny"].includes(voteValue)) {
            voteStore[qid] = voteStore[qid] || [];
            voteStore[qid] = voteStore[qid].filter((v) => v.member_id !== member_id);
            voteStore[qid].push({ member_id, vote: voteValue, member_name: member_name || member_id, voted_at: new Date().toISOString() });
            console.log(`[QUORUM][teams] Vote recorded: ${member_name || member_id} → ${voteValue} on ${qid}`);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ type: "message", text: `Vote recorded: ${voteValue}` }));
        }
      } catch (err) {
        console.warn(`[QUORUM] Vote server parse error: ${err.message}`);
        res.writeHead(400).end("Bad Request");
      }
    });
  });

  server.listen(PORT, () => {
    console.log(`[QUORUM] Vote callback server listening on port ${PORT} (platform: ${platform})`);
  });

  return { voteStore, server };
}

// ─────────────────────────────────────────────────────────────────────────────
// Message builders — Discord embeds
// ─────────────────────────────────────────────────────────────────────────────

const DISCORD_COLOR = {
  APPROVED:   0x22C55E,
  DENIED:     0xEF4444,
  EXPIRED:    0x6B7280,
  BLOCKED:    0xDC2626,
  QUARANTINE: 0xF97316,
};
const TRUST_COLOR = { HIGH: 0x22C55E, MEDIUM: 0xF59E0B, LOW: 0xDC2626 };

function buildDiscordPendingEmbed(p) {
  const { quorumId, pkg, version, ecosystem, trustOutcome, cfg, deadline, prUrl, sourceRepo, trust, updateReason } = p;
  const needed = requiredVotes(cfg.members.length, cfg.threshold);
  const roster = cfg.members.map((id) => `<@${id}>`).join("  ");
  const color  = TRUST_COLOR[trust.band] ?? (trustOutcome === "blocked" ? DISCORD_COLOR.BLOCKED : DISCORD_COLOR.QUARANTINE);

  return {
    title: `🔐 Quorum Override Request — \`${pkg}@${version}\``,
    color,
    description: [
      `The OSS Trust Framework flagged **\`${pkg}@${version}\`** (${ecosystem}) as **\`${trustOutcome.toUpperCase()}\`**.`,
      `A **simple majority** quorum is required to override and allow this dependency into the PR.`,
    ].join("\n"),
    fields: [
      { name: "📝 Reason for update",   value: updateReason,                                            inline: false },
      { name: "📦 Source repository",   value: sourceRepo ? `\`${sourceRepo}\`` : "_Not provided_",    inline: false },
      { name: "🔒 Trust level",         value: trust.label,                                             inline: true  },
      { name: "🔏 Signature",           value: trust.sigStatusLine,                                     inline: true  },
      { name: "🔑 Key / log ID",        value: trust.sigKeyId !== "n/a" ? `\`${trust.sigKeyId}\`` : "_n/a_", inline: true },
      { name: "🧮 Checksum",            value: trust.chkStatusLine,                                     inline: false },
      trust.flagLines.length > 0
        ? { name: "🚩 Supply-chain flags", value: trust.flagSummary, inline: false }
        : null,
      trust.deductionCount > 0
        ? { name: "⚠️ Trust deductions", value: trust.deductions,  inline: false }
        : null,
      { name: "Quorum ID",              value: `\`${quorumId}\``,                                       inline: true  },
      { name: "Trust Outcome",          value: `\`${trustOutcome.toUpperCase()}\``,                     inline: true  },
      { name: "Ecosystem",              value: `\`${ecosystem}\``,                                      inline: true  },
      { name: "PR",                     value: prUrl || "n/a",                                          inline: true  },
      { name: "Quorum Size",            value: `${cfg.members.length} eligible`,                        inline: true  },
      { name: "Votes Needed",           value: `${needed} to approve or deny`,                          inline: true  },
      { name: "Deadline",               value: `<t:${isoToUnix(deadline)}:R>`,                          inline: true  },
      { name: "How to vote",            value: "React with ✅ to **approve**, ❌ to **deny**.\nOnly quorum member votes are counted.", inline: false },
      { name: "Eligible voters",        value: roster || "None configured",                             inline: false },
    ].filter(Boolean),
    footer: { text: "HITL Quorum Framework · Simple Majority (>50%) · Chris Gillham" },
    timestamp: new Date().toISOString(),
  };
}

function buildDiscordVerdictEmbed(p) {
  const { quorumId, pkg, version, ecosystem, trustOutcome, verdict, tally, voterLines, decidedAt, cfg, sourceRepo, trust, updateReason } = p;
  const icon  = verdict === "APPROVED" ? "✅" : verdict === "DENIED" ? "🚫" : "⏱️";
  const color = { APPROVED: DISCORD_COLOR.APPROVED, DENIED: DISCORD_COLOR.DENIED, EXPIRED: DISCORD_COLOR.EXPIRED }[verdict] ?? DISCORD_COLOR.DENIED;

  return {
    title: `${icon} Quorum ${verdict} — \`${pkg}@${version}\``,
    color,
    fields: [
      { name: "📝 Reason for update",  value: updateReason,                                            inline: false },
      { name: "📦 Source repository",  value: sourceRepo ? `\`${sourceRepo}\`` : "_Not provided_",    inline: false },
      { name: "🔒 Trust level",        value: trust.label,                                             inline: true  },
      { name: "🔏 Signature",          value: trust.sigStatusLine,                                     inline: true  },
      { name: "🔑 Key / log ID",       value: trust.sigKeyId !== "n/a" ? `\`${trust.sigKeyId}\`` : "_n/a_", inline: true },
      { name: "🧮 Checksum",           value: trust.chkStatusLine,                                     inline: false },
      trust.flagLines.length > 0
        ? { name: "🚩 Supply-chain flags", value: trust.flagSummary, inline: false }
        : null,
      { name: "Quorum ID",             value: `\`${quorumId}\``,                                       inline: true  },
      { name: "Final Verdict",         value: `\`${verdict}\``,                                        inline: true  },
      { name: "Trust Outcome",         value: `\`${trustOutcome.toUpperCase()}\``,                     inline: true  },
      { name: "✅ Approve",            value: `${tally.approve}`,                                      inline: true  },
      { name: "❌ Deny",               value: `${tally.deny}`,                                         inline: true  },
      { name: "⬜ Abstain",            value: `${tally.abstain}`,                                      inline: true  },
      { name: "Voter detail",          value: voterLines.join("\n") || "None",                         inline: false },
    ].filter(Boolean),
    footer: { text: `Decided ${decidedAt} · HITL Quorum Framework · Chris Gillham` },
    timestamp: decidedAt,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Message builders — MS Teams Adaptive Cards
// ─────────────────────────────────────────────────────────────────────────────

function buildTeamsCard(p, voteWebhookUrl) {
  const { quorumId, pkg, version, ecosystem, trustOutcome, cfg, deadline, prUrl, sourceRepo, trust, updateReason } = p;
  const needed   = requiredVotes(cfg.members.length, cfg.threshold);
  const bandEmoji = { HIGH: "🟢", MEDIUM: "🟡", LOW: "🔴" }[trust.band] ?? "⬜";
  const accentColor = trust.band === "HIGH" ? "Good" : trust.band === "MEDIUM" ? "Warning" : "Attention";

  return {
    type: "message",
    attachments: [{
      contentType: "application/vnd.microsoft.card.adaptive",
      content: {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        type: "AdaptiveCard",
        version: "1.5",
        body: [
          {
            type: "TextBlock",
            text: `🔐 Quorum Override Request`,
            weight: "Bolder", size: "Large", color: accentColor,
          },
          {
            type: "TextBlock",
            text: `**${pkg}@${version}** (${ecosystem}) flagged as **${trustOutcome.toUpperCase()}**`,
            wrap: true,
          },
          { type: "TextBlock", text: "---", separator: true },
          {
            type: "FactSet",
            facts: [
              { title: "📝 Update reason", value: updateReason.slice(0, 200) },
              { title: "📦 Source repo",   value: sourceRepo || "Not provided" },
              { title: "🔒 Trust level",   value: `${bandEmoji} ${trust.band} (${trust.score}/100)` },
              { title: "🔏 Signature",     value: trust.sigStatusLine },
              { title: "🧮 Checksum",      value: trust.chkStatusLine },
              ...(trust.flagLines.length > 0
                ? [{ title: "🚩 Flags", value: trust.flagLines.join(", ") }]
                : []),
              ...(trust.deductionCount > 0
                ? [{ title: "⚠️ Deductions", value: trust.deductions.replace(/\n/g, ", ").slice(0, 200) }]
                : []),
              { title: "Quorum ID",    value: quorumId },
              { title: "Quorum size",  value: `${cfg.members.length} eligible, ${needed} votes needed` },
              { title: "Deadline",     value: new Date(deadline).toUTCString() },
              ...(prUrl ? [{ title: "PR", value: `[View PR](${prUrl})` }] : []),
            ],
          },
          {
            type: "TextBlock",
            text: "Click **✅ Approve Override** or **❌ Deny Override** to cast your vote. Only quorum members' votes are counted.",
            wrap: true, isSubtle: true,
          },
        ],
        actions: [
          {
            type: "Action.Submit",
            title: "✅ Approve Override",
            style: "positive",
            data: {
              quorum_id:    quorumId,
              vote:         "approve",
              member_id:    "{{MSTeams.User.Id}}",     // Resolved by Teams at submit time
              member_name:  "{{MSTeams.User.DisplayName}}",
            },
            url: voteWebhookUrl,
          },
          {
            type: "Action.Submit",
            title: "❌ Deny Override",
            style: "destructive",
            data: {
              quorum_id:    quorumId,
              vote:         "deny",
              member_id:    "{{MSTeams.User.Id}}",
              member_name:  "{{MSTeams.User.DisplayName}}",
            },
            url: voteWebhookUrl,
          },
        ],
      },
    }],
  };
}

function buildTeamsVerdictCard(p) {
  const { quorumId, pkg, version, verdict, tally, voterLines, decidedAt, trust, updateReason } = p;
  const icon  = verdict === "APPROVED" ? "✅" : verdict === "DENIED" ? "🚫" : "⏱️";
  const color = verdict === "APPROVED" ? "Good" : "Attention";

  return {
    type: "message",
    attachments: [{
      contentType: "application/vnd.microsoft.card.adaptive",
      content: {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        type: "AdaptiveCard",
        version: "1.5",
        body: [
          {
            type: "TextBlock",
            text: `${icon} Quorum ${verdict} — ${pkg}@${version}`,
            weight: "Bolder", size: "Large", color,
          },
          {
            type: "FactSet",
            facts: [
              { title: "Quorum ID",     value: quorumId },
              { title: "Final verdict", value: verdict },
              { title: "✅ Approve",    value: String(tally.approve) },
              { title: "❌ Deny",       value: String(tally.deny) },
              { title: "⬜ Abstain",    value: String(tally.abstain) },
              { title: "Decided at",   value: new Date(decidedAt).toUTCString() },
              { title: "🔒 Trust",     value: trust.label },
              { title: "📝 Reason",    value: updateReason.slice(0, 200) },
            ],
          },
          voterLines.length > 0
            ? { type: "TextBlock", text: "**Voter detail:** " + voterLines.join(" · "), wrap: true }
            : null,
          {
            type: "TextBlock",
            text: verdict === "APPROVED"
              ? "⚠️ Override approved. This dependency was flagged but quorum voted to allow it."
              : "🚫 Override denied. This dependency remains blocked.",
            wrap: true, color,
          },
        ].filter(Boolean),
      },
    }],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Message builders — Slack Block Kit
// ─────────────────────────────────────────────────────────────────────────────

function buildSlackBlocks(p) {
  const { quorumId, pkg, version, ecosystem, trustOutcome, cfg, deadline, prUrl, sourceRepo, trust, updateReason } = p;
  const needed   = requiredVotes(cfg.members.length, cfg.threshold);
  const bandEmoji = { HIGH: "🟢", MEDIUM: "🟡", LOW: "🔴" }[trust.band] ?? "⬜";

  const blocks = [
    {
      type: "header",
      text: { type: "plain_text", text: `🔐 Quorum Override Request`, emoji: true },
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*${pkg}@${version}* (${ecosystem}) flagged as *${trustOutcome.toUpperCase()}*\nA simple majority quorum is required to allow this dependency.`,
      },
    },
    { type: "divider" },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*📝 Update reason*\n${updateReason.slice(0, 150)}` },
        { type: "mrkdwn", text: `*📦 Source repo*\n${sourceRepo || "_Not provided_"}` },
        { type: "mrkdwn", text: `*🔒 Trust level*\n${bandEmoji} ${trust.band} (${trust.score}/100)` },
        { type: "mrkdwn", text: `*🔏 Signature*\n${trust.sigStatusLine}` },
        { type: "mrkdwn", text: `*🧮 Checksum*\n${trust.chkStatusLine}` },
        { type: "mrkdwn", text: `*Quorum size*\n${cfg.members.length} eligible, ${needed} needed` },
        { type: "mrkdwn", text: `*Deadline*\n${new Date(deadline).toUTCString()}` },
        ...(prUrl ? [{ type: "mrkdwn", text: `*PR*\n<${prUrl}|View PR>` }] : []),
      ],
    },
    ...(trust.flagLines.length > 0
      ? [{
          type: "section",
          text: { type: "mrkdwn", text: `*🚩 Supply-chain flags*\n${trust.flagLines.join("\n")}` },
        }]
      : []),
    ...(trust.deductionCount > 0
      ? [{
          type: "context",
          elements: [{ type: "mrkdwn", text: `⚠️ Trust deductions: ${trust.deductions.replace(/\n/g, " | ")}` }],
        }]
      : []),
    { type: "divider" },
    {
      type: "section",
      text: { type: "mrkdwn", text: `*Quorum ID:* \`${quorumId}\`\n_Only votes from configured quorum members are counted._` },
    },
    {
      type: "actions",
      block_id: `quorum_vote_${quorumId}`,
      elements: [
        {
          type: "button",
          text:        { type: "plain_text", text: "✅ Approve Override", emoji: true },
          style:       "primary",
          action_id:   "approve",
          value:       quorumId,
          confirm: {
            title:   { type: "plain_text", text: "Confirm vote" },
            text:    { type: "mrkdwn", text: `You are approving the override for *${pkg}@${version}*. This decision is logged and auditable.` },
            confirm: { type: "plain_text", text: "Yes, approve" },
            deny:    { type: "plain_text", text: "Cancel" },
          },
        },
        {
          type: "button",
          text:      { type: "plain_text", text: "❌ Deny Override", emoji: true },
          style:     "danger",
          action_id: "deny",
          value:     quorumId,
          confirm: {
            title:   { type: "plain_text", text: "Confirm vote" },
            text:    { type: "mrkdwn", text: `You are denying the override for *${pkg}@${version}*. The PR will remain blocked.` },
            confirm: { type: "plain_text", text: "Yes, deny" },
            deny:    { type: "plain_text", text: "Cancel" },
          },
        },
      ],
    },
  ];

  return blocks;
}

function buildSlackVerdictBlocks(p) {
  const { quorumId, pkg, version, verdict, tally, voterLines, decidedAt, trust, updateReason } = p;
  const icon  = verdict === "APPROVED" ? "✅" : verdict === "DENIED" ? "🚫" : "⏱️";

  return [
    {
      type: "header",
      text: { type: "plain_text", text: `${icon} Quorum ${verdict} — ${pkg}@${version}`, emoji: true },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Quorum ID:* \`${quorumId}\`` },
        { type: "mrkdwn", text: `*Final verdict:* \`${verdict}\`` },
        { type: "mrkdwn", text: `*✅ Approve:* ${tally.approve}` },
        { type: "mrkdwn", text: `*❌ Deny:* ${tally.deny}` },
        { type: "mrkdwn", text: `*⬜ Abstain:* ${tally.abstain}` },
        { type: "mrkdwn", text: `*Decided:* ${new Date(decidedAt).toUTCString()}` },
        { type: "mrkdwn", text: `*🔒 Trust:* ${trust.label}` },
      ],
    },
    ...(voterLines.length > 0
      ? [{ type: "section", text: { type: "mrkdwn", text: `*Voter detail:*\n${voterLines.join("\n")}` } }]
      : []),
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: verdict === "APPROVED"
          ? `⚠️ *Override approved.* This dependency was flagged but quorum voted to allow it.`
          : `🚫 *Override denied.* This dependency remains blocked.`,
      },
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Trust level computation (platform-agnostic)
// ─────────────────────────────────────────────────────────────────────────────

function computeTrustLevel(trustResult) {
  const sig   = trustResult.signature || {};
  const chk   = trustResult.checksum  || {};
  const flags = trustResult.flags     || {};

  let score = 100;
  const deductions = [];

  if (!sig.present) { score -= 40; deductions.push("-40 no cryptographic signature"); }
  else if (sig.strength === "weak") { score -= 20; deductions.push("-20 weak signature algorithm"); }
  if (sig.present && sig.verified === false) { score -= 10; deductions.push("-10 signature verification failed"); }

  if (!chk.present) { score -= 15; deductions.push("-15 no published checksum"); }
  else if (chk.verified === false) { score -= 15; deductions.push("-15 checksum mismatch — possible tampering"); }

  if (flags.typosquatting)      { score -= 25; deductions.push("-25 typosquatting"); }
  if (flags.behavior_change)    { score -= 20; deductions.push("-20 behavior change"); }
  if (flags.author_reputation)  { score -= 15; deductions.push("-15 author reputation"); }
  if (flags.provenance_activity){ score -= 10; deductions.push("-10 provenance/activity"); }

  score = Math.max(0, score);
  const band     = score >= 80 ? "HIGH" : score >= 50 ? "MEDIUM" : "LOW";
  const bandIcon = { HIGH: "🟢", MEDIUM: "🟡", LOW: "🔴" }[band];

  const chkStatusLine = !chk.present
    ? "🚫 No checksum published"
    : chk.verified ? `✅ Verified (${chk.algorithm ?? "unknown"})` : `❌ Mismatch — ${chk.algorithm ?? "unknown"} hash does not match`;

  const flagLines = [
    flags.typosquatting      ? "⚠️ Typosquatting risk"                                   : null,
    flags.behavior_change    ? "⚠️ New permissions / network access vs prior version"    : null,
    flags.author_reputation  ? "⚠️ New or changed maintainer / inactivity surge"        : null,
    flags.provenance_activity? "⚠️ No verifiable commit history or SLSA attestation"    : null,
  ].filter(Boolean);

  return {
    score, band, bandIcon,
    label:          `${bandIcon} ${band} (${score}/100)`,
    deductions:     deductions.length ? deductions.join("\n") : "none",
    deductionCount: deductions.length,
    sigPresent:     sig.present   ?? false,
    sigVerified:    sig.verified  ?? null,
    sigAlgorithm:   sig.algorithm ?? "unknown",
    sigStrength:    sig.strength  ?? "none",
    sigKeyId:       sig.keyid     ?? "n/a",
    sigStatusLine:  sig.present
      ? (sig.verified ? `✅ Valid — ${sig.algorithm ?? "unknown"} (${sig.strength ?? "?"})` : `❌ Invalid — ${sig.algorithm ?? "unknown"}`)
      : "🚫 No signature",
    chkPresent:    chk.present   ?? false,
    chkVerified:   chk.verified  ?? null,
    chkAlgorithm:  chk.algorithm ?? "unknown",
    chkStatusLine,
    flagLines,
    flagSummary: flagLines.length ? flagLines.join("\n") : "none",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Quorum logic (platform-agnostic)
// ─────────────────────────────────────────────────────────────────────────────

function requiredVotes(quorumSize, threshold) {
  return Math.floor(quorumSize * threshold) + 1;
}

function isoToUnix(iso) {
  return Math.floor(new Date(iso).getTime() / 1000);
}

function evaluateVotes(tally, quorumSize, threshold) {
  const needed = requiredVotes(quorumSize, threshold);
  if (tally.approve >= needed) return "APPROVED";
  if (tally.deny    >= needed) return "DENIED";
  return null;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function buildUpdateReason(prTitle, prBody) {
  const title = (prTitle || "").trim();
  const body  = (prBody  || "").trim();
  if (!title && !body) return "_No PR title or description provided._";
  const parts = [];
  if (title) parts.push(`**${title}**`);
  if (body) {
    const cleaned = body.replace(/<!--[\s\S]*?-->/g, "").replace(/!\[.*?\]\(.*?\)/g, "").trim();
    if (cleaned) parts.push(cleaned.length > 800 ? cleaned.slice(0, 797) + "…" : cleaned);
  }
  return parts.join("\n\n");
}

async function pollUntilDecision(adapter, cfg, messageId, quorumId, voteStore) {
  const POLL_MS    = 30_000;
  const deadline   = new Date(Date.now() + cfg.deadlineHours * 3_600_000);
  const quorumSize = cfg.members.length;

  console.log(`[QUORUM] Polling for votes on ${messageId} | deadline: ${deadline.toISOString()} | platform: ${cfg.platform}`);

  while (new Date() < deadline) {
    await sleep(POLL_MS);
    const tally  = await adapter.collectVotes(cfg, messageId, cfg.members, voteStore);
    const verdict = evaluateVotes(tally, quorumSize, cfg.threshold);
    console.log(`[QUORUM] Tally — ✅ ${tally.approve} ❌ ${tally.deny} ⬜ ${tally.abstain}` + (verdict ? ` → ${verdict}` : " → pending"));
    if (verdict) return { verdict, tally, decidedAt: new Date().toISOString() };
  }

  const tally = await adapter.collectVotes(cfg, messageId, cfg.members, voteStore);
  console.log(`[QUORUM] Deadline reached — failing closed`);
  return { verdict: "EXPIRED", tally, decidedAt: new Date().toISOString() };
}

async function buildVoterLines(adapter, cfg, tally) {
  const lines = [];
  for (const id of tally.approveIds) {
    const name = await adapter.resolveVoterName(cfg, id);
    lines.push(`✅ ${name} (${id})`);
  }
  for (const id of tally.denyIds) {
    const name = await adapter.resolveVoterName(cfg, id);
    lines.push(`❌ ${name} (${id})`);
  }
  for (const id of tally.abstainIds) {
    const name = await adapter.resolveVoterName(cfg, id);
    lines.push(`⬜ ${name} (${id}) — abstained`);
  }
  // Also include any webhook-provided voter names (Teams/Slack)
  if (tally.rawVotes) {
    const accountedFor = new Set([...tally.approveIds, ...tally.denyIds, ...tally.abstainIds]);
    for (const v of tally.rawVotes) {
      if (!accountedFor.has(v.member_id)) {
        lines.push(`${v.vote === "approve" ? "✅" : "❌"} ${v.member_name || v.member_id} (${v.member_id})`);
      }
    }
  }
  return lines;
}

// ─────────────────────────────────────────────────────────────────────────────
// Google Sheets audit log
// ─────────────────────────────────────────────────────────────────────────────

async function appendAuditRow(cfg, row) {
  if (!cfg.sheets.credentials || !cfg.sheets.spreadsheetId) {
    console.log("[QUORUM] Sheets not configured — audit row skipped");
    return;
  }
  const sa    = JSON.parse(Buffer.from(cfg.sheets.credentials, "base64").toString("utf8"));
  const token = await getServiceAccountToken(sa, ["https://www.googleapis.com/auth/spreadsheets"]);
  const range = `${cfg.sheets.sheetName}!A:AJ`;

  await httpRequest({
    hostname: "sheets.googleapis.com",
    path:     `/v4/spreadsheets/${cfg.sheets.spreadsheetId}/values/${encodeURIComponent(range)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`,
    method:   "POST",
    headers:  { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  }, JSON.stringify({ values: [Object.values(row)] }));

  console.log("[QUORUM] Audit row written to Google Sheets");
}

async function getServiceAccountToken(sa, scopes) {
  const now     = Math.floor(Date.now() / 1000);
  const header  = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iss: sa.client_email, scope: scopes.join(" "), aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const sigInput = `${header}.${payload}`;
  const sign     = crypto.createSign("RSA-SHA256");
  sign.update(sigInput);
  const sig = sign.sign(sa.private_key, "base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const jwt = `${sigInput}.${sig}`;
  const resp = await httpRequest({ hostname: "oauth2.googleapis.com", path: "/token", method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" } },
    `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
  );
  return resp.access_token;
}

function b64url(str) {
  return Buffer.from(str).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ─────────────────────────────────────────────────────────────────────────────
// GitHub PR comment
// ─────────────────────────────────────────────────────────────────────────────

async function postGitHubResult(cfg, pkg, version, verdict, tally, quorumId, messageId, threadUrl, sourceRepo, trust) {
  if (!cfg.github.prNumber || !cfg.github.repo) return;
  const [owner, repo] = cfg.github.repo.split("/");
  const icon   = { APPROVED: "✅", DENIED: "🚫", EXPIRED: "⏱️" }[verdict] ?? "❓";
  const marker = `<!-- quorum:${quorumId} -->`;

  const platformLabel = { discord: "Discord", teams: "MS Teams", slack: "Slack" }[cfg.platform] ?? cfg.platform;

  const body = [
    marker,
    `## ${icon} Quorum ${verdict} — \`${pkg}@${version}\``,
    `| Field | Value |`,
    `|-------|-------|`,
    `| Quorum ID | \`${quorumId}\` |`,
    `| Platform | ${platformLabel} |`,
    `| Source repository | \`${sourceRepo || "unknown"}\` |`,
    `| Trust level | ${trust.label} |`,
    `| Signature | ${trust.sigStatusLine} |`,
    `| Checksum | ${trust.chkStatusLine} |`,
    trust.flagLines.length > 0
      ? `| Supply-chain flags | ${trust.flagLines.join(", ")} |`
      : null,
    `| Verdict | \`${verdict}\` |`,
    `| ✅ Approve | ${tally.approve} |`,
    `| ❌ Deny | ${tally.deny} |`,
    `| ⬜ Abstain | ${tally.abstain} |`,
    threadUrl ? `| ${platformLabel} thread | [View vote](${threadUrl}) |` : null,
    `| Run | [${cfg.github.runId}](${cfg.github.serverUrl}/${cfg.github.repo}/actions/runs/${cfg.github.runId}) |`,
    verdict === "APPROVED"
      ? "\n> ⚠️ **Override approved.** This dependency was flagged but quorum voted to allow it."
      : "\n> 🚫 **Override denied.** This dependency remains blocked.",
  ].filter(Boolean).join("\n");

  const ghHeaders = {
    Authorization:  `Bearer ${cfg.github.token}`,
    Accept:         "application/vnd.github+json",
    "Content-Type": "application/json",
    "User-Agent":   "QuorumBot/2.0",
    "X-GitHub-Api-Version": "2022-11-28",
  };

  let existingId = null;
  try {
    const comments = await httpRequest({ hostname: "api.github.com", path: `/repos/${owner}/${repo}/issues/${cfg.github.prNumber}/comments?per_page=100`, method: "GET", headers: ghHeaders });
    const found    = comments.find?.((c) => c.body?.includes(marker));
    if (found) existingId = found.id;
  } catch { /* best-effort */ }

  const ghPath = existingId
    ? `/repos/${owner}/${repo}/issues/comments/${existingId}`
    : `/repos/${owner}/${repo}/issues/${cfg.github.prNumber}/comments`;

  await httpRequest({ hostname: "api.github.com", path: ghPath, method: existingId ? "PATCH" : "POST", headers: ghHeaders }, JSON.stringify({ body }));
  console.log(`[QUORUM] GitHub PR comment ${existingId ? "updated" : "posted"}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function main() {
  const trustResult = JSON.parse(fs.readFileSync("trust-result.json", "utf8"));
  const { package: pkg, version, ecosystem, outcome: trustOutcome } = trustResult;

  if (!["blocked", "quarantined"].includes(trustOutcome)) {
    console.log(`[QUORUM] Outcome '${trustOutcome}' — no quorum required. Exiting 0.`);
    process.exit(0);
  }

  const cfg     = loadConfig();
  const adapter = getAdapter(cfg.platform);
  console.log(`[QUORUM] Platform: ${cfg.platform.toUpperCase()}`);

  const sourceRepo   = cfg.github.registryUrl || trustResult.source_repository || trustResult.registry_url || "";
  const trust        = computeTrustLevel(trustResult);
  const quorumId     = `QR-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
  const deadline     = new Date(Date.now() + cfg.deadlineHours * 3_600_000).toISOString();
  const prUrl        = cfg.github.prNumber ? `${cfg.github.serverUrl}/${cfg.github.repo}/pull/${cfg.github.prNumber}` : null;
  const updateReason = buildUpdateReason(cfg.github.prTitle, cfg.github.prBody);

  console.log(`[QUORUM] ${quorumId} — posting vote request for ${pkg}@${version}`);
  console.log(`[QUORUM] Trust: ${trust.label} | Outcome: ${trustOutcome}`);

  // ── Start vote server for Teams/Slack push voting ─────────────────────────
  let voteStore = null;
  let server    = null;
  if (cfg.platform !== "discord") {
    ({ voteStore, server } = startVoteServer(cfg.platform, quorumId));
  }

  // ── Build platform-specific message payload ───────────────────────────────
  const msgPayload = {
    quorumId, pkg, version, ecosystem, trustOutcome,
    cfg, deadline, prUrl, sourceRepo, trust, updateReason,
    // Slack/Teams specific
    verdict: null, tally: null, voterLines: null, decidedAt: null,
  };

  // ── Post initial vote request ─────────────────────────────────────────────
  let embedPayload;
  if (cfg.platform === "discord") {
    embedPayload = { embed: buildDiscordPendingEmbed(msgPayload) };
  } else if (cfg.platform === "teams") {
    // For Teams the full card is the payload
    embedPayload = msgPayload;
  } else {
    embedPayload = msgPayload;
  }

  const { messageId, threadUrl } = await adapter.postVoteRequest(cfg, embedPayload);
  console.log(`[QUORUM] Message posted. ID: ${messageId}`);

  // ── Poll until majority or deadline ──────────────────────────────────────
  const { verdict, tally, decidedAt } = await pollUntilDecision(
    adapter, cfg, messageId, quorumId, voteStore
  );

  // ── Resolve voter names ───────────────────────────────────────────────────
  const voterLines = await buildVoterLines(adapter, cfg, tally);

  // ── Update notification with final verdict ────────────────────────────────
  const verdictPayload = { ...msgPayload, verdict, tally, voterLines, decidedAt };

  if (cfg.platform === "discord") {
    await adapter.updateWithVerdict(cfg, messageId, {
      embed: buildDiscordVerdictEmbed(verdictPayload),
    });
  } else {
    await adapter.updateWithVerdict(cfg, messageId, verdictPayload);
  }
  console.log(`[QUORUM] Notification updated: ${verdict}`);

  // Shut down vote server
  if (server) server.close();

  // ── Audit log ─────────────────────────────────────────────────────────────
  const auditRow = {
    quorum_id:            quorumId,
    package:              pkg,
    version,
    ecosystem,
    source_repository:    sourceRepo || "unknown",
    platform:             cfg.platform,
    notification_message_id: messageId,
    trust_level:          trust.band,
    trust_level_score:    trust.score,
    sig_status:           trust.sigPresent ? (trust.sigVerified ? "valid" : "invalid") : "none",
    sig_algorithm:        trust.sigAlgorithm,
    sig_strength:         trust.sigStrength,
    sig_key_id:           trust.sigKeyId,
    chk_status:           trust.chkPresent ? (trust.chkVerified ? "verified" : "mismatch") : "none",
    chk_algorithm:        trust.chkAlgorithm,
    flag_typosquatting:   trustResult.flags?.typosquatting      ? "true" : "false",
    flag_behavior_change: trustResult.flags?.behavior_change    ? "true" : "false",
    flag_author_rep:      trustResult.flags?.author_reputation  ? "true" : "false",
    flag_provenance:      trustResult.flags?.provenance_activity? "true" : "false",
    trust_deductions:     trust.deductions.replace(/\n/g, " | "),
    trust_outcome:        trustOutcome,
    update_reason:        updateReason.replace(/\n+/g, " | ").slice(0, 500),
    initiated_at:         new Date().toISOString(),
    deadline,
    quorum_size:          cfg.members.length,
    threshold:            cfg.threshold,
    approve_count:        tally.approve,
    deny_count:           tally.deny,
    abstain_count:        tally.abstain,
    final_verdict:        verdict,
    decided_at:           decidedAt,
    decided_by:           verdict === "EXPIRED" ? "DEADLINE" : "QUORUM_VOTE",
    voter_detail:         voterLines.join(" | "),
    discord_message_id:   messageId,
    github_pr:            prUrl || "",
    run_id:               cfg.github.runId,
    override_rationale:   verdict === "APPROVED"
      ? `Quorum override: ${tally.approve}/${cfg.members.length} approved`
      : `Override rejected or expired: ${tally.deny} deny, ${tally.abstain} abstain`,
  };

  await appendAuditRow(cfg, auditRow);

  // ── GitHub PR comment ─────────────────────────────────────────────────────
  await postGitHubResult(cfg, pkg, version, verdict, tally, quorumId, messageId, threadUrl, sourceRepo, trust);

  // ── Exit ──────────────────────────────────────────────────────────────────
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
