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
//   PKG_REGISTRY_URL        URL of the registry/repository the package was fetched from
//                           (e.g. https://registry.npmjs.org, https://pypi.org/simple)
//
// trust-result.json fields consumed by this engine:
//   package, version, ecosystem, outcome      — standard oss-trust fields
//   source_repository                         — URL of the registry the package came from
//   signature.present    bool                 — whether any cryptographic signature exists
//   signature.algorithm  string               — e.g. "ed25519", "rsa-sha256", "none"
//   signature.verified   bool                 — whether the signature validated successfully
//   signature.keyid      string               — key fingerprint / Sigstore log ID
//   signature.strength   "strong"|"weak"|"none"
//                         strong = ed25519 / ECDSA-P256+ / RSA≥3072 / Sigstore
//                         weak   = RSA<3072 / SHA-1 / MD5 / GPG without transparency log
//                         none   = no signature found
//
// Computed trust level (0–100) surfaced in the embed:
//   Starts at 100; deductions applied in order:
//     -40   No cryptographic signature
//     -20   Signature present but weak algorithm
//     -10   Signature present but verification failed
//   Score bands:
//     80–100  HIGH
//     50–79   MEDIUM
//     0–49    LOW
//
// Audit record schema (one row per quorum event):
//   quorum_id | package | version | ecosystem | source_repository |
//   trust_level | trust_level_score |
//   sig_status | sig_algorithm | sig_strength | sig_key_id |
//   chk_status | chk_algorithm |
//   flag_typosquatting | flag_behavior_change | flag_author_reputation | flag_provenance |
//   trust_deductions | trust_outcome | update_reason | initiated_at | deadline |
//   quorum_size | threshold | approve_count | deny_count | abstain_count |
//   final_verdict | decided_at | decided_by | voter_detail |
//   discord_message_id | github_pr | run_id | override_rationale

"use strict";

const https   = require("https");
const fs      = require("fs");
const crypto  = require("crypto");

// ── Config ────────────────────────────────────────────────────────────────────

function loadConfig() {
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
    members,
    threshold:     parseFloat(process.env.QUORUM_THRESHOLD      || fileConfig.threshold      || "0.5"),
    deadlineHours: parseInt(  process.env.QUORUM_DEADLINE_HOURS || fileConfig.deadlineHours  || "24", 10),
    discord: {
      token:     requireEnv("DISCORD_BOT_TOKEN"),
      channelId: requireEnv("DISCORD_CHANNEL_ID"),
      guildId:   requireEnv("DISCORD_GUILD_ID"),
    },
    sheets: {
      credentials:   process.env.SHEETS_CREDENTIALS    || null,
      spreadsheetId: process.env.SHEETS_SPREADSHEET_ID || null,
      sheetName:     process.env.SHEETS_SHEET_NAME      || "QuorumAuditLog",
    },
    github: {
      token:     requireEnv("GITHUB_TOKEN"),
      repo:      process.env.GITHUB_REPOSITORY || "",
      prNumber:  process.env.PR_NUMBER         || "",
      runId:     process.env.GITHUB_RUN_ID     || "",
      serverUrl: process.env.GITHUB_SERVER_URL || "https://github.com",
      // PR title + body: the stated reason for the dependency update.
      prTitle:   process.env.PR_TITLE || "",
      prBody:    process.env.PR_BODY  || "",
      // Source registry URL passed explicitly from the workflow.
      // Falls back to a value in trust-result.json if not set here.
      registryUrl: process.env.PKG_REGISTRY_URL || "",
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

  _opts(method, path) {
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

  post(path, body)  { return request(this._opts("POST",   path), body); }
  patch(path, body) { return request(this._opts("PATCH",  path), body); }
  get(path)         { return request(this._opts("GET",    path)); }
  put(path)         { return request(this._opts("PUT",    path)); }
  delete(path)      { return request(this._opts("DELETE", path)); }

  async postEmbed(embed) {
    return this.post(`/channels/${this.channelId}/messages`, { embeds: [embed] });
  }
  async updateEmbed(messageId, embed) {
    return this.patch(`/channels/${this.channelId}/messages/${messageId}`, { embeds: [embed] });
  }
  async addReaction(messageId, emoji) {
    return this.put(`/channels/${this.channelId}/messages/${messageId}/reactions/${encodeURIComponent(emoji)}/@me`);
  }
  async getReactions(messageId, emoji) {
    return this.get(`/channels/${this.channelId}/messages/${messageId}/reactions/${encodeURIComponent(emoji)}?limit=100`);
  }
  async getUser(userId) {
    try { return await this.get(`/users/${userId}`); }
    catch { return { id: userId, username: userId }; }
  }
}

// ── Trust level computation ───────────────────────────────────────────────────
//
// Reads trust-result.json and computes a 0–100 composite score across six
// signal categories. The score drives the embed color, the band label shown
// to voters, and is persisted in the audit log for trend analysis.
//
// trust-result.json fields consumed (all optional — missing = not penalised):
//
//   Integrity / cryptographic signals
//   ─────────────────────────────────
//   signature.present    bool     — whether any cryptographic signature exists
//   signature.algorithm  string   — e.g. "ed25519", "rsa-sha256", "none"
//   signature.verified   bool     — whether the signature validated
//   signature.keyid      string   — key fingerprint / Sigstore log ID
//   signature.strength   string   — "strong" | "weak" | "none"
//                         strong = ed25519 / ECDSA-P256+ / RSA≥3072 / Sigstore
//                         weak   = RSA<3072 / SHA-1 / MD5 / GPG w/o transparency
//   checksum.present     bool     — whether a published checksum exists
//   checksum.verified    bool     — whether downloaded hash matches published hash
//   checksum.algorithm   string   — e.g. "sha256", "md5"
//
//   Provenance / supply-chain signals
//   ──────────────────────────────────
//   flags.typosquatting         bool   — name similarity to known popular package
//   flags.behavior_change       bool   — new version requests permissions/network
//                                        access not present in previous version
//   flags.author_reputation     bool   — new/changed maintainer or inactivity surge
//                                        (possible account hijack indicator)
//   flags.provenance_activity   bool   — repo has no commit history, dead issues,
//                                        or no verifiable SLSA provenance
//
// Deduction table (applied in order, cumulative, floor at 0):
//
//   Cryptographic integrity
//   −40   No cryptographic signature
//   −20   Signature present but weak algorithm
//   −10   Signature present but verification failed
//   −15   No published checksum  OR  checksum mismatch
//
//   Provenance and supply-chain
//   −25   Typosquatting flag (name closely resembles a popular package)
//   −20   Behavioral change flag (new permissions / network access)
//   −15   Author reputation flag (new maintainer / inactivity surge)
//   −10   Provenance/activity flag (dead repo / no SLSA attestation)
//
// Score bands:
//   80–100  🟢 HIGH    — low additional risk
//   50–79   🟡 MEDIUM  — elevated risk; voters should review carefully
//   0–49    🔴 LOW     — high risk; strong justification required

function computeTrustLevel(trustResult) {
  const sig   = trustResult.signature || {};
  const chk   = trustResult.checksum  || {};
  const flags = trustResult.flags     || {};

  let score = 100;
  const deductions = [];

  // ── Cryptographic signature ─────────────────────────────────────────────
  if (!sig.present) {
    score -= 40;
    deductions.push("-40 no cryptographic signature");
  } else if (sig.strength === "weak") {
    score -= 20;
    deductions.push("-20 weak signature algorithm");
  }
  if (sig.present && sig.verified === false) {
    score -= 10;
    deductions.push("-10 signature verification failed");
  }

  // ── Checksum integrity ──────────────────────────────────────────────────
  // Penalise either: no checksum published at all, or checksum present but
  // the downloaded file hash does not match (tamper indicator).
  if (!chk.present) {
    score -= 15;
    deductions.push("-15 no published checksum");
  } else if (chk.verified === false) {
    score -= 15;
    deductions.push("-15 checksum mismatch — possible tampering");
  }

  // ── Provenance and supply-chain flags ───────────────────────────────────
  if (flags.typosquatting) {
    score -= 25;
    deductions.push("-25 typosquatting — name resembles a known package");
  }
  if (flags.behavior_change) {
    score -= 20;
    deductions.push("-20 behavior change — new permissions or network access");
  }
  if (flags.author_reputation) {
    score -= 15;
    deductions.push("-15 author reputation — new maintainer or inactivity surge");
  }
  if (flags.provenance_activity) {
    score -= 10;
    deductions.push("-10 provenance — no commit history or SLSA attestation");
  }

  score = Math.max(0, score);

  const band     = score >= 80 ? "HIGH" : score >= 50 ? "MEDIUM" : "LOW";
  const bandIcon = { HIGH: "🟢", MEDIUM: "🟡", LOW: "🔴" }[band];

  // ── Checksum display line ───────────────────────────────────────────────
  const chkStatusLine = !chk.present
    ? "🚫 No checksum published"
    : chk.verified
      ? `✅ Verified (${chk.algorithm ?? "unknown"})`
      : `❌ Mismatch — ${chk.algorithm ?? "unknown"} hash does not match`;

  // ── Flag summary for embed display ─────────────────────────────────────
  const flagLines = [
    flags.typosquatting      ? "⚠️ Typosquatting risk"                          : null,
    flags.behavior_change    ? "⚠️ New permissions / network access vs prior version" : null,
    flags.author_reputation  ? "⚠️ New or changed maintainer / inactivity surge" : null,
    flags.provenance_activity? "⚠️ No verifiable commit history or SLSA attestation" : null,
  ].filter(Boolean);

  return {
    score,
    band,
    bandIcon,
    label:          `${bandIcon} ${band} (${score}/100)`,
    deductions:     deductions.length ? deductions.join("\n") : "none",
    deductionCount: deductions.length,

    // Signature
    sigPresent:    sig.present   ?? false,
    sigVerified:   sig.verified  ?? null,
    sigAlgorithm:  sig.algorithm ?? "unknown",
    sigStrength:   sig.strength  ?? "none",
    sigKeyId:      sig.keyid     ?? "n/a",
    sigStatusLine: sig.present
      ? (sig.verified
          ? `✅ Valid — ${sig.algorithm ?? "unknown"} (${sig.strength ?? "?"})`
          : `❌ Invalid / unverifiable — ${sig.algorithm ?? "unknown"}`)
      : "🚫 No signature",

    // Checksum
    chkPresent:    chk.present  ?? false,
    chkVerified:   chk.verified ?? null,
    chkAlgorithm:  chk.algorithm ?? "unknown",
    chkStatusLine,

    // Flags
    flagLines,
    flagSummary: flagLines.length ? flagLines.join("\n") : "none",
  };
}

// ── Embed helpers ─────────────────────────────────────────────────────────────

const COLOR = {
  APPROVED:   0x22C55E,
  DENIED:     0xEF4444,
  EXPIRED:    0x6B7280,
  BLOCKED:    0xDC2626,
  QUARANTINE: 0xF97316,
};

// Trust-level band overrides the default embed color so the severity is
// immediately visible even before reading the text.
const TRUST_COLOR = { HIGH: 0x22C55E, MEDIUM: 0xF59E0B, LOW: 0xDC2626 };

function buildUpdateReason(prTitle, prBody) {
  const title = (prTitle || "").trim();
  const body  = (prBody  || "").trim();
  if (!title && !body) return "_No PR title or description provided._";
  const parts = [];
  if (title) parts.push(`**${title}**`);
  if (body) {
    const cleaned = body
      .replace(/<!--[\s\S]*?-->/g, "")
      .replace(/!\[.*?\]\(.*?\)/g, "")
      .trim();
    if (cleaned) parts.push(cleaned.length > 800 ? cleaned.slice(0, 797) + "…" : cleaned);
  }
  return parts.join("\n\n");
}

function pendingEmbed(quorumId, pkg, version, ecosystem, trustOutcome,
                      cfg, deadlineIso, prUrl, sourceRepo, trust) {
  const needed       = requiredVotes(cfg.members.length, cfg.threshold);
  const roster       = cfg.members.map((id) => `<@${id}>`).join("  ");
  const updateReason = buildUpdateReason(cfg.github.prTitle, cfg.github.prBody);

  // Color is driven by trust level band, not just blocked/quarantined
  const embedColor = TRUST_COLOR[trust.band] ??
    (trustOutcome === "blocked" ? COLOR.BLOCKED : COLOR.QUARANTINE);

  return {
    title: `🔐 Quorum Override Request — \`${pkg}@${version}\``,
    color: embedColor,
    description: [
      `The OSS Trust Framework flagged **\`${pkg}@${version}\`** (${ecosystem}) as **\`${trustOutcome.toUpperCase()}\`**.`,
      `A **simple majority** quorum is required to override and allow this dependency into the PR.`,
    ].join("\n"),
    fields: [
      // ── Reason for update — most important voter context ─────────────────
      {
        name:   "📝 Reason for update",
        value:  updateReason,
        inline: false,
      },
      // ── Source and cryptographic trust context ───────────────────────────
      {
        name:   "📦 Source repository",
        value:  sourceRepo ? `\`${sourceRepo}\`` : "_Not provided — check PR for origin._",
        inline: false,
      },
      {
        name:   "🔒 Trust level",
        value:  trust.label,
        inline: true,
      },
      {
        name:   "🔏 Signature status",
        value:  trust.sigStatusLine,
        inline: true,
      },
      {
        name:   "🔑 Key / log ID",
        value:  trust.sigKeyId !== "n/a" ? `\`${trust.sigKeyId}\`` : "_n/a_",
        inline: true,
      },
      {
        name:   "🧮 Checksum",
        value:  trust.chkStatusLine,
        inline: false,
      },
      trust.flagLines.length > 0
        ? {
            name:   "🚩 Supply-chain flags",
            value:  trust.flagSummary,
            inline: false,
          }
        : null,
      trust.deductionCount > 0
        ? {
            name:   "⚠️ Trust level deductions",
            value:  trust.deductions,
            inline: false,
          }
        : null,
      // ── Vote metadata ────────────────────────────────────────────────────
      { name: "Quorum ID",     value: `\`${quorumId}\``,                   inline: true },
      { name: "Trust Outcome", value: `\`${trustOutcome.toUpperCase()}\``, inline: true },
      { name: "Ecosystem",     value: `\`${ecosystem}\``,                  inline: true },
      { name: "PR",            value: prUrl || "n/a",                      inline: true },
      { name: "Quorum Size",   value: `${cfg.members.length} eligible`,    inline: true },
      { name: "Votes Needed",  value: `${needed} to approve or deny`,      inline: true },
      { name: "Deadline",      value: `<t:${isoToUnix(deadlineIso)}:R>`,   inline: true },
      {
        name:   "How to vote",
        value:  "React with ✅ to **approve** the override, or ❌ to **deny** it.\nOnly votes from the quorum roster below are counted.",
        inline: false,
      },
      { name: "Eligible voters", value: roster || "None configured", inline: false },
    ].filter(Boolean),   // remove null entries (conditional deductions field)
    footer: { text: "HITL Quorum Framework · Simple Majority (>50%) · Chris Gillham" },
    timestamp: new Date().toISOString(),
  };
}

function resolvedEmbed(quorumId, pkg, version, ecosystem, trustOutcome,
                        verdict, tally, voterLines, decidedAt, cfg, sourceRepo, trust) {
  const icon  = verdict === "APPROVED" ? "✅" : verdict === "DENIED" ? "🚫" : "⏱️";
  const color = verdict === "APPROVED" ? COLOR.APPROVED
              : verdict === "DENIED"   ? COLOR.DENIED
              :                          COLOR.EXPIRED;
  const updateReason = buildUpdateReason(cfg.github.prTitle, cfg.github.prBody);

  return {
    title: `${icon} Quorum ${verdict} — \`${pkg}@${version}\``,
    color,
    fields: [
      { name: "📝 Reason for update",    value: updateReason,                                                    inline: false },
      { name: "📦 Source repository",    value: sourceRepo ? `\`${sourceRepo}\`` : "_Not provided_",             inline: false },
      { name: "🔒 Trust level",          value: trust.label,                                                     inline: true  },
      { name: "🔏 Signature status",     value: trust.sigStatusLine,                                             inline: true  },
      { name: "🔑 Key / log ID",         value: trust.sigKeyId !== "n/a" ? `\`${trust.sigKeyId}\`` : "_n/a_",   inline: true  },
      { name: "🧮 Checksum",             value: trust.chkStatusLine,                                             inline: false },
      trust.flagLines.length > 0
        ? { name: "🚩 Supply-chain flags", value: trust.flagSummary,  inline: false }
        : null,
      { name: "Quorum ID",               value: `\`${quorumId}\``,                                              inline: true  },
      { name: "Final Verdict",           value: `\`${verdict}\``,                                               inline: true  },
      { name: "Trust Outcome",           value: `\`${trustOutcome.toUpperCase()}\``,                            inline: true  },
      { name: "✅ Approve",              value: `${tally.approve}`,                                             inline: true  },
      { name: "❌ Deny",                 value: `${tally.deny}`,                                                inline: true  },
      { name: "⬜ Abstain",              value: `${tally.abstain}`,                                             inline: true  },
      { name: "Voter detail",            value: voterLines.join("\n") || "None",                                inline: false },
    ].filter(Boolean),
    footer: { text: `Decided at ${decidedAt} · HITL Quorum Framework · Chris Gillham` },
    timestamp: decidedAt,
  };
}

// ── Quorum logic ──────────────────────────────────────────────────────────────

function requiredVotes(quorumSize, threshold) {
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

  const memberSet  = new Set(quorumMembers);
  const approveIds = (approvers || []).filter((u) => !u.bot && memberSet.has(u.id)).map((u) => u.id);
  const denyIds    = (deniers   || []).filter((u) => !u.bot && memberSet.has(u.id)).map((u) => u.id);

  // Dual-react = deny (more conservative)
  const denySet            = new Set(denyIds);
  const filteredApproveIds = approveIds.filter((id) => !denySet.has(id));
  const abstainIds         = quorumMembers.filter(
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
  return null;
}

async function pollUntilDecision(discord, messageId, quorumId, pkg, version,
                                  ecosystem, trustOutcome, cfg, deadline) {
  const POLL_INTERVAL_MS = 30_000;
  const quorumSize = cfg.members.length;

  console.log(`[QUORUM] ${quorumId} — polling for votes on message ${messageId}`);
  console.log(`[QUORUM] Quorum size: ${quorumSize} | Threshold: ${cfg.threshold} | Deadline: ${deadline}`);

  while (new Date() < new Date(deadline)) {
    await sleep(POLL_INTERVAL_MS);
    const tally   = await collectVotes(discord, messageId, cfg.members);
    const verdict = evaluateVotes(tally, quorumSize, cfg.threshold);
    console.log(
      `[QUORUM] ${quorumId} tally — ✅ ${tally.approve} ❌ ${tally.deny} ⬜ ${tally.abstain}` +
      (verdict ? ` → ${verdict}` : " → pending")
    );
    if (verdict) return { verdict, tally, decidedAt: new Date().toISOString() };
  }

  const tally = await collectVotes(discord, messageId, cfg.members);
  console.log(`[QUORUM] ${quorumId} — deadline reached without majority. Failing closed.`);
  return { verdict: "EXPIRED", tally, decidedAt: new Date().toISOString() };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

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

  const serviceAccount = JSON.parse(
    Buffer.from(cfg.sheets.credentials, "base64").toString("utf8")
  );
  const token = await getServiceAccountToken(serviceAccount, [
    "https://www.googleapis.com/auth/spreadsheets",
  ]);

  // Column range grows with the new fields — use A:Z to future-proof
  const range  = `${cfg.sheets.sheetName}!A:Z`;
  const values = [Object.values(row)];
  const body   = JSON.stringify({ values });
  const opts   = {
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

async function getServiceAccountToken(sa, scopes) {
  const now    = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({
    iss: sa.client_email,
    scope: scopes.join(" "),
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
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
  return Buffer.from(str).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ── GitHub PR comment ─────────────────────────────────────────────────────────

async function postGitHubResult(cfg, pkg, version, verdict, tally,
                                 quorumId, messageId, sourceRepo, trust) {
  if (!cfg.github.prNumber || !cfg.github.repo) return;

  const [owner, repo] = cfg.github.repo.split("/");
  const icon       = { APPROVED: "✅", DENIED: "🚫", EXPIRED: "⏱️" }[verdict] ?? "❓";
  const discordUrl = `https://discord.com/channels/${process.env.DISCORD_GUILD_ID}/${process.env.DISCORD_CHANNEL_ID}/${messageId}`;
  const marker     = `<!-- quorum:${quorumId} -->`;

  const body = [
    marker,
    `## ${icon} Quorum ${verdict} — \`${pkg}@${version}\``,
    `| Field | Value |`,
    `|-------|-------|`,
    `| Quorum ID | \`${quorumId}\` |`,
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
    `| Discord thread | [View vote](${discordUrl}) |`,
    `| Run | [${cfg.github.runId}](${cfg.github.serverUrl}/${cfg.github.repo}/actions/runs/${cfg.github.runId}) |`,
    verdict === "APPROVED"
      ? "\n> ⚠️ **Override approved.** This dependency was flagged by OSS Trust Framework but quorum voted to allow it."
      : "\n> 🚫 **Override denied.** This dependency remains blocked.",
  ].filter(Boolean).join("\n");

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
    const found    = comments.find((c) => c.body?.includes(marker));
    if (found) existingId = found.id;
  } catch { /* best-effort */ }

  const ghPath = existingId
    ? `/repos/${owner}/${repo}/issues/comments/${existingId}`
    : `/repos/${owner}/${repo}/issues/${cfg.github.prNumber}/comments`;

  await request({
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
  }, JSON.stringify({ body }));

  console.log(`[QUORUM] GitHub PR comment ${existingId ? "updated" : "posted"}`);
}

// ── Main entry point ──────────────────────────────────────────────────────────

async function main() {
  const trustResult = JSON.parse(fs.readFileSync("trust-result.json", "utf8"));
  const { package: pkg, version, ecosystem, outcome: trustOutcome } = trustResult;

  if (!["blocked", "quarantined"].includes(trustOutcome)) {
    console.log(`[QUORUM] Trust outcome is '${trustOutcome}' — no quorum required. Exiting 0.`);
    process.exit(0);
  }

  const cfg = loadConfig();

  // ── Resolve source repository ─────────────────────────────────────────────
  // Priority: explicit env var set in workflow → trust-result.json field → unknown
  const sourceRepo = cfg.github.registryUrl
    || trustResult.source_repository
    || trustResult.registry_url
    || "";
  console.log(`[QUORUM] Source repository: ${sourceRepo || "(not provided)"}`);

  // ── Compute trust level from signature data ───────────────────────────────
  const trust = computeTrustLevel(trustResult);
  console.log(`[QUORUM] Trust level: ${trust.label} | Sig: ${trust.sigStatusLine}`);
  if (trust.deductions !== "none") {
    console.log(`[QUORUM] Trust deductions: ${trust.deductions}`);
  }

  const discord  = new DiscordClient(cfg.discord.token, cfg.discord.channelId, cfg.discord.guildId);
  const quorumId = `QR-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
  const deadline = new Date(Date.now() + cfg.deadlineHours * 3_600_000).toISOString();
  const prUrl    = cfg.github.prNumber
    ? `${cfg.github.serverUrl}/${cfg.github.repo}/pull/${cfg.github.prNumber}`
    : null;

  const updateReason = buildUpdateReason(cfg.github.prTitle, cfg.github.prBody);
  console.log(`[QUORUM] Update reason: ${updateReason.slice(0, 120).replace(/\n/g, " ")}`);

  // ── 1. Post quorum request embed ─────────────────────────────────────────
  console.log(`[QUORUM] ${quorumId} — posting quorum request for ${pkg}@${version}`);
  const message = await discord.postEmbed(
    pendingEmbed(quorumId, pkg, version, ecosystem, trustOutcome,
                 cfg, deadline, prUrl, sourceRepo, trust)
  );
  const messageId = message.id;

  // ── 2. Seed vote reactions ────────────────────────────────────────────────
  await discord.addReaction(messageId, "✅");
  await sleep(500);
  await discord.addReaction(messageId, "❌");
  console.log(`[QUORUM] Seed reactions posted. Message ID: ${messageId}`);

  // ── 3. Poll until majority or deadline ───────────────────────────────────
  const { verdict, tally, decidedAt } = await pollUntilDecision(
    discord, messageId, quorumId, pkg, version, ecosystem, trustOutcome, cfg, deadline
  );

  // ── 4. Resolve voter display names ───────────────────────────────────────
  const voterLines = await buildVoterLines(discord, tally);

  // ── 5. Update Discord embed with final verdict ────────────────────────────
  await discord.updateEmbed(
    messageId,
    resolvedEmbed(quorumId, pkg, version, ecosystem, trustOutcome,
                  verdict, tally, voterLines, decidedAt, cfg, sourceRepo, trust)
  );
  console.log(`[QUORUM] Discord embed updated: ${verdict}`);

  // ── 6. Append audit record to Google Sheets ───────────────────────────────
  const auditRow = {
    quorum_id:          quorumId,
    package:            pkg,
    version,
    ecosystem,
    source_repository:  sourceRepo || "unknown",
    trust_level:        trust.band,
    trust_level_score:  trust.score,
    sig_status:         trust.sigPresent
                          ? (trust.sigVerified ? "valid" : "invalid")
                          : "none",
    sig_algorithm:      trust.sigAlgorithm,
    sig_strength:       trust.sigStrength,
    sig_key_id:         trust.sigKeyId,
    chk_status:         trust.chkPresent
                          ? (trust.chkVerified ? "verified" : "mismatch")
                          : "none",
    chk_algorithm:      trust.chkAlgorithm,
    flag_typosquatting:    trustResult.flags?.typosquatting     ? "true" : "false",
    flag_behavior_change:  trustResult.flags?.behavior_change   ? "true" : "false",
    flag_author_reputation:trustResult.flags?.author_reputation ? "true" : "false",
    flag_provenance:       trustResult.flags?.provenance_activity ? "true" : "false",
    trust_deductions:   trust.deductions.replace(/\n/g, " | "),
    trust_outcome:      trustOutcome,
    update_reason:      updateReason.replace(/\n+/g, " | ").slice(0, 500),
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
  await postGitHubResult(cfg, pkg, version, verdict, tally,
                          quorumId, messageId, sourceRepo, trust);

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
