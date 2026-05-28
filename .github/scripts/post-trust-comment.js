// .github/scripts/post-trust-comment.js
// Called by the dep-trust-check workflow via actions/github-script.
// Reads trust-result.json and posts or updates a PR comment.

const fs = require("fs");

module.exports = async ({ github, context }) => {
  const result = JSON.parse(fs.readFileSync("trust-result.json", "utf8"));

  const ICONS = {
    approved:        "✅",
    blocked:         "🚫",
    quarantined:     "⚠️",
    hold:            "⏸️",
    pending_quorum:  "🔐",
  };
  const icon = ICONS[result.outcome] ?? "❓";

  // Build gate table rows — pipes are fine here; this is JS, not YAML
  const gateRows = (result.gates ?? [])
    .map((g) => `| ${g.gate} | ${g.passed ? "✅" : "❌"} | ${g.decision} |`)
    .join("\n");

  const gateTable = gateRows.length
    ? `
### Gate results
| Gate | Passed | Decision |
|------|--------|----------|
${gateRows}`
    : "";

  const advisories = (result.advisories ?? []).length
    ? `
### Advisories
${result.advisories.map((a) => `- **${a.id}** — ${a.summary}`).join("\n")}`
    : "";

  const body = [
    `## ${icon} OSS Trust Framework — \`${result.package}@${result.version}\``,
    `**Outcome:** \`${result.outcome.toUpperCase()}\`  `,
    `**Message:** ${result.message}`,
    gateTable,
    advisories,
    `\n<sub>Ecosystem: \`${result.ecosystem}\` · Run: [${context.runId}](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})</sub>`,
  ]
    .filter(Boolean)
    .join("\n");

  // Find an existing bot comment for this package to update rather than spam
  const marker = `<!-- oss-trust:${result.package}@${result.version} -->`;
  const fullBody = `${marker}\n${body}`;

  const { data: comments } = await github.rest.issues.listComments({
    owner:      context.repo.owner,
    repo:       context.repo.repo,
    issue_number: context.issue.number,
  });

  const existing = comments.find(
    (c) => c.user.type === "Bot" && c.body.includes(marker)
  );

  if (existing) {
    await github.rest.issues.updateComment({
      owner:      context.repo.owner,
      repo:       context.repo.repo,
      comment_id: existing.id,
      body:       fullBody,
    });
  } else {
    await github.rest.issues.createComment({
      owner:        context.repo.owner,
      repo:         context.repo.repo,
      issue_number: context.issue.number,
      body:         fullBody,
    });
  }
};
