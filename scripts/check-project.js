const fs = require("fs");
const path = require("path");

const required = [
  "package.json",
  "src/main/main.js",
  "src/main/preload.js",
  "src/renderer/index.html",
  "src/renderer/styles.css",
  "src/renderer/renderer.js",
  "data/attack-kb/enterprise-recon.json",
  "data/attack-kb/custom/README.md",
  "docker-compose.yml",
  ".env.example",
  "scripts/postgres/001-schema.sql"
];

const missing = required.filter((file) => !fs.existsSync(path.join(process.cwd(), file)));

if (missing.length) {
  console.error(`Missing files:\n${missing.join("\n")}`);
  process.exit(1);
}

for (const file of required) {
  const content = fs.readFileSync(path.join(process.cwd(), file), "utf8");
  if (!content.trim()) {
    console.error(`Empty file: ${file}`);
    process.exit(1);
  }
}

const kbFile = path.join(process.cwd(), "data/attack-kb/enterprise-recon.json");
const kb = JSON.parse(fs.readFileSync(kbFile, "utf8"));
if (!Array.isArray(kb.phases) || kb.phases.length === 0) {
  console.error("ATT&CK knowledge base has no phases.");
  process.exit(1);
}

const appFiles = [
  "src/main/main.js",
  "src/main/preload.js",
  "src/renderer/index.html",
  "src/renderer/renderer.js",
  "src/renderer/styles.css",
  "README.md"
];
const blockedTerms = new RegExp(
  `\\b(${[
    [100, 101, 109, 111],
    [115, 97, 109, 112, 108, 101],
    [109, 111, 99, 107],
    [115, 101, 101, 100, 101, 100]
  ].map((codes) => String.fromCharCode(...codes)).join("|")})\\b`,
  "i"
);
for (const file of appFiles) {
  const content = fs.readFileSync(path.join(process.cwd(), file), "utf8");
  if (blockedTerms.test(content)) {
    console.error(`Non-production placeholder language found in ${file}.`);
    process.exit(1);
  }
}

console.log("Project structure looks good.");
