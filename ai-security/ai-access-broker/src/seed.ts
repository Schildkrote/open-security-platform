import { getDB } from "./db.ts";
import { registerApp } from "./catalog.ts";

const db = getDB(process.env.DB_PATH ?? "broker.db");

const seed = [
  { name: "ChatGPT", category: "assistant", vendor: "OpenAI", risk: "medium", data_residency: "us", approval_required: 1 },
  { name: "Claude", category: "assistant", vendor: "Anthropic", risk: "medium", data_residency: "us", approval_required: 1 },
  { name: "GitHub Copilot", category: "code", vendor: "GitHub", risk: "low", data_residency: "us", approval_required: 0 },
  { name: "Perplexity", category: "search", vendor: "Perplexity", risk: "medium", data_residency: "eu", approval_required: 1 },
  { name: "SketchyAI", category: "assistant", vendor: "Unknown", risk: "high", data_residency: "cn", approval_required: 1 },
];

for (const app of seed) registerApp(db, app);
console.log(`Seeded ${seed.length} apps into ${process.env.DB_PATH ?? "broker.db"}`);
