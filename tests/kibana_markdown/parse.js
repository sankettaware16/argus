// Kibana's Markdown reader, as a command: reads a JSON list of texts on stdin and writes, for each
// text, what the reader made of it. The reader is the one Kibana's EUI uses for case comments:
// remark-parse 8.0.3 (not CommonMark) under unified 9.2.2, with remark-emoji 2.2.0.
//
//   node parse.js <node_modules directory holding the three packages>  < texts.json
//
// Per text: {"nodes": {type: count}, "tables": [[cells in each row]], "urls": [link and image
// targets]}. tests/unit/caseteam/test_kibana_parser.py runs it (see README.md).
"use strict";
const path = require("path");

const dir = path.resolve(process.argv[2] || "node_modules");
const load = (name) => require(path.join(dir, name));
const unified = load("unified");
const parse = load("remark-parse");
const emoji = load("remark-emoji");

const reader = unified().use(parse).use(emoji, { emoticon: false });

function summarize(text) {
  const tree = reader.runSync(reader.parse(text));
  const nodes = {};
  const tables = [];
  const urls = [];
  (function walk(node) {
    nodes[node.type] = (nodes[node.type] || 0) + 1;
    if (node.type === "table") tables.push(node.children.map((row) => row.children.length));
    if ((node.type === "link" || node.type === "image") && node.url !== undefined) urls.push(node.url);
    for (const child of node.children || []) walk(child);
  })(tree);
  return { nodes, tables, urls };
}

const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  const texts = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  process.stdout.write(JSON.stringify(texts.map(summarize)));
});
