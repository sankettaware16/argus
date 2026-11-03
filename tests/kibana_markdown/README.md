# Kibana's Markdown reader, for the differential tests (D-248)

The text ARGUS writes into a Kibana case is read by Kibana's own reader: EUI's `remark-parse@8.0.3`
under `unified@9.2.2`, with `remark-emoji@2.2.0`. That is not CommonMark. It looks for the end of
`**bold**` by scanning raw characters (a code span does not hide a `**`), ends a table cell at every
pipe that no backslash protects (inside a code span too), and honours a backslash only before
``\ ` * _ { } [ ] ( ) # + - . ! > ~ |``. A test that parses ARGUS's text with markdown-it (CommonMark)
can pass where Kibana does something else, so `tests/unit/caseteam/test_kibana_parser.py` runs the
real reader.

`parse.js` reads a JSON list of texts on stdin and prints, for each, the count of each node type, the
cells in every table row and the targets of links and images. `tests/unit/caseteam/kibana_reader.py`
runs it.

## Install (once, needs the network)

```bash
npm i --prefix tests/kibana_markdown remark-parse@8.0.3 unified@9.2.2 remark-emoji@2.2.0
```

`tests/kibana_markdown/node_modules` is ignored by git. The tests look for the three packages, at
exactly these versions, in this order:

1. `tests/kibana_markdown/node_modules`
2. the directory named by `$ARGUS_REMARK_NODE_MODULES`
3. `/home/dev/code/OpenSearch-Dashboards/node_modules` (its EUI carries the same pins)

and **skip with that reason** when none holds them (or `node` is missing). Note that ARGUS refuses
`ARGUS_` variables that are not settings, so export `ARGUS_REMARK_NODE_MODULES` only for the pytest
run (`ARGUS_REMARK_NODE_MODULES=... uv run pytest ...`), not in a shell where `argus` runs.

```bash
echo '["**a** `b|c`", "| a | b |\n|---|---|\n| 1 | 2 |"]' | node tests/kibana_markdown/parse.js tests/kibana_markdown/node_modules
```
