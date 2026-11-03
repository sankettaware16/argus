// The HTML-injection lint (Q-B1's gate): every way to put markup, inline style or code into the
// page from our code is refused by `npm run lint`.
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const REFUSED: Record<string, string> = {
  dangerouslySetInnerHTML: "export const A = () => <div dangerouslySetInnerHTML={{ __html: x }} />;",
  "a style attribute": "export const A = () => <div style={{ color: 'red' }} />;",
  srcDoc: "export const A = () => <iframe srcDoc={x} />;",
  "innerHTML assignment": "document.body.innerHTML = x;",
  "outerHTML assignment": "el.outerHTML = x;",
  "innerHTML read into a sink": "const h = el.innerHTML;",
  insertAdjacentHTML: "el.insertAdjacentHTML('beforeend', x);",
  "document.write": "document.write(x);",
  writeln: "document.writeln(x);",
  createContextualFragment: "document.createRange().createContextualFragment(x);",
  setHTMLUnsafe: "el.setHTMLUnsafe(x);",
  parseFromString: "new DOMParser().parseFromString(x, 'text/html');",
  "an inline style by setAttribute": "el.setAttribute('style', x);",
  "an event handler by setAttribute": "el.setAttribute('onclick', x);",
  eval: "eval(x);",
  "window.eval": "window.eval(x);",
  "new Function": "new Function(x);",
  "setTimeout with a string": "setTimeout('alert(1)', 1);",
  "a javascript: URL": "export const A = () => <a href='javascript:alert(1)'>x</a>;",
  "a javascript: template": "const u = `javascript:${x}`;",
  "Radix": "import * as D from '@radix-ui/react-dialog';",
  "sonner": "import { toast } from 'sonner';",
  "vaul": "import { Drawer } from 'vaul';",
  "echarts": "import * as echarts from 'echarts';",
  // review F5: the same sinks reached another way
  "computed innerHTML": "el['innerHTML'] = x;",
  "computed outerHTML": 'el["outerHTML"] = x;',
  "a computed innerHTML read": "const h = el[`innerHTML`];",
  "Object.assign innerHTML": "Object.assign(el, { innerHTML: x });",
  "an object literal with a quoted outerHTML key": "Object.assign(el, { 'outerHTML': x });",
  "Reflect.set innerHTML": "Reflect.set(el, 'innerHTML', x);",
  "computed insertAdjacentHTML": "el['insertAdjacentHTML']('beforeend', x);",
  "execCommand insertHTML": "document.execCommand('insertHTML', false, x);",
  "Function without new": "Function(x)();",
  "new window.Function": "new window.Function(x);",
  "globalThis.Function": "globalThis.Function(x);",
  "setAttributeNS onclick": "el.setAttributeNS(null, 'onclick', x);",
  "setAttributeNS style": "el.setAttributeNS(null, 'style', x);",
  "setAttribute with a template literal": "el.setAttribute(`style`, x);",
  "setAttribute with a template literal event": "el.setAttribute(`onload`, x);",
  "a script element's text": "const s = document.createElement('script'); s.text = x; document.head.append(s);",
  "a script element's src": "const s = document.createElement('script'); s.src = x;",
  "a script element made at all": "document.createElement('script');",
  "a script element by template": "document.createElement(`script`);",
  "setTimeout with a template": "setTimeout(`alert(1)`, 1);",
  "window.setTimeout with a string": "window.setTimeout('alert(1)', 1);",
  "setTimeout with a joined string": "setTimeout('alert(' + x + ')', 1);",
  "a script element by createElementNS": "document.createElementNS('http://www.w3.org/1999/xhtml', 'script');",
};

const ALLOWED = [
  "export const A = ({ x }: { x: string }) => <p className='m-0'>{x}</p>;",
  "el.textContent = x;",
  "el.setAttribute('aria-label', x);",
  "el.setAttribute(`aria-label`, x);",
  "setTimeout(() => {}, 1);",
  "const f = () => {}; setInterval(f, 1);",
  "const o = { text: x, title: x }; el.title = o.text;",
  "document.createElement('span');",
  "Object.assign(el, { title: x });",
  "Reflect.set(el, 'title', x);",
  "const h = el['title'];",
];

describe("the HTML-injection lint", () => {
  const eslint = new ESLint({ cwd: process.cwd() });

  for (const [name, code] of Object.entries(REFUSED)) {
    it(`refuses ${name}`, async () => {
      const [result] = await eslint.lintText(`declare const x: string; declare const el: HTMLElement;\n${code}\n`, {
        filePath: "src/pages/Probe.tsx",
      });
      const rules = (result?.messages ?? []).map((m) => m.ruleId);
      expect(rules.some((r) => r === "no-restricted-syntax" || r === "no-restricted-imports" || r === "no-restricted-properties"), JSON.stringify(result?.messages)).toBe(true);
    });
  }

  it("lets text, attributes and functions through", async () => {
    for (const code of ALLOWED) {
      const [result] = await eslint.lintText(`declare const x: string; declare const el: HTMLElement;\n${code}\n`, {
        filePath: "src/pages/Probe.tsx",
      });
      const injection = (result?.messages ?? []).filter((m) => m.ruleId?.startsWith("no-restricted"));
      expect(injection, code).toEqual([]);
    }
  });
});
