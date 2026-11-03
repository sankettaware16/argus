// Lint (Q-B1): the TypeScript and React rules, and the HTML-injection lint (plan §7.5): no way to
// put markup, inline style or script into the page from our code. tests/lint.test.ts proves that
// every construct below is refused.
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

const HTML_SINKS = "innerHTML|outerHTML|insertAdjacentHTML|srcdoc|srcDoc";
const HTML_CALLS = "insertAdjacentHTML|write|writeln|createContextualFragment|setHTMLUnsafe|parseHTMLUnsafe|parseFromString";
const NO_MARKUP = "No markup from strings (plan §7.5): render text, or use UntrustedText.";
const NO_CODE = "No code from strings.";
const NO_ATTRIBUTE = "No inline style or event-handler attributes.";
// a string used as code: a literal, a template or a joined string
const STRINGY = "/^(Literal|TemplateLiteral|BinaryExpression)$/";

export const INJECTION = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: NO_MARKUP,
  },
  {
    selector: "JSXAttribute[name.name='style']",
    message: "No style attributes (the CSP refuses them): use a class from the tokens.",
  },
  {
    selector: "JSXAttribute[name.name=/^(srcDoc|srcdoc)$/]",
    message: "No srcdoc: it is markup from a string.",
  },
  {
    selector: "AssignmentExpression > MemberExpression.left[property.name=/^(innerHTML|outerHTML)$/]",
    message: "No innerHTML or outerHTML (Trusted Types refuse them on /app).",
  },
  {
    selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/][computed=false]",
    message: "No innerHTML or outerHTML (Trusted Types refuse them on /app).",
  },
  // review F5: the same sinks by another name: el["innerHTML"], el[`innerHTML`],
  // Reflect.set(el, "innerHTML", x), { "outerHTML": x }, Object.assign(el, { innerHTML: x })
  { selector: `Literal[value=/^(${HTML_SINKS})$/]`, message: NO_MARKUP },
  { selector: `TemplateElement[value.raw=/^(${HTML_SINKS})$/]`, message: NO_MARKUP },
  { selector: "Property[key.name=/^(innerHTML|outerHTML)$/]", message: NO_MARKUP },
  {
    selector: `MemberExpression[computed=true][property.value=/^(${HTML_CALLS})$/]`,
    message: NO_MARKUP,
  },
  {
    selector: `CallExpression[callee.property.name=/^(${HTML_CALLS})$/]`,
    message: NO_MARKUP,
  },
  { selector: "CallExpression[callee.property.name='execCommand']", message: NO_MARKUP },
  {
    selector: "CallExpression[callee.property.name='setAttribute'][arguments.0.value=/^(style|srcdoc|on.*)$/i]",
    message: NO_ATTRIBUTE,
  },
  {
    selector: "CallExpression[callee.property.name='setAttribute'][arguments.0.quasis.0.value.raw=/^(style|srcdoc|on)/i]",
    message: NO_ATTRIBUTE,
  },
  {
    selector: "CallExpression[callee.property.name='setAttributeNS'][arguments.1.value=/^(style|srcdoc|on.*)$/i]",
    message: NO_ATTRIBUTE,
  },
  {
    selector: "CallExpression[callee.property.name='setAttributeNS'][arguments.1.quasis.0.value.raw=/^(style|srcdoc|on)/i]",
    message: NO_ATTRIBUTE,
  },
  // a script element at all (then its text, src or children are code)
  {
    selector: "CallExpression[callee.property.name=/^createElement(NS)?$/] > Literal[value=/^script$/i]",
    message: "No script elements from our code.",
  },
  {
    selector: "CallExpression[callee.property.name=/^createElement(NS)?$/] > TemplateLiteral > TemplateElement[value.raw=/^script$/i]",
    message: "No script elements from our code.",
  },
  {
    selector: `CallExpression[callee.name=/^(setTimeout|setInterval)$/][arguments.0.type=${STRINGY}]`,
    message: NO_CODE,
  },
  {
    selector: `CallExpression[callee.property.name=/^(setTimeout|setInterval)$/][arguments.0.type=${STRINGY}]`,
    message: NO_CODE,
  },
  { selector: "CallExpression[callee.name='eval']", message: "No eval." },
  { selector: "NewExpression[callee.name='Function']", message: NO_CODE },
  { selector: "CallExpression[callee.name='Function']", message: NO_CODE },
  { selector: "MemberExpression[property.name='Function']", message: NO_CODE },
  { selector: "Literal[value=/^\\s*javascript:/i]", message: "No javascript: URLs." },
  {
    selector: "TemplateElement[value.raw=/^\\s*javascript:/i]",
    message: "No javascript: URLs.",
  },
];

const BANNED_IMPORTS = {
  patterns: [
    { group: ["@radix-ui/*"], message: "Radix injects <style> the CSP refuses (DQ24): use Base UI." },
    { group: ["sonner", "vaul"], message: "Banned by plan §7.5 (style injection)." },
    { group: ["echarts", "echarts/*", "zrender", "zrender/*"], message: "ECharts' painter assigns innerHTML, which Trusted Types refuse on /app: Q-B2 decides charts (gate report Q-B1)." },
  ],
};

export default tseslint.config(
  { ignores: ["dist", "node_modules", "coverage", "reports", ".stryker-tmp"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["**/*.{ts,tsx,js,mjs}"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "no-restricted-syntax": ["error", ...INJECTION],
      "no-restricted-imports": ["error", BANNED_IMPORTS],
      "no-restricted-properties": [
        "error",
        { object: "document", property: "write", message: "No document.write." },
        { object: "window", property: "eval", message: "No eval." },
      ],
    },
  },
  {
    // the generated client (Hey API) is checked for injection like our code, not for its style
    files: ["src/client/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-invalid-void-type": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-dynamic-delete": "off",
    },
  },
);
