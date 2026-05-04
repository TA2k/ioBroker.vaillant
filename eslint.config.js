const js = require("@eslint/js");
const globals = require("globals");

module.exports = [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: "commonjs",
      globals: {
        ...globals.node,
        ...globals.mocha,
        ...globals.es6,
      },
    },
    rules: {
      indent: ["error", 2, { SwitchCase: 1 }],
      "no-console": "off",
      "no-unused-vars": ["error", { ignoreRestSiblings: true, argsIgnorePattern: "^_" }],
      "no-var": "error",
      "no-trailing-spaces": "error",
      "prefer-const": "error",
      "preserve-caught-error": "off",
      quotes: ["error", "double", { avoidEscape: true, allowTemplateLiterals: true }],
      semi: ["error", "always"],
    },
  },
  {
    ignores: [".prettierrc.js", "**/.eslintrc.js", "node_modules/", ".references/"],
  },
];
