// Shiki theme in TUI colours. Every colour is a CSS variable from global.css,
// so code blocks follow the light/dark scheme (and the theme switcher) without a second theme.
import type { ThemeRegistration } from "shiki";

export const tuiTheme: ThemeRegistration = {
  name: "sodabox-tui",
  type: "dark",
  colors: {
    "editor.background": "var(--c-surface)",
    "editor.foreground": "var(--c-fg)",
  },
  tokenColors: [
    { scope: ["comment", "punctuation.definition.comment"], settings: { foreground: "var(--c-muted)", fontStyle: "italic" } },
    { scope: ["string", "string.quoted", "string.unquoted", "string.template"], settings: { foreground: "var(--c-green)" } },
    { scope: ["constant.character.escape", "punctuation.section.embedded", "meta.embedded"], settings: { foreground: "var(--c-cyan)" } },
    { scope: ["keyword", "storage", "storage.type", "keyword.operator.word"], settings: { foreground: "var(--c-yellow)" } },
    { scope: ["constant", "constant.numeric", "constant.language", "support.constant"], settings: { foreground: "var(--c-cyan)" } },
    { scope: ["entity.other.attribute-name", "support.type.property-name", "meta.object-literal.key", "variable.other.property"], settings: { foreground: "var(--c-cyan)" } },
    { scope: ["entity.name.function", "support.function", "variable.parameter"], settings: { foreground: "var(--c-fg)" } },
    { scope: ["punctuation", "keyword.operator", "meta.brace"], settings: { foreground: "var(--c-muted)" } },
    { scope: ["invalid"], settings: { foreground: "var(--c-red)" } },
  ],
};
