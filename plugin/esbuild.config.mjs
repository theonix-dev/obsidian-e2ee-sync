import esbuild from "esbuild";
import process from "process";
import builtinModules from "builtin-modules";

const banner = `/*
 * Obsidian E2EE Sync — bundled by esbuild. DO NOT EDIT MANUALLY.
 * Source lives in src/. Rebuild with: npm run build
 */`;

const production = process.argv[2] === "production";

const context = await esbuild.context({
  banner: { js: banner },
  entryPoints: ["src/main.ts"],
  bundle: true,
  // "obsidian" is provided by the app at runtime; Node builtins must never be
  // bundled (they do not exist on mobile).
  external: [
    "obsidian",
    "electron",
    "@codemirror/language",
    "@codemirror/state",
    "@codemirror/view",
    "@lezer/common",
    ...builtinModules,
  ],
  format: "cjs",
  target: "es2018",
  logLevel: "info",
  sourcemap: production ? false : "inline",
  treeShaking: true,
  outfile: "main.js",
});

if (production) {
  await context.rebuild();
  process.exit(0);
} else {
  await context.watch();
}
