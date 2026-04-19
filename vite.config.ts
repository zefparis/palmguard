import { defineConfig } from "vite";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  root: "src/demo",
  base: "/",
  resolve: {
    alias: [
      // Map each .js import to the real .ts source file
      { find: "/src/fractal/boxcount.js",   replacement: resolve(__dirname, "src/fractal/boxcount.ts") },
      { find: "/src/topology/skeleton.js",  replacement: resolve(__dirname, "src/topology/skeleton.ts") },
      { find: "/src/topology/tda.js",       replacement: resolve(__dirname, "src/topology/tda.ts") },
    ],
  },
  build: {
    outDir: "../../dist/demo",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, "src/demo/index.html"),
      },
    },
  },
  optimizeDeps: {
    exclude: ["@techstark/opencv-js"],
  },
  assetsInclude: ["**/*.wasm"],
  server: {
    port: 5174,
    host: true,
  },
});
