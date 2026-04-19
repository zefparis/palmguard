import { defineConfig } from "vite";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  root: "src/demo",
  base: "/",
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
