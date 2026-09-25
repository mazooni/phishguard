import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    // Every test builds its own in-memory SQLite database and fake APNs sender; nothing touches the network.
    isolate: true,
    testTimeout: 10_000,
  },
});
