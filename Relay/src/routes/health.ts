import type { FastifyInstance } from "fastify";

export default async function healthRoutes(app: FastifyInstance): Promise<void> {
  app.get("/healthz", async () => ({ status: "ok", uptimeSeconds: Math.round(process.uptime()) }));
}
