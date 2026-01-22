import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { authRouter } from "./routes/auth.js";
import { adminRouter } from "./routes/admin.js";
import { coordinatorRouter } from "./routes/coordinator.js";
import { teacherRouter } from "./routes/teacher.js";
import { env } from "./utils/env.js";

dotenv.config();

const app = express();

app.use(helmet());
app.use(cors({ origin: env.CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: "2mb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.use("/auth", authRouter);
app.use("/admin", adminRouter);
app.use("/coordinator", coordinatorRouter);
app.use("/teacher", teacherRouter);

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err);
  res.status(500).json({ error: "internal_error" });
});

app.listen(env.PORT, () => {
  console.log(`API running on port ${env.PORT}`);
});
