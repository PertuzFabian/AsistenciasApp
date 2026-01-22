import { Router } from "express";
import { z } from "zod";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { prisma } from "../utils/prisma.js";
import { env } from "../utils/env.js";
import { Role, Status } from "@prisma/client";

export const authRouter = Router();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  role: z.nativeEnum(Role)
});

authRouter.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const { email, password, role } = parsed.data;
  const user = await prisma.user.findUnique({ where: { email }, include: { school: true } });
  if (!user) {
    return res.status(401).json({ error: "invalid_credentials" });
  }
  if (user.role !== role) {
    return res.status(403).json({ error: "role_mismatch" });
  }
  if (user.status === Status.INACTIVE) {
    return res.status(403).json({ error: "user_inactive" });
  }
  if ((user.role === Role.COORDINATOR || user.role === Role.TEACHER) && user.school) {
    if (user.school.status === Status.INACTIVE || user.school.endDate < new Date()) {
      return res.status(403).json({ error: "school_membership_expired" });
    }
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const token = jwt.sign({ sub: user.id, role: user.role }, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN
  });

  return res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      schoolId: user.schoolId
    }
  });
});

const forgotSchema = z.object({
  email: z.string().email()
});

authRouter.post("/forgot-password", async (req, res) => {
  const parsed = forgotSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const user = await prisma.user.findUnique({ where: { email: parsed.data.email } });
  if (!user) {
    return res.status(404).json({ error: "email_not_registered" });
  }

  const token = crypto.randomBytes(32).toString("hex");
  await prisma.passwordReset.create({
    data: {
      userId: user.id,
      token,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000)
    }
  });

  return res.json({ message: "reset_sent" });
});

const resetSchema = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(8)
});

authRouter.post("/reset-password", async (req, res) => {
  const parsed = resetSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const reset = await prisma.passwordReset.findUnique({ where: { token: parsed.data.token } });
  if (!reset || reset.usedAt || reset.expiresAt < new Date()) {
    return res.status(400).json({ error: "invalid_token" });
  }

  const passwordHash = await bcrypt.hash(parsed.data.newPassword, 12);
  await prisma.$transaction([
    prisma.user.update({
      where: { id: reset.userId },
      data: { passwordHash }
    }),
    prisma.passwordReset.update({
      where: { id: reset.id },
      data: { usedAt: new Date() }
    })
  ]);

  return res.json({ message: "password_updated" });
});
