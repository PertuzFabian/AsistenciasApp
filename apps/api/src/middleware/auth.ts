import { Role, Status } from "@prisma/client";
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { env } from "../utils/env.js";
import { prisma } from "../utils/prisma.js";

type JwtPayload = {
  sub: string;
  role: Role;
};

export const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing_token" });
  }

  const token = header.slice("Bearer ".length);
  try {
    const decoded = jwt.verify(token, env.JWT_SECRET) as JwtPayload;
    const user = await prisma.user.findUnique({ where: { id: decoded.sub }, include: { school: true } });
    if (!user) {
      return res.status(401).json({ error: "invalid_token" });
    }
    if (user.status === Status.INACTIVE) {
      return res.status(403).json({ error: "user_inactive" });
    }

    if ((user.role === Role.COORDINATOR || user.role === Role.TEACHER) && user.school) {
      if (user.school.status === Status.INACTIVE || user.school.endDate < new Date()) {
        return res.status(403).json({ error: "school_membership_expired" });
      }
    }

    req.user = {
      id: user.id,
      role: user.role,
      schoolId: user.schoolId,
      name: user.name,
      email: user.email
    };

    return next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
};

export const requireRole = (...roles: Role[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "forbidden" });
    }
    return next();
  };
};
