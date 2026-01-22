import { Router } from "express";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { prisma } from "../utils/prisma.js";
import { requireAuth, requireRole } from "../middleware/auth.js";
import { AttendanceStatus, Role, Status } from "@prisma/client";

export const adminRouter = Router();

adminRouter.use(requireAuth, requireRole(Role.ADMIN));

const schoolSchema = z.object({
  name: z.string().min(2),
  city: z.string().min(2),
  address: z.string().min(3),
  phone: z.string().min(5),
  email: z.string().email(),
  startDate: z.string(),
  endDate: z.string(),
  status: z.nativeEnum(Status).default(Status.ACTIVE),
  coordinator: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    phone: z.string().min(5).optional(),
    password: z.string().min(8),
    status: z.nativeEnum(Status).default(Status.ACTIVE)
  })
});

adminRouter.get("/schools", async (_req, res) => {
  const schools = await prisma.school.findMany({
    orderBy: { createdAt: "desc" },
    include: {
      users: { where: { role: Role.COORDINATOR } }
    }
  });
  return res.json(schools);
});

adminRouter.post("/schools", async (req, res) => {
  const parsed = schoolSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const data = parsed.data;
  const passwordHash = await bcrypt.hash(data.coordinator.password, 12);

  const school = await prisma.$transaction(async (tx) => {
    const created = await tx.school.create({
      data: {
        name: data.name,
        city: data.city,
        address: data.address,
        phone: data.phone,
        email: data.email,
        startDate: new Date(data.startDate),
        endDate: new Date(data.endDate),
        status: data.status
      }
    });

    await tx.user.create({
      data: {
        name: data.coordinator.name,
        email: data.coordinator.email,
        phone: data.coordinator.phone,
        passwordHash,
        role: Role.COORDINATOR,
        status: data.coordinator.status,
        schoolId: created.id
      }
    });

    return created;
  });

  return res.status(201).json(school);
});

const updateSchoolSchema = z.object({
  name: z.string().min(2).optional(),
  city: z.string().min(2).optional(),
  address: z.string().min(3).optional(),
  phone: z.string().min(5).optional(),
  email: z.string().email().optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  status: z.nativeEnum(Status).optional(),
  coordinator: z
    .object({
      name: z.string().min(2).optional(),
      email: z.string().email().optional(),
      phone: z.string().min(5).optional(),
      password: z.string().min(8).optional(),
      status: z.nativeEnum(Status).optional()
    })
    .optional()
});

adminRouter.put("/schools/:id", async (req, res) => {
  const parsed = updateSchoolSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const schoolId = req.params.id;
  const data = parsed.data;

  const school = await prisma.$transaction(async (tx) => {
    const updated = await tx.school.update({
      where: { id: schoolId },
      data: {
        name: data.name,
        city: data.city,
        address: data.address,
        phone: data.phone,
        email: data.email,
        startDate: data.startDate ? new Date(data.startDate) : undefined,
        endDate: data.endDate ? new Date(data.endDate) : undefined,
        status: data.status
      }
    });

    if (data.coordinator) {
      const coordinator = await tx.user.findFirst({
        where: { schoolId, role: Role.COORDINATOR }
      });

      const passwordHash = data.coordinator.password
        ? await bcrypt.hash(data.coordinator.password, 12)
        : undefined;

      if (coordinator) {
        await tx.user.update({
          where: { id: coordinator.id },
          data: {
            name: data.coordinator.name,
            email: data.coordinator.email,
            phone: data.coordinator.phone,
            status: data.coordinator.status,
            passwordHash
          }
        });
      } else if (data.coordinator.email && data.coordinator.name && data.coordinator.password) {
        await tx.user.create({
          data: {
            name: data.coordinator.name,
            email: data.coordinator.email,
            phone: data.coordinator.phone,
            passwordHash: passwordHash ?? "",
            role: Role.COORDINATOR,
            status: data.coordinator.status ?? Status.ACTIVE,
            schoolId
          }
        });
      }
    }

    return updated;
  });

  return res.json(school);
});

adminRouter.get("/schools/:id", async (req, res) => {
  const schoolId = req.params.id;
  const school = await prisma.school.findUnique({
    where: { id: schoolId },
    include: { users: { where: { role: Role.COORDINATOR } } }
  });
  if (!school) {
    return res.status(404).json({ error: "not_found" });
  }
  return res.json(school);
});

adminRouter.get("/schools/:id/stats", async (req, res) => {
  const schoolId = req.params.id;
  const totalStudents = await prisma.student.count({ where: { schoolId } });
  const activeStudents = await prisma.student.count({ where: { schoolId, status: Status.ACTIVE } });
  const inactiveStudents = totalStudents - activeStudents;

  const totalRecords = await prisma.attendanceRecord.count({
    where: { student: { schoolId } }
  });
  const presentRecords = await prisma.attendanceRecord.count({
    where: { student: { schoolId }, status: AttendanceStatus.PRESENT }
  });

  const attendanceRate = totalRecords === 0 ? 0 : Math.round((presentRecords / totalRecords) * 1000) / 10;
  const absenceRate = 100 - attendanceRate;

  return res.json({
    activeStudents,
    inactiveStudents,
    attendanceRate,
    absenceRate
  });
});
