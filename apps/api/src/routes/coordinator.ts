import { Router } from "express";
import { z } from "zod";
import multer from "multer";
import xlsx from "xlsx";
import bcrypt from "bcryptjs";
import { requireAuth, requireRole } from "../middleware/auth.js";
import { prisma } from "../utils/prisma.js";
import { AttendanceStatus, Role, Status } from "@prisma/client";

export const coordinatorRouter = Router();
const upload = multer();

coordinatorRouter.use(requireAuth, requireRole(Role.COORDINATOR));

const teacherSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  phone: z.string().min(5).optional(),
  password: z.string().min(8),
  status: z.nativeEnum(Status).default(Status.ACTIVE)
});

coordinatorRouter.get("/teachers", async (req, res) => {
  const teachers = await prisma.user.findMany({
    where: { role: Role.TEACHER, schoolId: req.user?.schoolId ?? undefined }
  });
  return res.json(teachers);
});

coordinatorRouter.post("/teachers", async (req, res) => {
  const parsed = teacherSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }
  const passwordHash = await bcrypt.hash(parsed.data.password, 12);
  const teacher = await prisma.user.create({
    data: {
      name: parsed.data.name,
      email: parsed.data.email,
      phone: parsed.data.phone,
      passwordHash,
      role: Role.TEACHER,
      status: parsed.data.status,
      schoolId: req.user?.schoolId ?? null
    }
  });
  return res.status(201).json(teacher);
});

const teacherUpdateSchema = z.object({
  name: z.string().min(2).optional(),
  email: z.string().email().optional(),
  phone: z.string().min(5).optional(),
  password: z.string().min(8).optional(),
  status: z.nativeEnum(Status).optional()
});

coordinatorRouter.put("/teachers/:id", async (req, res) => {
  const parsed = teacherUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const passwordHash = parsed.data.password ? await bcrypt.hash(parsed.data.password, 12) : undefined;

  const teacher = await prisma.user.update({
    where: { id: req.params.id },
    data: {
      name: parsed.data.name,
      email: parsed.data.email,
      phone: parsed.data.phone,
      status: parsed.data.status,
      passwordHash
    }
  });

  return res.json(teacher);
});

const courseSchema = z.object({
  name: z.string().min(2),
  academicYear: z.number().int().min(2000),
  teacherId: z.string().optional(),
  status: z.nativeEnum(Status).default(Status.ACTIVE)
});

coordinatorRouter.get("/courses", async (req, res) => {
  const courses = await prisma.course.findMany({
    where: { schoolId: req.user?.schoolId ?? undefined },
    include: { teacher: true }
  });
  return res.json(courses);
});

coordinatorRouter.post("/courses", async (req, res) => {
  const parsed = courseSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const course = await prisma.course.create({
    data: {
      name: parsed.data.name,
      academicYear: parsed.data.academicYear,
      teacherId: parsed.data.teacherId,
      status: parsed.data.status,
      schoolId: req.user?.schoolId ?? ""
    }
  });

  return res.status(201).json(course);
});

const courseUpdateSchema = z.object({
  name: z.string().min(2).optional(),
  academicYear: z.number().int().min(2000).optional(),
  teacherId: z.string().nullable().optional(),
  status: z.nativeEnum(Status).optional()
});

coordinatorRouter.put("/courses/:id", async (req, res) => {
  const parsed = courseUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const course = await prisma.course.update({
    where: { id: req.params.id },
    data: parsed.data
  });

  return res.json(course);
});

const studentSchema = z.object({
  fullName: z.string().min(2),
  guardianName: z.string().optional(),
  guardianPhone: z.string().optional(),
  guardianEmail: z.string().email().optional(),
  nfcUid: z.string().optional(),
  status: z.nativeEnum(Status).default(Status.ACTIVE)
});

coordinatorRouter.post("/courses/:id/students", async (req, res) => {
  const parsed = studentSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const student = await prisma.student.create({
    data: {
      schoolId: req.user?.schoolId ?? "",
      fullName: parsed.data.fullName,
      guardianName: parsed.data.guardianName,
      guardianPhone: parsed.data.guardianPhone,
      guardianEmail: parsed.data.guardianEmail,
      nfcUid: parsed.data.nfcUid,
      status: parsed.data.status,
      enrollments: {
        create: {
          courseId: req.params.id
        }
      }
    }
  });

  return res.status(201).json(student);
});

coordinatorRouter.put("/students/:id", async (req, res) => {
  const parsed = studentSchema.partial().safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const student = await prisma.student.update({
    where: { id: req.params.id },
    data: parsed.data
  });

  return res.json(student);
});

coordinatorRouter.post("/courses/:id/students/import", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "file_required" });
  }

  const commit = String(req.query.commit) === "true";
  const workbook = xlsx.read(req.file.buffer, { type: "buffer" });
  const sheet = workbook.Sheets[workbook.SheetNames[0]];
  const rows = xlsx.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: "" });

  const errors: Array<{ row: number; reason: string }> = [];
  const valid: Array<{
    fullName: string;
    guardianName?: string;
    guardianPhone?: string;
    guardianEmail?: string;
    nfcUid?: string;
  }> = [];

  const seenNfc = new Set<string>();

  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    const normalized = {
      fullName: String(row.fullName ?? row["Nombre completo"] ?? row["nombre"] ?? "").trim(),
      guardianName: String(row.guardianName ?? row["Acudiente"] ?? "").trim() || undefined,
      guardianPhone: String(row.guardianPhone ?? row["Telefono"] ?? "").trim() || undefined,
      guardianEmail: String(row.guardianEmail ?? row["Correo"] ?? "").trim() || undefined,
      nfcUid: String(row.nfcUid ?? row["NFC"] ?? row["nfc"] ?? "").trim() || undefined
    };

    if (!normalized.fullName) {
      errors.push({ row: i + 2, reason: "Nombre requerido" });
      continue;
    }

    if (normalized.guardianEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized.guardianEmail)) {
      errors.push({ row: i + 2, reason: "Correo del acudiente invalido" });
      continue;
    }

    if (normalized.nfcUid) {
      if (seenNfc.has(normalized.nfcUid)) {
        errors.push({ row: i + 2, reason: "NFC duplicado en el archivo" });
        continue;
      }
      seenNfc.add(normalized.nfcUid);
    }

    valid.push(normalized);
  }

  if (commit && valid.length > 0) {
    const nfcValues = valid.map((item) => item.nfcUid).filter(Boolean) as string[];
    if (nfcValues.length > 0) {
      const existing = await prisma.student.findMany({
        where: { nfcUid: { in: nfcValues }, schoolId: req.user?.schoolId ?? undefined }
      });
      const existingSet = new Set(existing.map((item) => item.nfcUid));
      for (const item of valid) {
        if (item.nfcUid && existingSet.has(item.nfcUid)) {
          errors.push({ row: -1, reason: `NFC ya existe: ${item.nfcUid}` });
        }
      }
    }

    if (errors.length === 0) {
      await prisma.$transaction(
        valid.map((item) =>
          prisma.student.create({
            data: {
              schoolId: req.user?.schoolId ?? "",
              fullName: item.fullName,
              guardianName: item.guardianName,
              guardianPhone: item.guardianPhone,
              guardianEmail: item.guardianEmail,
              nfcUid: item.nfcUid,
              status: Status.ACTIVE,
              enrollments: {
                create: {
                  courseId: req.params.id
                }
              }
            }
          })
        )
      );
    }
  }

  return res.json({
    total: rows.length,
    validCount: valid.length,
    errorCount: errors.length,
    errors,
    valid
  });
});

coordinatorRouter.get("/courses/:id/stats", async (req, res) => {
  const courseId = req.params.id;
  const sessions = await prisma.attendanceSession.findMany({
    where: { courseId },
    include: { records: true }
  });

  const totalRecords = sessions.reduce((sum, s) => sum + s.records.length, 0);
  const presentRecords = sessions.reduce(
    (sum, s) => sum + s.records.filter((r) => r.status === AttendanceStatus.PRESENT).length,
    0
  );

  const attendanceRate = totalRecords === 0 ? 0 : Math.round((presentRecords / totalRecords) * 1000) / 10;

  const students = await prisma.enrollment.findMany({
    where: { courseId },
    include: { student: true }
  });

  return res.json({ attendanceRate, students });
});

coordinatorRouter.get("/students/:id/stats", async (req, res) => {
  const studentId = req.params.id;
  const records = await prisma.attendanceRecord.findMany({
    where: { studentId }
  });

  const total = records.length;
  const present = records.filter((r) => r.status === AttendanceStatus.PRESENT).length;
  const attendanceRate = total === 0 ? 0 : Math.round((present / total) * 1000) / 10;

  return res.json({ attendanceRate, total, present });
});

coordinatorRouter.get("/stats", async (req, res) => {
  const schoolId = req.user?.schoolId ?? "";
  const activeStudents = await prisma.student.count({ where: { schoolId, status: Status.ACTIVE } });
  const inactiveStudents = await prisma.student.count({ where: { schoolId, status: Status.INACTIVE } });

  const totalRecords = await prisma.attendanceRecord.count({
    where: { student: { schoolId } }
  });
  const presentRecords = await prisma.attendanceRecord.count({
    where: { student: { schoolId }, status: AttendanceStatus.PRESENT }
  });
  const attendanceRate = totalRecords === 0 ? 0 : Math.round((presentRecords / totalRecords) * 1000) / 10;
  const absenceRate = 100 - attendanceRate;

  const courses = await prisma.course.findMany({
    where: { schoolId },
    include: { sessions: { include: { records: true } } }
  });

  const ranking = courses
    .map((course) => {
      const courseRecords = course.sessions.flatMap((s) => s.records);
      const coursePresent = courseRecords.filter((r) => r.status === AttendanceStatus.PRESENT).length;
      const courseRate = courseRecords.length === 0 ? 0 : Math.round((coursePresent / courseRecords.length) * 1000) / 10;
      return { id: course.id, name: course.name, academicYear: course.academicYear, rate: courseRate };
    })
    .sort((a, b) => b.rate - a.rate);

  return res.json({ activeStudents, inactiveStudents, attendanceRate, absenceRate, ranking });
});
