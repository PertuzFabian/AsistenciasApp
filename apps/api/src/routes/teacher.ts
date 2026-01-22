import { Router } from "express";
import { z } from "zod";
import { prisma } from "../utils/prisma.js";
import { requireAuth, requireRole } from "../middleware/auth.js";
import { AttendanceMethod, AttendanceStatus, Role } from "@prisma/client";

export const teacherRouter = Router();

teacherRouter.use(requireAuth, requireRole(Role.TEACHER));

teacherRouter.get("/courses", async (req, res) => {
  const courses = await prisma.course.findMany({
    where: { teacherId: req.user?.id ?? undefined },
    include: { school: true }
  });
  return res.json(courses);
});

const attendanceSchema = z.object({
  courseId: z.string(),
  date: z.string(),
  records: z
    .array(
      z.object({
        studentId: z.string(),
        status: z.nativeEnum(AttendanceStatus),
        method: z.nativeEnum(AttendanceMethod)
      })
    )
    .min(1)
});

teacherRouter.post("/attendance", async (req, res) => {
  const parsed = attendanceSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_payload" });
  }

  const { courseId, date, records } = parsed.data;
  const course = await prisma.course.findUnique({ where: { id: courseId } });
  if (!course || course.teacherId !== req.user?.id) {
    return res.status(403).json({ error: "forbidden" });
  }

  const sessionDate = new Date(date);
  const session = await prisma.attendanceSession.upsert({
    where: { courseId_date: { courseId, date: sessionDate } },
    update: {},
    create: {
      courseId,
      teacherId: req.user?.id ?? "",
      date: sessionDate
    }
  });

  await prisma.$transaction(
    records.map((record) =>
      prisma.attendanceRecord.upsert({
        where: { sessionId_studentId: { sessionId: session.id, studentId: record.studentId } },
        update: { status: record.status, method: record.method, timestamp: new Date() },
        create: {
          sessionId: session.id,
          studentId: record.studentId,
          status: record.status,
          method: record.method
        }
      })
    )
  );

  return res.status(201).json({ sessionId: session.id });
});

teacherRouter.get("/attendance/history", async (req, res) => {
  const sessions = await prisma.attendanceSession.findMany({
    where: { teacherId: req.user?.id ?? undefined },
    include: { course: true, records: true },
    orderBy: { date: "desc" }
  });

  const history = sessions.map((session) => {
    const present = session.records.filter((r) => r.status === AttendanceStatus.PRESENT).length;
    const absent = session.records.filter((r) => r.status === AttendanceStatus.ABSENT).length;
    return {
      id: session.id,
      course: session.course,
      date: session.date,
      present,
      absent
    };
  });

  return res.json(history);
});

teacherRouter.get("/attendance/:id", async (req, res) => {
  const session = await prisma.attendanceSession.findUnique({
    where: { id: req.params.id },
    include: { course: true, records: { include: { student: true } } }
  });

  if (!session || session.teacherId !== req.user?.id) {
    return res.status(404).json({ error: "not_found" });
  }

  return res.json(session);
});
