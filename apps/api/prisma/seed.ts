import bcrypt from "bcryptjs";
import { PrismaClient, Role, Status } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const email = "pertuz001@gmail.com";
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return;
  }

  const passwordHash = await bcrypt.hash("Clave.12345", 12);
  await prisma.user.create({
    data: {
      email,
      passwordHash,
      name: "fabian pertuz",
      role: Role.ADMIN,
      status: Status.ACTIVE
    }
  });
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
