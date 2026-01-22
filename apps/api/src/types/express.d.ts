import { Role } from "@prisma/client";

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        role: Role;
        schoolId: string | null;
        name: string;
        email: string;
      };
    }
  }
}

export {};
