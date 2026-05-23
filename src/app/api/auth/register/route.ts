import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import prisma from "@/lib/db";
import { RegisterSchema } from "@/lib/validations/auth";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const validatedData = RegisterSchema.safeParse(body);

    if (!validatedData.success) {
      return NextResponse.json(
        { error: "Invalid input", details: validatedData.error.flatten() },
        { status: 400 }
      );
    }

    const { name, email, password } = validatedData.data;

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return NextResponse.json(
        { error: "User with this email already exists" },
        { status: 409 }
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    return NextResponse.json(
      { message: "User registered successfully", userId: user.id },
      { status: 201 }
    );
  } catch (error: any) {
    console.error("REGISTRATION_ERROR", error);
    
    let errorMessage = "Internal server error";
    if (!process.env.DATABASE_URL) {
      errorMessage = "Database URL is not configured. Please create a .env file with DATABASE_URL.";
    } else if (error.code === "P2021" || error.message?.includes("does not exist")) {
      errorMessage = "Database tables not found. Please run 'npx prisma migrate deploy' to set up the database schema.";
    } else if (error.message?.includes("Can't reach database server")) {
      errorMessage = "Cannot reach the database server. Please check your DATABASE_URL and network connection.";
    } else if (process.env.NODE_ENV === "development") {
      errorMessage = `Registration error: ${error.message || error}`;
    }

    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}
