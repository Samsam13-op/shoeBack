import type { Request, Response } from "express";
import type { HydratedDocument } from "mongoose";
import User from "../models/user.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import type { IUser, PublicUser } from "../types/models.js";
import { getErrorMessage } from "../utils/errors.js";
import { env } from "../config/env.js";

interface SignUpBody {
  name?: unknown;
  email?: unknown;
  password?: unknown;
}

interface LoginBody {
  email: string;
  password: string;
}

const publicUser = (user: HydratedDocument<IUser>): PublicUser => ({
  _id: user._id.toString(),
  name: user.name,
  email: user.email,
  role: user.role,
});

export const signUp = async (
  req: Request<{}, {}, SignUpBody>,
  res: Response,
) => {
  try {
    const body = req.body;
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({ message: "Invalid signup request" });
    }

    const email =
      typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const password = body.password;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    if (typeof password !== "string" || password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters long",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        message: "User already exist",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    res.status(201).json(publicUser(user));
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === 11000
    ) {
      return res.status(409).json({ message: "User already exist" });
    }

    console.error("Signup error:", getErrorMessage(error));
    res.status(500).json({ message: "Unable to create account" });
  }
};

export const login = async (req: Request<{}, {}, LoginBody>, res: Response) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user)
      return res.status(400).json({
        message: "User not Found",
      });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        message: "invalid credentails",
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
      },

      env.JWT_SECRET,

      {
        expiresIn: "1d",
      },
    );

    res.status(200).json({
      message: "login successful",
      user: publicUser(user),
      token,
    });
  } catch (error) {
    res.status(400).json({ message: getErrorMessage(error) });
  }
};
