import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { User } from "../models/User";
import { hashPassword , comparePassword } from "../utils/hash";
import { sendVerificationEmail } from "../services/emailService";
import { signAccessToken, signRefreshToken } from "../utils/jwt";


export const register = async (req: Request, res: Response) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    // Vérifie si l'utilisateur existe déjà
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email is already in use" });
    }

    // Hash du mot de passe
    const hashedPassword = await hashPassword(password);

    // Génération du token de vérification email
    const emailVerificationToken = jwt.sign(
      { email },
      process.env.EMAIL_VERIFICATION_SECRET!,
      { expiresIn: "1h" }
    );

    // Création de l'utilisateur
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      emailVerificationToken,
    });

    // Envoi de l'email de vérification
    await sendVerificationEmail(email, emailVerificationToken);

    return res.status(201).json({
      message: "User registered successfully. Please check your email to verify your account.",
    });
  } catch (err) {
    console.error("Registration error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};


export const verifyEmail = async (req: Request, res: Response) => {
  const token = req.query.token as string;

  if (!token) return res.status(400).json({ message: "Token is missing" });

  try {
    // 1. Vérifie le token JWT
    const decoded = jwt.verify(token, process.env.EMAIL_VERIFICATION_SECRET!) as { email: string };

    const user = await User.findOne({ email: decoded.email });

    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.isEmailVerified) {
      return res.status(400).json({ message: "Email already verified" });
    }

    if (user.emailVerificationToken !== token) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // 2. Met à jour le user
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    await user.save();

    return res.status(200).json({ message: "Email verified successfully" });
  } catch (err) {
    return res.status(400).json({ message: "Invalid or expired token", error: err });
  }
};


export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user)
      return res.status(401).json({ message: "Invalid email or password" });

    if (!user.isEmailVerified)
      return res.status(403).json({ message: "Email not verified" });

    const isMatch = await comparePassword(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    user.refreshToken = refreshToken;
    await user.save();

    // Définir le refresh token comme cookie sécurisé HttpOnly
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Uniquement en HTTPS en production
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
    });

    return res.json({ accessToken, user: { id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error", error: err });
  }
};