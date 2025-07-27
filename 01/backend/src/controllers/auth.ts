import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { User } from "../models/User";
import { hashPassword } from "../utils/hash";
import { sendVerificationEmail } from "../services/emailService";

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
