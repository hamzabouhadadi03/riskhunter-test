import express from "express";
import { login, logout, refreshToken, register, verifyEmail } from "../controllers/auth";

const router = express.Router();

router.post("/register", register);

router.get("/verify-email", verifyEmail); 

router.post("/login", login);

router.get("/refresh-token", refreshToken);

router.post("/logout", logout);

export default router;