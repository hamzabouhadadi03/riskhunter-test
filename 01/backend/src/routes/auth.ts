import express from "express";
import { login, refreshToken, register, verifyEmail } from "../controllers/auth";

const router = express.Router();

router.post("/register", register);

router.get("/verify-email", verifyEmail); 

router.post("/login", login);

router.get("/refresh-token", refreshToken);


export default router;