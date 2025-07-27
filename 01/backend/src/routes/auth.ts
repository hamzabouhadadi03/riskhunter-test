import express from "express";
import { login, register, verifyEmail } from "../controllers/auth";

const router = express.Router();

router.post("/register", register);

router.get("/verify-email", verifyEmail); 

router.post("/login", login);


export default router;