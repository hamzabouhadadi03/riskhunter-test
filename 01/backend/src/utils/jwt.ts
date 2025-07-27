import jwt from "jsonwebtoken";
import { IUser } from "../models/User";

export const signAccessToken = (user: IUser) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_ACCESS_SECRET!,
    { expiresIn: "15m" }
  );
};

export const signRefreshToken = (user: IUser) => {
  return jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET!,
    { expiresIn: "7d" }
  );
};

export const verifyRefreshToken = (token: string): any => {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!);
};