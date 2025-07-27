import nodemailer from "nodemailer";

const getTransporter = () => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    throw new Error("EMAIL_USER or EMAIL_PASS not set in environment variables");
  }
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
};

export const sendVerificationEmail = async (to: string, token: string) => {
  const url = `${process.env.CLIENT_URL}/verify-email?token=${token}`;
  const transporter = getTransporter();
  await transporter.sendMail({
    from: `"Risk Hunter" <${process.env.EMAIL_USER}>`,
    to,
    subject: "Email Verification",
    html: `
      <div style="font-family: Arial, sans-serif; background: #f7f7f7; padding: 40px 0;">
        <table align="center" width="100%" style="max-width: 480px; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.07);">
          <tr>
            <td style="padding: 32px 32px 16px 32px; text-align: center;">
              <img src="https://cdn-icons-png.flaticon.com/512/3135/3135715.png" alt="Risk Hunter" width="64" style="margin-bottom: 16px;" />
              <h2 style="color: #2d3748; margin-bottom: 8px;">Welcome to Risk Hunter!</h2>
              <p style="color: #4a5568; font-size: 16px; margin-bottom: 24px;">
                Thank you for registering.<br>
                Please verify your email address to activate your account.
              </p>
              <a href="${url}" style="display: inline-block; padding: 12px 28px; background: #2563eb; color: #fff; border-radius: 4px; text-decoration: none; font-weight: bold; font-size: 16px;">
                Verify Email
              </a>
              <p style="color: #a0aec0; font-size: 13px; margin-top: 32px;">
                If the button doesn't work, copy and paste this link in your browser:<br>
                <a href="${url}" style="color: #2563eb;">${url}</a>
              </p>
              <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 32px 0 16px 0;">
              <p style="color: #a0aec0; font-size: 12px;">
                &copy; ${new Date().getFullYear()} Risk Hunter. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </div>
    `,
  });
};