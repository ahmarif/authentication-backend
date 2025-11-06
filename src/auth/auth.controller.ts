import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { User } from './user.model.js';
import { generateToken, verifyToken } from '../common/utils/jwt.js';
import { sendEmail } from '../common/service/email.service.js';
import { ApiError } from '../common/utils/ApiError.js';
import { successResponse } from '../common/utils/response.js';
import { generateOtp } from '../common/utils/generateOtp.js';
import { bento } from '../common/utils/bento.client.js';

export const register = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    console.log("🆕 Registering user:", email);

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.warn("⚠️ Email already exists:", email);
      throw new ApiError(400, "Email already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      isVerified: false,
    });

    await newUser.save();
    console.log("✅ New user saved to DB:", newUser._id);

    const token = generateToken({ userId: newUser._id.toString() }, "1h");
    const confirmUrl = `${process.env.CLIENT_URL}/confirm?token=${token}`;
    console.log("🔗 Confirmation URL:", confirmUrl);

    try {
      await sendEmail(email, firstName, confirmUrl, "SIGNUP_CONFIRM");
      console.log("✅ Registration email triggered successfully for:", email);
    } catch (emailErr) {
      console.error("❌ Email sending failed for:", email);
      console.error(emailErr);
    }

    return successResponse(
      res,
      "User registered. Please check your email to confirm your account.",
      {
        id: newUser._id,
        email: newUser.email,
      },
      201
    );
  } catch (err) {
    console.error("❌ Registration error:", err);
    next(err);
  }
};

export const confirmEmail = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.query;
    if (!token || typeof token !== 'string') {
      throw new ApiError(400, 'Confirmation token is required');
    }

    const payload = verifyToken(token) as { userId: string };
    const user = await User.findById(payload.userId);

    if (!user) throw new ApiError(404, 'User not found');
    if (user.isVerified) {
      return successResponse(res, 'Email already confirmed.', { email: user.email });
    }

    user.isVerified = true;
    if (!user.hasBeenAskedToSubscribe) {
      const subscribeLink = `${process.env.CLIENT_URL}/subscribe?email=${encodeURIComponent(user.email)}`;
      sendEmail(user.email, user.firstName, subscribeLink, "SUBSCRIBE_PROMPT")
        .catch(err => console.error("Failed to send subscribe email:", err));

      user.hasBeenAskedToSubscribe = true;
      await user.save();
    }


    return successResponse(res, 'Email confirmed successfully. You can now log in.', {
      id: user._id,
      email: user.email,
    });
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      return next(new ApiError(400, 'Confirmation link expired. Please register again.'));
    }
    next(new ApiError(400, 'Invalid or expired token'));
  }
};

export const resendConfirmation = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = req.body;

    if (!email) throw new ApiError(400, 'Email is required');

    const user = await User.findOne({ email });
    if (!user) throw new ApiError(404, 'User not found');

    if (user.isVerified) {
      return successResponse(res, 'Email already confirmed.', { email: user.email });
    }

    const token = generateToken({ userId: user._id.toString() }, '1h');
    const confirmUrl = `${process.env.CLIENT_URL}/confirm?token=${token}`;

    await sendEmail(user.email, user.firstName, confirmUrl, "SIGNUP_CONFIRM");

    return successResponse(res, 'Confirmation email resent. Please check your inbox.', {
      email: user.email,
    });
  } catch (err) {
    next(err);
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) throw new ApiError(404, 'User not found');

    if (!user.isVerified) {
      throw new ApiError(403, 'Please verify your email first');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) throw new ApiError(401, 'Invalid credentials');

    const token = generateToken(
      { userId: user._id.toString() },
      '1h'
    );

    return successResponse(res, 'Login successful', {
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
    });
  } catch (err) {
    next(err);
  }
};

export const sendOtp = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = req.body;
    if (!email) throw new ApiError(400, 'Email is required');

    const user = await User.findOne({ email });
    if (!user) throw new ApiError(404, 'User not found');

    const otp = generateOtp();
    user.resetOtp = otp;
    user.resetOtpExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await sendEmail(email, user.firstName, `Your OTP for password reset is: ${otp}`, "FORGOT_PASSWORD");

    return successResponse(res, 'OTP sent to your email');
  } catch (err) {
    next(err);
  }
};

export const verifyOtp = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) throw new ApiError(400, 'Email and OTP are required');

    const user = await User.findOne({ email });
    if (!user) throw new ApiError(404, 'User not found');

    if (user.resetOtp !== otp || !user.resetOtpExpiry || user.resetOtpExpiry < new Date()) {
      throw new ApiError(400, 'Invalid or expired OTP');
    }

    return successResponse(res, 'OTP verified successfully');
  } catch (err) {
    next(err);
  }
};

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      throw new ApiError(400, 'Email and new password are required');
    }

    const user = await User.findOne({ email });
    if (!user) throw new ApiError(404, 'User not found');

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetOtp = undefined;
    user.resetOtpExpiry = undefined;

    await user.save();

    // send confirmation email
    await sendEmail(user.email, user.firstName, "", "PASSWORD_RESET_SUCCESS");

    return successResponse(res, 'Password reset successfully');
  } catch (err) {
    next(err);
  }
};

export const subscribe = async (req: Request, res: Response, next: NextFunction) => {
  const email = req.query.email as string;
  if (!email) return res.status(400).send("Missing email");

  try {

    const userDoc = await User.findOne({ email });
    const firstName = userDoc ? userDoc.firstName : '';

    const fallbackName = firstName || email.split('@')[0];

    await bento.V1.track({
      email,
      type: '$subscribe',
      fields: {
        subscribed: true,
        first_name: fallbackName,
      },
    });

    return res.send("You are now subscribed! Thank you!");
  } catch (err) {
    console.error("Subscription error:", err);
    return res.status(500).send("Something went wrong.");
  }
}