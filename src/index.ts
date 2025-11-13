import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import authRoutes from "./auth/auth.route.js";
import { errorHandler } from "./auth/middleware/errorHandler.middleware.js";

dotenv.config();

const app = express();

app.use(
  cors({
    origin: [
      "https://register.analyticsauditor.com",
      // Add other allowed domains here as needed
    ],
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/auth", authRoutes);

app.use(errorHandler);

mongoose
  .connect(process.env.MONGO_URI || "", {})
  .then(() => {
    console.log("MongoDB connected");
    app.listen(process.env.PORT || 3000, () => {
      console.log(
        `Server running on http://localhost:${process.env.PORT || 3000}`
      );
    });
  })
  .catch((err) => console.error("DB connection error:", err));
