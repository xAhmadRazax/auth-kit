// src/app.ts
import express from "express";
import type { Application } from "express";
import cookieParser from "cookie-parser";
// import { Database } from "./config/database";
// import authRoutes from "./routes/auth.routes";
import errorMiddleware from "../middlewares/error.middleware";
import { router as authRoutes } from "../routes/auth.route";
import { router as userRoutes } from "../routes/user.route";

export class App {
  private app: Application;
  private port: number;

  constructor() {
    this.app = express();
    this.port = Number(process.env.PORT) || 3000;
  }

  // Initialize everything
  static async init(): Promise<App> {
    const appInstance = new App();

    // // 1. Connect to database
    // console.log("📦 Connecting to database...");

    // 2. Setup middleware
    console.log("⚙️  Setting up middleware...");
    appInstance.setupMiddleware();

    // 3. Setup routes
    console.log("🛣️  Setting up routes...");
    appInstance.setupRoutes();

    // 4. Setup error handling
    console.log("🚨 Setting up error handlers...");
    appInstance.setupErrorHandlers();

    return appInstance;
  }

  // Setup middleware
  private setupMiddleware(): void {
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(cookieParser());
  }

  // Setup routes
  private setupRoutes(): void {
    //     this.app.use("/auth", authRoutes);
    //     // Health check
    // this.app.get("/", (req, res) => {
    //   res.json({ status: "ok" });
    // });

    this.app.use("/api/v1/auth", authRoutes);
    this.app.use("/api/v1/users", userRoutes);
  }

  // Setup error handlers
  private setupErrorHandlers(): void {
    this.app.use(errorMiddleware);
  }

  // Start listening
  listen(): void {
    this.app.listen(this.port, () => {
      console.log(`🚀 AuthKit running on http://localhost:${this.port}`);
    });

    process.on("unhandledRejection", (err) => {
      console.error("❌ Unhandled Rejection:", err);
      process.exit(1);
    });

    process.on("uncaughtException", (err) => {
      console.error("❌ Uncaught Exception:", err);
      process.exit(1);
    });
  }

  // Graceful shutdown
  async shutdown(): Promise<void> {
    console.log("👋 Shutting down gracefully...");
    // await Database.disconnect();
    process.exit(0);
  }
}
