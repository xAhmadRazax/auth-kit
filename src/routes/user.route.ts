import { Router } from "express";
import { protect } from "../middlewares/auth.middleware";
import { getMe } from "../controller/user.controller";

const router = Router();

router.route("/me").get(protect, getMe);

export { router };
