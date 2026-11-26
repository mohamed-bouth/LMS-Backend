import express from "express";
import {
  createUser,
  getUser,
  listUsers,
  updateUser,
} from "../controllers/adminUserController.js";
import { authenticate, authorize } from "../middlewares/Auth.js";

const router = express.Router();

router.use(authenticate, authorize("admin"));
router.get("/", listUsers);
router.post("/", createUser);
router.get("/:userId", getUser);
router.patch("/:userId", updateUser);

export default router;
