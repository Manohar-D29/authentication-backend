import { Router } from "express";
import authRouter from "./auth.routes";

const router: Router = Router();

router.use('/auth', authRouter)

export default router