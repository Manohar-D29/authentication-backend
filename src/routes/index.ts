import { Router } from "express";
import authRouter from "./auth.routes";
import googleRouter from "./google.routes";

const router: Router = Router();

router.use('/auth', authRouter)
router.use(googleRouter)


export default router