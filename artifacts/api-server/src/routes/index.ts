import { Router, type IRouter } from "express";
import healthRouter from "./health";
import breachRouter from "./breach";

const router: IRouter = Router();

router.use(healthRouter);
router.use(breachRouter);

export default router;
