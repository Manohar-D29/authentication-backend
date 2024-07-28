import { Request, Response, Router } from "express";
import passport from "passport";
import UtilityFunctions from "../utils/utilityFunctions";

const googleRouter: Router = Router();
googleRouter.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

googleRouter.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: `${process.env.FRONTEND_URL}/account/login`, session: false }),
    (req: Request, res: Response) => {
        // Type assertion to ensure TypeScript understands the shape of req.user
        const { user, accessToken, refreshToken, accessTokenExp, refreshTokenExp } = req.user as any;

        UtilityFunctions.setCookie(res, { accessToken, refreshToken, accessTokenExp, refreshTokenExp });

        // Successful authentication, redirect home.
        res.redirect(`${process.env.FRONTEND_URL}/user/profile`);
    });

export default googleRouter