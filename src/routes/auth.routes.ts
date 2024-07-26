import { Router } from "express";
import { AuthController } from "../controllers/auth.controllers";
import accessTokenAutoRefresh from "../middlewares/autoRefreshAccessToken";
import passport from "passport";

const authRouter = Router();

// unprotected routes
authRouter.route('/sign-up').post(AuthController.signUpUser)
authRouter.route('/sign-in').post(AuthController.signInUser)
authRouter.route('/verify-email').post(AuthController.verifyEmail)
authRouter.route('/refresh-token').post(AuthController.refreshToken)
authRouter.route('/reset-password-link').post(AuthController.passwordResetLink)
authRouter.route('/reset-password/:userId/:token').post(AuthController.resetPassword)

// protected routes
authRouter.route("/me").get(accessTokenAutoRefresh, passport.authenticate('jwt', { session: false }), AuthController.getUser)
authRouter.route('/logout').post(accessTokenAutoRefresh, passport.authenticate('jwt', { session: false }), AuthController.Logout)
authRouter.route('/change-password').post(accessTokenAutoRefresh, passport.authenticate('jwt', { session: false }), AuthController.ChangePassword)


export default authRouter