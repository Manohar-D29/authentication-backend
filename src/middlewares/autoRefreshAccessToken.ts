import { NextFunction, Request, Response } from "express";
import UtilityFunctions from "../utils/utilityFunctions";
import CustomError from "../utils/customError";
import asyncHandler from "../utils/asyncHandler";
const accessTokenAutoRefresh = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {

    const accessToken = req.cookies.accessToken;

    if (accessToken && !(UtilityFunctions.isTokenExpired(accessToken))) {
        //  Add the access token to the Authorization header
        req.headers['authorization'] = `Bearer ${accessToken}`
    }

    if (!accessToken) {
        // Attempt to get a new access token using the refresh token
        const oldRefreshToken = req.cookies.refreshToken;
        if (!oldRefreshToken) {
            // If refresh token is also missing, throw an error
            throw new CustomError('Unauthorized: Refresh token is missing', 401)
        }
        const decoded = await UtilityFunctions.verifyToken(oldRefreshToken, process.env.JWT_REFRESH_TOKEN_SECRET!);
        if (!decoded) throw new CustomError('Unauthorized: Invalid refresh token', 401)

        // Access token is expired, make a refresh token request
        const { accessToken, refreshToken, accessTokenExp, refreshTokenExp } = await UtilityFunctions.generateTokens({ _id: decoded?._id, email: decoded?.email })

        // set cookies
        UtilityFunctions.setCookie(res, { accessToken, refreshToken, accessTokenExp, refreshTokenExp });

        //  Add the access token to the Authorization header
        req.headers['authorization'] = `Bearer ${accessToken}`
    }
    next()

})
export default accessTokenAutoRefresh