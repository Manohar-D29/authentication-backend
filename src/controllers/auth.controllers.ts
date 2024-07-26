import { Request, RequestHandler, Response } from "express";
import jwt from 'jsonwebtoken';
import { AuthenticatedRequest, IChangePasswordReq, ILoginReq, IOtpReq, IPayload, IRegisterReq, IResetParams } from "../interfaces/authReq.interface";
import EmailVerificationModel, { IEmailVerification } from "../models/emailVarification.model";
import UserRefreshTokenModel from "../models/tokens.model";
import { IUser, UserModel } from "../models/user.model";
import ApiResponse from "../utils/apiResponse";
import asyncHandler from "../utils/asyncHandler";
import CustomError from "../utils/customError";
import UtilityFunctions from "../utils/utilityFunctions";

export class AuthController {

    static signUpUser: RequestHandler = asyncHandler(async (req: Request<{}, {}, IRegisterReq>, res: Response) => {
        if (!req.body) throw new CustomError('Request body is empty', 400)
        const { name, email, password } = req.body
        if (!name || !email || !password) throw new CustomError('All fields are required', 400)

        // check if user already exists
        const existingUser: IUser | null = await UserModel.findOne({ email })
        if (existingUser) throw new CustomError('User already exists please login', 409)

        // encrypt password
        const hashPassword: string = UtilityFunctions.hashPassword(password)

        // create user  
        const user: IUser = await UserModel.create({ name, email, password: hashPassword })

        // send varifiaction email
        await UtilityFunctions.sendEmailVarificationOTP(user)
        // send response
        res.status(201).json(new ApiResponse(201, 'User created successfully', user))
    })

    static verifyEmail: RequestHandler = asyncHandler(async (req: Request<{}, {}, IOtpReq>, res: Response) => {
        if (!req.body) throw new CustomError('Request body is empty', 400)
        const { userId, otp } = req.body
        if (!userId || !otp) throw new CustomError('All fields are required', 400)

        const existingUser: IUser | null = await UserModel.findOne({ _id: userId })
        if (!existingUser) throw new CustomError('User not found', 404)
        if (existingUser.is_varified) throw new CustomError('User already varified', 409)

        const emailVarification: IEmailVerification | null = await EmailVerificationModel.findOne({ userId: existingUser._id, otp })
        if (!emailVarification) throw new CustomError('Invalid OTP, Please try again', 400)
        if (emailVarification.otp !== otp) throw new CustomError('Invalid OTP, Please try again', 400)

        // update user AND delete otp
        await Promise.all([UserModel.findByIdAndUpdate({ _id: existingUser._id }, { is_varified: true }), EmailVerificationModel.deleteOne({ userId: existingUser._id })])
        // send response
        res.status(200).json(new ApiResponse(200, 'Email verified successfully', {}))
    });

    static resendOTP: RequestHandler = asyncHandler(async (req: Request<{}, {}, { userId: string }>, res: Response) => {
        if (!req.body) throw new CustomError('Request body is empty', 400)
        const { userId } = req.body
        if (!userId) throw new CustomError('All fields are required', 400)

        const existingUser: IUser | null = await UserModel.findOne({ _id: userId })
        if (!existingUser) throw new CustomError('User not found', 404)

        // update user AND delete otp
        await EmailVerificationModel.deleteMany({ userId: existingUser._id })
        // send varifiaction email
        await UtilityFunctions.sendEmailVarificationOTP(existingUser)

        // send response
        res.status(200).json(new ApiResponse(200, 'OTP resend successfully'))
    });

    static signInUser: RequestHandler = asyncHandler(async (req: Request<{}, {}, ILoginReq>, res: Response) => {
        if (!req.body) throw new CustomError('Request body is empty', 400)
        const { email, password } = req.body
        if (!email || !password) throw new CustomError('All fields are required', 400)

        const existingUser: IUser | null = await UserModel.findOne({ email })
        if (!existingUser) throw new CustomError('User not found', 404)

        if (!existingUser.is_varified) throw new CustomError('Please verify your email', 400)

        if (!UtilityFunctions.comparePassword(password, existingUser.password)) throw new CustomError('Invalid credentials', 400)

        // generate token
        const tokens = await UtilityFunctions.generateTokens(existingUser)
        // set to cookie
        UtilityFunctions.setCookie(res, tokens)
        // send response
        res.status(200).json(new ApiResponse(200, 'User logged in successfully'))

    });

    static refreshToken: RequestHandler = asyncHandler(async (req: Request, res: Response) => {
        if (!req.cookies) throw new CustomError('No cookies found', 400)
        const { refreshToken } = req.cookies

        if (!refreshToken) throw new CustomError('No refresh token found', 400)

        // verify token
        const decoded: IPayload = await UtilityFunctions.verifyToken(refreshToken, process.env.REFRESH_TOKEN_SECRET!)
        if (!decoded) throw new CustomError('Invalid refresh token', 400)

        // get user  and token from db
        const [existingUser, existingToken]: any = await Promise.all([UserModel.findById(decoded?._id), UserRefreshTokenModel.findOne({ token: refreshToken })])
        if (!existingUser) throw new CustomError('User not found', 404)
        if (!existingToken) throw new CustomError('Invalid refresh token', 400)

        // compare token
        if (refreshToken !== existingToken.token) throw new CustomError('unUnauthorized access', 401)

        // generate new tokens
        const tokens = await UtilityFunctions.generateTokens(existingUser)

        // set to cookie
        UtilityFunctions.setCookie(res, tokens)

        // send response    
        res.status(200).json(new ApiResponse(200, 'Refreshed token successfully', { accessToken: tokens.accessToken, refreshToken: tokens.refreshToken }))
    })

    static getUser: RequestHandler = asyncHandler(async (req: Request, res: Response) => {
        if (!req.user) throw new CustomError('User not found', 404)
        res.status(200).json(new ApiResponse(200, 'User fetched successfully', req.user))
    })

    static Logout: RequestHandler = asyncHandler(async (req: Request, res: Response) => {
        if (!req.user) throw new CustomError('User not found', 404)
        // blacklist token
        await UserRefreshTokenModel.findOneAndUpdate({ token: req.cookies.refreshToken },
            { $set: { isBlacklisted: true } }
        )
        // clearCookies
        res.clearCookie('refreshToken')
        res.clearCookie('accessToken')
        res.clearCookie('is_auth')

        res.status(200).json(new ApiResponse(200, 'User logged out successfully'))
    })

    static ChangePassword: RequestHandler = asyncHandler(async (req: Request<{}, {}, IChangePasswordReq> & AuthenticatedRequest, res: Response) => {
        if (!req.user) throw new CustomError('Unauthorized', 401)
        if (!req.body) throw new CustomError('Request body is empty', 400)

        const { password, confirmPassword } = req.body

        if (!password || !confirmPassword) throw new CustomError('All fields are required', 400)
        if (password !== confirmPassword) throw new CustomError('Passwords do not match', 400)

        // //check for user
        const existingUser: IUser | null = await UserModel.findById(req.user?._id)
        if (!existingUser) throw new CustomError('User not found', 404)
        if (!existingUser.is_varified) throw new CustomError('Please verify your email', 400)

        // hash password
        const hashedPassword = await UtilityFunctions.hashPassword(password)

        // update password
        const updatedUser: IUser | null = await UserModel.findByIdAndUpdate(req.user?._id, { password: hashedPassword })

        res.status(200).json(new ApiResponse(200, 'Password changed successfully', updatedUser))

    })

    static passwordResetLink: RequestHandler = asyncHandler(async (req: Request<{}, {}, { email: string }>, res: Response) => {

        if (!req.body) throw new CustomError('Request body is empty', 400)
        const { email } = req.body
        if (!email) throw new CustomError('Email is required', 400)

        const existingUser: IUser | null = await UserModel.findOne({ email })
        if (!existingUser) throw new CustomError('User not found', 404)

        // generate token
        const resetToken = jwt.sign({ _id: existingUser._id }, process.env.JWT_ACCESS_TOKEN_SECRET!, { expiresIn: '10m' })

        // send email
        await UtilityFunctions.sendResetLink(existingUser, resetToken)

        res.status(200).json(new ApiResponse(200, 'Password reset link sent to your email'))
    })

    static resetPassword: RequestHandler = asyncHandler(async (req: Request<IResetParams, {}, IChangePasswordReq>, res: Response) => {

        if (!req.body) throw new CustomError('Request body is empty', 400)
        const { password, confirmPassword } = req.body
        if (!req.params) throw new CustomError('Request params is empty', 400)
        const { userId, token } = req.params

        console.log({ userId, token })
        if (!password || !confirmPassword) throw new CustomError('All fields are required', 400)
        if (password !== confirmPassword) throw new CustomError('Passwords do not match', 400)

        // verify token
        const decoded: any = await jwt.verify(token, process.env.JWT_ACCESS_TOKEN_SECRET!)
        if (!decoded) throw new CustomError('Link is invalid or expired, please try again', 400)

        // check for user
        const existingUser: IUser | null = await UserModel.findById(userId)
        if (!existingUser) throw new CustomError('User not found', 404)

        // hash password
        const hashedPassword = UtilityFunctions.hashPassword(password)

        // update password
        const updatedUser: IUser | null = await UserModel.findByIdAndUpdate(userId, { password: hashedPassword })

        res.status(200).json(new ApiResponse(200, 'Password changed successfully', updatedUser))
    })


}