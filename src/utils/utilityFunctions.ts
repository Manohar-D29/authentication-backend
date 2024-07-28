import bcrypt from "bcryptjs"
import crypto from "node:crypto"
import jwt from "jsonwebtoken"
import { sendEmail } from "../config/nodeMailer"
import EmailVerificationModel from "../models/emailVarification.model"
import { IPayload, IToken } from "../interfaces/authReq.interface"
import { IUser } from "../models/user.model"
import UserRefreshTokenModel from "../models/tokens.model"


export default class UtilityFunctions {

    static hashPassword: (password: string) => string = (password: string) => {
        const salt: string = bcrypt.genSaltSync(10)
        return bcrypt.hashSync(password, salt)
    }

    static comparePassword: (password: string, hashPassword: string) => boolean = (password: string, hashPassword: string) => {
        return bcrypt.compareSync(password, hashPassword)
    }

    static generateOtp: () => string = () => {
        return crypto.randomInt(100000, 999999).toString()
    }

    static sendEmailVarificationOTP: (user: IUser) => Promise<void> = async (user: IUser) => {
        // generate otp
        const otp = this.generateOtp()
        // save otp in db
        await new EmailVerificationModel({ userId: user._id, otp }).save()
        // create varification link
        const link = `${process.env.FRONTEND_URL}/account/verify-email`
        //generate & send email
        const html = `<p>Dear ${user.name},</p><p>Thank you for signing up with our website.
         To complete your registration, please verify your email address by entering the following one-time password (OTP): <a href="${link}">${link}</a> </p>
        <h2>OTP: ${otp}</h2>
        <p>This OTP is valid for 10 minutes. If you didn't request this OTP, please ignore this email.</p>`

        await sendEmail(user.email, 'Email Varification', "", html)
    }

    static generateTokens: (user: IUser | IPayload) => Promise<IToken> = async (user: IUser | IPayload) => {
        const payload: IPayload = { _id: String(user._id), email: user.email }

        // generate access token
        const accessTokenExp = Math.floor(Date.now() / 1000) + 100; // Set expiration to 100 seconds from now
        const accessToken: string = jwt.sign({ ...payload, exp: accessTokenExp }, process.env.JWT_ACCESS_TOKEN_SECRET!,
            // { expiresIn: "100s" }
        )
        // generate refresh token
        const refreshTokenExp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 5; // Set expiration to 5 days from now

        const refreshToken: string = jwt.sign({ ...payload, exp: refreshTokenExp }, process.env.JWT_REFRESH_TOKEN_SECRET!,
            //  { expiresIn: "5d" }
        )

        await Promise.all([UserRefreshTokenModel.deleteMany({ userId: user._id }), new UserRefreshTokenModel({ userId: user._id, token: refreshToken }).save()])

        return { accessToken, refreshToken, accessTokenExp, refreshTokenExp }
    }

    static verifyToken: (token: string, secretKey: string) => any = (token: string, secretKey: string) => {
        return jwt.verify(token, secretKey)
    }

    static setCookie: (res: any, tokensObj: IToken) => void = (res: any, tokensObj: IToken) => {

        const accessTokenMaxAge = (tokensObj.accessTokenExp - Math.floor(Date.now() / 1000)) * 1000;
        const refreshTokenmaxAge = (tokensObj.refreshTokenExp - Math.floor(Date.now() / 1000)) * 1000;

        // Set Cookie for Access Token
        res.cookie('accessToken', tokensObj.accessToken, {
            httpOnly: true,
            secure: true, // Set to true if using HTTPS
            maxAge: accessTokenMaxAge,
            // sameSite: 'strict', // Adjust according to your requirements
        });

        // Set Cookie for Refresh Token
        res.cookie('refreshToken', tokensObj.refreshToken, {
            httpOnly: true,
            secure: true, // Set to true if using HTTPS
            maxAge: refreshTokenmaxAge,
            // sameSite: 'strict', // Adjust according to your requirements
        });

        res.cookie('is_authenticated', true, {
            httpOnly: false,
            secure: true, // Set to true if using HTTPS
            maxAge: refreshTokenmaxAge,
            // sameSite: 'strict', // Adjust according to your requirements         )
        });
    }

    static isTokenExpired: (token: string) => boolean = (token: string) => {
        if (!token) return true
        const decoded: IToken = this.verifyToken(token, process.env.JWT_ACCESS_TOKEN_SECRET!)
        return decoded ? false : true
    }

    static isTokenExpirednew = (token: string) => {
        if (!token) {
            return true
        }
        const decodedToken: any = jwt.decode(token)
        const currentTime = Date.now() / 1000
        return decodedToken.exp < currentTime
    }

    static sendResetLink: (user: IUser, token: string) => Promise<any> = async (user: IUser, token: string) => {
        const id = user._id
        // create varification link
        const link = `${process.env.FRONTEND_URL}/account/reset-password-confirm/${id}/${token}`

        //generate & send email
        const html = `<p>Dear ${user.name},</p><p>Here is your Reset Password Link : <a href="${link}"> <h4>Click Here</h4></a> </p>
        <p>This link is valid for 10 minutes. If you didn't request for reset password link, please ignore this email.</p>`

        await sendEmail(user.email, 'Reset Password Link', "", html)
    }

}