import { Request } from "express"
import { IUser } from "../models/user.model"

export interface IRegisterReq {
    name: string,
    email: string,
    password: string,
    profile?: string
}

export interface ILoginReq {
    email: string,
    password: string
}

export interface IPayload {
    _id: string,
    email: string
}

export interface IToken {
    accessToken: string,
    refreshToken: string,
    accessTokenExp: number,
    refreshTokenExp: number
}

export interface IChangePasswordReq {
    password: string
    confirmPassword: string
}

export interface AuthenticatedRequest extends Request {
    user?: IUser; // Ensure `req.user` is typed correctly
}

export interface IResetParams {
    id: string
    token: string
}

export interface IOtpReq {
    email: string,
    otp: string
}