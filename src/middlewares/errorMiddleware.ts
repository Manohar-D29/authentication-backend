import { NextFunction, Request, Response } from "express";
import CustomError from "../utils/customError";


const errorMiddleware = (err: CustomError, req: Request, res: Response, next: NextFunction) => {
    let status = err.statusCode || 500
    let message = err.message || 'Something went wrong'

    if (err.message === "JsonWebTokenError") {
        message = "Invalid token"
    }

    res.status(status).json({
        success: false,
        status,
        message
    })
    next()

}

export default errorMiddleware