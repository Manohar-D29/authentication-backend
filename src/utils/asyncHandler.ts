
// export default function asyncHandler(fn: Function) {
//     return async function (req: any, res: any, next: any) {
//         try {
//             await fn(req, res, next)
//         } catch (error) {
//             next(error)
//         }
//     }
// }

import { NextFunction, Request, Response } from "express"



const asyncHandler = (fn: Function) => (req: Request, res: Response, next: NextFunction) => {
    return Promise.resolve(fn(req, res, next)).catch(next)
}

export default asyncHandler