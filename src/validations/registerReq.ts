import Joi from "joi"

export const registerReq = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required(),
    profile: Joi.string()
})