import mongoose, { Document, Model, ObjectId, Schema } from "mongoose"

export interface IUser extends Document {
    _id: string | ObjectId
    name: string
    email: string
    password: string
    profile?: string
    is_varified?: boolean
}

const UserSchema: Schema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    profile: {
        type: String
    },
    is_varified: {
        type: Boolean,
        default: false
    },
    role: {
        type: String,
        enum: ["admin", "user"],
        default: "user"
    }
}, { timestamps: true })


export const UserModel: Model<IUser> = mongoose.model<IUser>("User", UserSchema)
