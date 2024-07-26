import mongoose, { Document, Model, Schema } from "mongoose";

export interface IUserRefreshToken extends Document {
    userId: string;
    token: string;
    blacklisted: boolean;
    createdAt: Date;
}
// Defining Schema
const userRefreshTokenSchema: Schema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    token: {
        type: String,
        required: true
    },
    blacklisted: {
        type: Boolean,
        default: false
    }
}, { timestamps: true });

// Model
const UserRefreshTokenModel: Model<IUserRefreshToken> = mongoose.model<IUserRefreshToken>("UserRefreshToken", userRefreshTokenSchema);

export default UserRefreshTokenModel;