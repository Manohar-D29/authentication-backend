import mongoose, { Document, Model, Schema } from "mongoose";

export interface IEmailVerification extends Document {
    userId: string;
    otp: string;
    createdAt: Date;
}
// Defining Schema
const emailVerificationSchema: Schema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: '10m'
    }
});

// Model
const EmailVerificationModel: Model<IEmailVerification> = mongoose.model<IEmailVerification>("EmailVerification", emailVerificationSchema);

export default EmailVerificationModel;