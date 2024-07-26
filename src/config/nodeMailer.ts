import nodemailer, { Transporter } from 'nodemailer';

export let transporter: Transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST as string,
    port: parseInt(process.env.EMAIL_PORT as string),
    secure: true,
    auth: {
        user: process.env.EMAIL_USER as string,
        pass: process.env.EMAIL_PASS as string
    },
});

export const sendEmail = async (email: string, subject: string, text?: string, html?: string) => {
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject,
            text,
            html
        })
    } catch (error) {
        console.log(error)
    }
}

