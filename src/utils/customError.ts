
export default class CustomError extends Error {
    constructor(public message: string, public statusCode: number, public success?: boolean) {
        super(message);
        this.statusCode = statusCode;
        this.success = false
    }
}
