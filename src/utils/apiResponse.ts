
export default class ApiResponse {
    constructor(public status: number, public message: string, public data?: any) { }
}