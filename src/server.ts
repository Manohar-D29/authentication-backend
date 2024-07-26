import dotEnv from 'dotenv';
dotEnv.config()

import { connectDB } from './db/mongo_connection';
import app from './app';

connectDB().then(() => {
    app.listen(process.env.PORT, () => {
        console.log(`Server listening on port ${process.env.PORT}`)
    })
}).catch((error: Error) => {
    console.log(error)
    process.exit(1)
})