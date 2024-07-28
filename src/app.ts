import express, { Application } from 'express';
import cors from "cors";
import passport from 'passport'
import router from './routes';
import errorMiddleware from './middlewares/errorMiddleware';
import cookieParser from 'cookie-parser';
import "./config/passportJwtStratergy"
// create app 
const app: Application = express();

// middleware


const options = {
    origin: process.env.FRONTEND_URL,
    credentials: true,
    optionsSuccessStatus: 200,
};

app.use(cors(options));

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize())

//  routes
app.use("/api/v1", router)

// common error handler
app.use(errorMiddleware)

// export app
export default app