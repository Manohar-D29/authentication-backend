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
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize())

const options = {
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204
};
app.use(cors(options));

//  routes
app.use("/api/v1", router)

// common error handler
app.use(errorMiddleware)

// export app
export default app