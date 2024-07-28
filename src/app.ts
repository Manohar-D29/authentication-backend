import express, { Application } from 'express';
import cors from "cors";
import passport from 'passport'
import router from './routes';
import errorMiddleware from './middlewares/errorMiddleware';
import cookieParser from 'cookie-parser';
import "./config/passportJwtStratergy"
import "./config/passwordGoogleStratergy"
import googleRouter from './routes/google.routes';
// import session from 'express-session';
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


// app.use(session({
//     secret: process.env.SESSION_SECRET as string,
//     resave: false,
//     saveUninitialized: true,
//     cookie: { secure: process.env.NODE_ENV === 'production' }
// }));

app.use(passport.initialize());
// app.use(passport.session());



//  routes
app.use("/api/v1", router)
app.use(googleRouter)

// common error handler
app.use(errorMiddleware)

// export app
export default app