import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { UserModel } from "../models/user.model";
import UtilityFunctions from "../utils/utilityFunctions";

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID!,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
            callbackURL: "/api/v1/auth/google/callback",
            scope: ["profile"],
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                let user = await UserModel.findOne({ email: profile._json.email });

                if (!user) {
                    const password = UtilityFunctions.createPassword(
                        profile._json.name as string
                    );
                    const hashPassword = UtilityFunctions.hashPassword(password);
                    // save profile details in db
                    user = await UserModel.create({
                        name: profile._json.name,
                        email: profile._json.email,
                        is_varified: true,
                        password: hashPassword,
                    });
                }

                // generate token
                const { accessToken, refreshToken, accessTokenExp, refreshTokenExp } = await UtilityFunctions.generateTokens({
                    _id: user?._id,
                    email: user?.email,
                });
                return done(null, {
                    user,
                    accessToken,
                    refreshToken,
                    accessTokenExp,
                    refreshTokenExp,
                });
            } catch (error) {
                return done(error);
            }

        }
    )

);

// serialize and deserialize user when using session
passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (obj: any, done) {
    done(null, obj);
});

