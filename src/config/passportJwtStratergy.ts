import { Strategy as JwtStrategy, ExtractJwt, StrategyOptions } from 'passport-jwt';
import passport from 'passport';
import { IUser, UserModel } from '../models/user.model';

const opts: StrategyOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_ACCESS_TOKEN_SECRET as string
};

passport.use(new JwtStrategy(opts, async (jwt_payload, done: (error: any, user?: IUser | false | null) => void) => {
    try {
        const user: IUser | null = await UserModel.findOne({ _id: jwt_payload._id }).select('-password');
        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    } catch (error) {
        return done(error, false);
    }
}));

