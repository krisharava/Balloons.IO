
/*
 * Module dependencies
 */

var passport = require('passport')
  , TwitterStrategy = require('passport-twitter').Strategy
  , config = require('./config.json');

/*
 * Auth strategy
 */

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new TwitterStrategy({
    consumerKey: config.auth.twitter.consumerkey,
    consumerSecret: config.auth.twitter.consumersecret,
    callbackURL: config.auth.twitter.callback
  },
  function(token, tokenSecret, profile, done) {
    return done(null, profile);
  }
));

//JAVI
LocalStrategy = require('passport-local').Strategy;

passport.use(new LocalStrategy(
  function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { message: 'Unknown user' });
      }
      if (!user.validPassword(password)) {
        return done(null, false, { message: 'Invalid password' });
      }
      return done(null, user);
    });
  }
));
