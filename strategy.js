
/*
 * Module dependencies
 */

var fs = require('fs');

var passport = require('passport')
  , TwitterStrategy = require('passport-twitter').Strategy
  , FacebookStrategy = require('passport-facebook').Strategy
  , GoogleStrategy = require('passport-google-oauth').OAuth2Strategy
  , LocalStrategy = require('passport-local').Strategy;

/**
 * Expose Authentication Strategy
 */

module.exports = Strategy;

/*
 * Defines Passport authentication
 * strategies from application configs
 *
 * @param {Express} app `Express` instance.
 * @api public
 */

function Strategy (app) {
  var config = app.get('config');
  var userfile = __dirname + '/users.json';
  var users;

  fs.readFile(userfile, 'utf8', function (err, data) {
    if (err) {
      console.log('Error: ' + err);
      return;
    }
    users = JSON.parse(data);
  });

  function findByUsername(username, fn) {
    var i = 0;
    for (i, len = users.length; i < len; i++) {
      var user = users[i];
      if (user.username === username) {
        return fn(null, user);
      }
    }
    return fn(null, null);
  }

  passport.serializeUser(function(user, done) {
    done(null, user);
  });

  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

  if(config.auth.twitter.consumerkey.length) {
    passport.use(new TwitterStrategy({
        consumerKey: config.auth.twitter.consumerkey,
        consumerSecret: config.auth.twitter.consumersecret,
        callbackURL: config.auth.twitter.callback
      },
      function(token, tokenSecret, profile, done) {
        return done(null, profile);
      }
    ));
  }

  if(config.auth.facebook.clientid.length) {
    passport.use(new FacebookStrategy({
        clientID: config.auth.facebook.clientid,
        clientSecret: config.auth.facebook.clientsecret,
        callbackURL: config.auth.facebook.callback
      },
      function(accessToken, refreshToken, profile, done) {
        return done(null, profile);
      }
    ));
  }

  if(config.auth.google.clientid.length) {
	  passport.use(new GoogleStrategy({
	    clientID: config.auth.google.clientid,
		clientSecret: config.auth.google.clientsecret,
		callbackURL: config.auth.google.callback
	  },
	  function(accessToken, refreshToken, profile, done) {
		 process.nextTick(function () {
			return done(null, profile);
		 });
	  }
	));
  }
  
  passport.use(new LocalStrategy(function(username, password, done) {
    findByUsername(username, function(err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false, { message: 'Unknown user ' + username }); }
      if (user.password != password) { return done(null, false, { message: 'Invalid password' }); }
      return done(null, user);
    });
  }));
}

