var jwt = require('jsonwebtoken');
var unless = require('express-unless');
var restify = require('restify');

module.exports = function(options) {
  if (!options || !options.secret) throw new Error('secret should be set');

  var _userProperty = options.userProperty || 'user';
  var credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;

  var middleware = function(req, res, next) {
    var token;

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
      var hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
                                    .split(',').map(function (header) {
                                      return header.trim();
                                    }).indexOf('authorization');

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (options.getToken && typeof options.getToken === 'function') {
      try {
        token = options.getToken(req);
      } catch (e) {
        return next(e);
      }
    } else if (req.headers && req.headers.authorization) {
      var parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        var scheme = parts[0];
        var credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        return next(new restify.InvalidCredentialsError('Format is Authorization: Bearer [token]'));
      }
    }

    if (!token) {
      if (credentialsRequired) {
        return next(new restify.InvalidCredentialsError('No authorization token was found'));
      } else {
        return next();
      }
    }

    jwt.verify(token, options.secret, options, function(err, decoded) {
      if (err && credentialsRequired) return next(new restify.errors.InvalidCredentialsError(err));

      req[_userProperty] = decoded;
      next();
    });
  };

  middleware.unless = unless;

  return middleware;
};
