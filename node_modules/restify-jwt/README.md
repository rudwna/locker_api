# restify-jwt

[![Build Status](https://travis-ci.org/amrav/restify-jwt.svg)](https://travis-ci.org/amrav/restify-jwt)

[Restify](http://mcavage.me/node-restify/) middleware that validates JsonWebTokens and sets `req.user`.

This module lets you authenticate HTTP requests using JWT tokens in your restify applications.

## Install

    $ npm install restify-jwt

## Usage

The JWT authentication middleware authenticates callers using a JWT.
If the token is valid, `req.user` will be set with the JSON object decoded
to be used by later middleware for authorization and access control.

For example,

```javascript
var jwt = require('restify-jwt');

app.get('/protected',
  jwt({secret: 'shhhhhhared-secret'}),
  function(req, res) {
    if (!req.user.admin) return res.send(401);
    res.send(200);
  });
```

You can specify audience and/or issuer as well:

```javascript
jwt({ secret: 'shhhhhhared-secret',
  audience: 'http://myapi/protected',
  issuer: 'http://issuer' })
```

> If the JWT has an expiration (`exp`), it will be checked.

Optionally you can make some paths unprotected as follows:

```javascript
app.use(jwt({ secret: 'shhhhhhared-secret'}).unless({path: ['/token']}));
```

This is especially useful when applying to multiple routes.

This module also support tokens signed with public/private key pairs. Instead of a secret, you can specify a Buffer with the public key

```javascript
var publicKey = fs.readFileSync('/pat/to/public.pub');
jwt({ secret: publicKey });
```

By default, the decoded token is attached to `req.user` but can be configured with the `userProperty` option.

```javascript
jwt({ secret: publicKey, userProperty: 'auth' });
```

You might want to use this module to identify registered users without preventing unregistered clients to access to some data, you
can do it using the option _credentialsRequired_:

    app.use(jwt({
      secret: 'hello world !',
      credentialsRequired: false
    }));

## Tests

    $ npm install
    $ npm test

## Credits

Forked from [auth0/express-jwt](https://github.com/auth0/express-jwt). The major difference is that restify-jwt tries to use built in restify errors wherever possible.

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
