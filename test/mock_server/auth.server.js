'use strict';

/* 
 * This application is a proof-of-concept (PoC) of using AngularJS with secured REST service
 * with session handling and authorization.
 * It is using JTW - JSON Web Token.
 * 
 * Based on https://github.com/auth0/angular-token-auth
 * 
 * JWT more information:
 * https://auth0.com/blog/2014/01/07/angularjs-authentication-with-cookies-vs-token/
 * http://mariuszprzydatek.com/2013/07/12/jwt-json-web-tokens/
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20
 * for java backend: http://mvnrepository.com/artifact/org.springframework.security/spring-security-jwt
 * 
 * IT IS A PROOF-OF-CONCEPT! DO NOT USE IN PRODUCTION.
 */
var express = require('express');
var colors = require('colors');
var jwt = require('jsonwebtoken'); // https://github.com/auth0/node-jsonwebtoken
var expressJwt = require('express-jwt'); // https://github.com/auth0/express-jwt

var app = express();

// your secret
var secret = 'this is the secret secret secret 12356';
// working dir for static files
var workingDir = '/home/patoi/NetBeansProjects/client-vanio-template';
// JWT options: https://github.com/auth0/node-jsonwebtoken
var jwtOptions = {algorithm: 'HS256', expiresInMinutes: 1};

// We are going to protect /api routes with JWT
app.use('/api', expressJwt({secret: secret}));

app.use(express.json());
app.use(express.urlencoded());

app.use('/', express.static(workingDir));

console.log(workingDir);

app.use(function(err, req, res, next) {
    if (err.constructor.name === 'UnauthorizedError') {
        console.log(err);
        res.send(401, 'Unauthorized');
    }
});

app.post('/authenticate', function(req, res) {
    //TODO validate req.body.username and req.body.password
    //if is invalid, return 401
    if (!(req.body.username === 'john.doe' && req.body.password === 'foobar')) {
        res.send(401, 'Wrong user or password');
        return;
    }

    // user object (session data) handled by express-jwt
    var user = {
        session: {
            counter: 0
        },
        first_name: 'John',
        last_name: 'Doe',
        email: 'john@doe.com',
        roles: [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000],
        id: 123
    };

    // We are sending the user inside the token
    var token = jwt.sign(user, secret, jwtOptions);

    // CORS: http://stackoverflow.com/questions/20048699/http-response-interceptors-headers
    // 
    // It is working in FF and Chrome without it.
    //res.header('Access-Control-Expose-Headers', 'Authorization')

    // response with token in response but not in HTTP header
    res.json({token: token});
});

app.get('/api/restricted', function(req, res) {
    console.log('user ' + req.user.email + ' is calling /api/restricted with roles: ' + req.user.roles);
    // TODO check roles

    // CORS: http://stackoverflow.com/questions/20048699/http-response-interceptors-headers
    // 
    // It is working in FF and Chrome without it.
    //res.header('Access-Control-Expose-Headers', 'Authorization')

    // get token from header
    // HTTP Header format: "Authorization: Bearer this_is_the_token"
    var token = '';
    if (req.headers && req.headers.authorization) {
        var parts = req.headers.authorization.split(' ');
        if (parts.length === 2) {
            var scheme = parts[0]
                    , credentials = parts[1];

            if (/^Bearer$/i.test(scheme)) {
                token = credentials;
            }
        } else {
            return new UnauthorizedError('credentials_bad_format', {message: 'Format is Authorization: Bearer [token]'});
        }
    } else {
        return new UnauthorizedError('credentials_required', {message: 'No Authorization header was found'});
    }

    // verify token: send by client in Authorization HTTP header
    // 'session timeout' handled by express-jwt (exp value) and throws 401
    jwt.verify(token, secret, jwtOptions, function(err, decoded) {
        if (err)
            return new UnauthorizedError('invalid_token', err);

        req.user = decoded;
        console.log(req.user);
    });

    // update sample data in the session ...
    req.user.session.counter = req.user.session.counter + 10;

    // ... and create new token ...
    var newToken = jwt.sign(req.user, secret, jwtOptions);

    // ... and update in the response HTTP header
    res.header('Authorization', 'Bearer ' + newToken)
    res.json(req.user);
});

app.listen(8080, function() {
    console.log('listening on http://localhost:8080');
});

