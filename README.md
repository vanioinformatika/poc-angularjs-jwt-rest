# README

This application is a proof-of-concept (PoC) of using AngularJS with secured REST service with session handling and authorization.
It is using JTW - JSON Web Token.

Based on https://github.com/auth0/angular-token-auth

JWT more information:

https://auth0.com/blog/2014/01/07/angularjs-authentication-with-cookies-vs-token/

http://mariuszprzydatek.com/2013/07/12/jwt-json-web-tokens/

http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20

for java backend: http://mvnrepository.com/artifact/org.springframework.security/spring-security-jwt

__IT IS A PROOF-OF-CONCEPT! DO NOT USE IN PRODUCTION.__

## Install and run

Set correct working dir in app.server.js: workingDir

    bower install
    npm install
    cd test/mock_server
    nodejs app.server.js

## Tips

If you have __Error: listen EADDRINUSE__ then change the port number in app.listen

