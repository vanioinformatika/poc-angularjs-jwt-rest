'use strict';

var myApp = angular.module('myApp', ['ngSanitize', 'ui.bootstrap']);

//this is used to parse the profile
function url_base64_decode(str) {
    var output = str.replace('-', '+').replace('_', '/');
    switch (output.length % 4) {
        case 0:
            break;
        case 2:
            output += '==';
            break;
        case 3:
            output += '=';
            break;
        default:
            throw 'Illegal base64url string!';
    }
    return window.atob(output); //polifyll https://github.com/davidchambers/Base64.js
}

myApp.controller('UserCtrl', function($rootScope, $scope, $http, $window, $sce) {
    
    // user object set in $rootScope
    $rootScope.user = {username: 'john.doe', password: 'foobar'};
    $rootScope.isAuthenticated = false;
    $rootScope.welcome = '';
    $rootScope.message = '';
    $rootScope.error = '';

    $scope.submit = function() {
        $http
                .post('/authenticate', $rootScope.user)
                .success(function(data, status, headers, config) {
                    $window.sessionStorage.token = data.token;
                    $rootScope.isAuthenticated = true;
                    var encodedProfile = data.token.split('.')[1];
                    var profile = JSON.parse(url_base64_decode(encodedProfile));
                    $rootScope.welcome = profile.first_name + ' ' + profile.last_name;
                    $rootScope.error = '';
                    $rootScope.message = '';
                })
                .error(function(data, status, headers, config) {
                    // Erase the token if the user fails to log in
                    delete $window.sessionStorage.token;
                    // view depends on isAuthenticated value, see index.html
                    $rootScope.isAuthenticated = false;

                    // Handle login errors here
                    $rootScope.error = 'Login failed!';
                    $rootScope.welcome = '';
                    $rootScope.message = '';
                });
    };

    $scope.logout = function() {
        $rootScope.welcome = '';
        $rootScope.message = '';
        $rootScope.error = '';
        $rootScope.isAuthenticated = false;
        delete $window.sessionStorage.token;
    };

    $scope.callRestricted = function() {
        $http({url: '/api/restricted', method: 'GET'})
                .success(function(data, status, headers, config) {
                    $rootScope.message = $rootScope.message + '<br>' + JSON.stringify(data);
                })
                .error(function(data, status, headers, config) {
                    console.log('error: ' + status);
                    if (status !== 401) {
                        alert(data);
                    }
                });
    };

    $scope.getMessage = function() {
        return $sce.trustAsHtml($rootScope.message);
    };

});

myApp.factory('authInterceptor', function($rootScope, $q, $window) {
    return {
        request: function(config) {
            config.headers = config.headers || {};
            if ($window.sessionStorage.token) {
                config.headers['Authorization'] = 'Bearer ' + $window.sessionStorage.token;
            }
            return config;
        },
        response: function(response) {
            // respone has Authorization HTTP header, and token will be saved into the sessionStorage
            var tokenWithBearer = response.headers('Authorization');
            if (tokenWithBearer !== null) {
                var parts = tokenWithBearer.split(' ');
                var token = parts[1];
                $window.sessionStorage.token = token;
            }
            return response;
        },
        responseError: function(rejection) {
            if (rejection.status === 401) {
                // handle the case where the user is not authenticated
                delete $window.sessionStorage.token;
                $rootScope.isAuthenticated = false;
            }
            return $q.reject(rejection);
        }
    };
});

myApp.config(function($httpProvider) {
    $httpProvider.interceptors.push('authInterceptor');
});

