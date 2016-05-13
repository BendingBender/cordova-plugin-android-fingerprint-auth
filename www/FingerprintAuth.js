function FingerprintAuth() {
}

FingerprintAuth.prototype.encrypt = function (params, successCallback, errorCallback) {
    cordova.exec(
            successCallback,
            errorCallback,
            "FingerprintAuth", // Java Class
            "encrypt", // action
            [// Array of arguments to pass to the Java class
                {
                    appId: params.appId,
                    plain: params.plain,
                    description: params.description
                }
            ]
            );
}

FingerprintAuth.prototype.decrypt = function (params, successCallback, errorCallback) {
    cordova.exec(
            successCallback,
            errorCallback,
            "FingerprintAuth", // Java Class
            "decrypt", // action
            [// Array of arguments to pass to the Java class
                {
                    appId: params.appId,
                    encrypted: params.encrypted,
                    initializationVector: params.initializationVector,
                    description: params.description
                }
            ]
            );
}

FingerprintAuth.prototype.isAvailable = function (successCallback, errorCallback) {
    cordova.exec(
            successCallback,
            errorCallback,
            "FingerprintAuth", // Java Class
            "availability", // action
            [{}]
            );
}

FingerprintAuth = new FingerprintAuth();
module.exports = FingerprintAuth;