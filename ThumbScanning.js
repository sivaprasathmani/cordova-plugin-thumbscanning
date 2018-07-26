var exec = require('cordova/exec');

exports.checkFingerPrint = function (arg0, success, error) {
    exec(success, error, 'ThumbScanning', 'checkFingerPrint', [arg0]);
};

exports.fingerPrintAuth = function (arg0, success, error) {
    exec(success, error, 'ThumbScanning', 'fingerPrintAuth', [arg0]);
};

