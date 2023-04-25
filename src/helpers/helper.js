export function uint8Tobase64url(uintArray){
    return new Buffer.from(uintArray).toString('base64url')
}
export function base64urlToUint8(base64String){
    return new Uint8Array(Buffer.from(base64String,'base64url'))
}
