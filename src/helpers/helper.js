import speakeasy from 'speakeasy'


export function uint8Tobase64url(uintArray){
    return new Buffer.from(uintArray).toString('base64url')
}
export function base64urlToUint8(base64String){
    return new Uint8Array(Buffer.from(base64String,'base64url'))
}

export function OTPGenerator() {
    let secret = speakeasy.generateSecret().base32
    let token = speakeasy.totp({
        secret,
        encoding: 'base32',
        algorithm: 'sha512',
        window: 2
    })
    return { secret, token }
}

export function VerifyOTP(secret, token) {
    let verifed = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        algorithm: 'sha512',
        token,
        window: 2
    })
    return verifed
}