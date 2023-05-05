import express from 'express'
import { config } from 'dotenv'
import Token from '../models/Token.js'
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';
import User from '../models/User.js'
import JWT from 'jsonwebtoken'
import { base64urlToUint8, uint8Tobase64url, OTPGenerator } from '../helpers/helper.js'
import sendMail from '../helpers/gmail.js'


config()
export const route = express.Router()
const JWT_SECRET = process.env.SINGING_SECRET

const rpName = process.env.RP_NAME
const rpID = process.env.RP_ID
const origin = `https://${rpID}`

route.post('/', async (req, res) => {
    try {
        const { Email, Phone } = req.body
        const user = await User.create({
            Email,
            Phone
        })
        const { secret, token } = OTPGenerator()
        await Token.findOneAndUpdate({ user: user.id }, {
            secret,
            user: user.id,
            created_At: Date.now()
        }, { upsert: true })

        await sendMail({
            to: Email,
            from: "webAuthn",
            subject: 'OTP for verification',
            body: `<p style="font-size:16px">Your OTP is <span style="font-weight:bold;font-size:19px">${token}</span>, hurry up! it will expire in 60 seconds</p>`
        })

        return res.status(200).json({ success: true, message: "your account has been created" })
    }
    catch (error) {
        console.log(error)
        if (error.keyPattern && error.keyPattern.Email === 1) {
            res.status(403).json({ error: "The Email already exists" })
            return
        }
        res.status(500).json({ error: "Internal Server Error" })
    }
})
route.post('/generate-register-option', async (req, res) => {
    const { Email } = req.body
    try {
        const user = await User.findOne({ Email })
        console.log(user)
        const authenticators = user.devices
        const options = generateRegistrationOptions({
            rpName,
            rpID,
            userID: user.id,
            userName: user.Email,
            attestationType: "none",
            excludeCredentials: authenticators.map(authenticator => ({
                id: base64urlToUint8(authenticator.credentialID),
                type: "public-key",
                transports: authenticator.transports
            }))
        })
        res.status(200).json(options)
        await User.findByIdAndUpdate(user.id, { $set: { challenge: options.challenge } })
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ error: "Internal Server Error" })
    }
})

route.post('/Verify-Registration', async (req, res) => {
    const { registrationBody: body, Email } = req.body
    const user = await User.findOne({ Email })
    const { challenge: expectedChallenge } = user
    let verification
    try {
        verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID
        })
        const { verified, registrationInfo } = verification
        if (!verified) {
            return res.status(401).json({ error: "Invalid credentials" })
        }
        const { credentialID, counter, credentialPublicKey } = registrationInfo
        const data = {
            user: {
                id: user.id
            }
        }
        const sessionToken = JWT.sign(data, JWT_SECRET)
        res.status(200).json({ verified, sessionToken })
        await User.findByIdAndUpdate(user.id, {
            $set: { challenge: "" },
            $push: {
                devices: {
                    credentialID: uint8Tobase64url(credentialID),
                    counter,
                    PublicKey: uint8Tobase64url(credentialPublicKey)
                }
            }
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ error: "Internal Server Error" })
    }
})
