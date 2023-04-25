import express from 'express'
import { config } from 'dotenv'
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';
import bcrypt from 'bcrypt'
import User from '../models/User.js'
import JWT from 'jsonwebtoken'
import { uint8Tobase64url } from '../helpers/helper.js'
import { authenticator } from '../middleware/authenticator.js';

config()
export const route = express.Router()
const JWT_SECRET = process.env.SINGING_SECRET

const rpName = process.env.RP_NAME
const rpID = process.env.RP_ID
const origin = `https://${rpID}${process.env.RP_SUBDOMAIN}`

route.post('/', async (req, res) => {
    try {
        const { username, password } = req.body
        const salt = await bcrypt.genSalt(15)
        const hashPassword = await bcrypt.hash(password, salt)
       await User.create({
            username,
            password: hashPassword
        })
        return res.status(200).json({ success: true, message: "your account has been created" })
    }
    catch (error) {
        console.log(error)
        if (error.keyPattern && error.keyPattern.username === 1) {
            res.status(403).json({ error: "The username already exists" })
            return
        }
        res.status(500).json({ error: "Internal Server Error" })
    }
})
route.post('/generate-register-option', async (req, res) => {
    const {username}= req.body
    try {
        const user = await User.findOne({username})
        const authenticators = user.devices
        const options = generateRegistrationOptions({
            rpName,
            rpID,
            userID: user.id,
            userName: user.username,
            attestationType: "none",
            excludeCredentials: authenticators.map(authenticator => ({
                id: authenticator.credentialID,
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
    const { registrationBody: body,username } = req.body
    const user = await User.findOne({username})
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
                id:user.id
            }
        }
        const sessionToken = JWT.sign(data, JWT_SECRET)
        res.status(200).json({ verified,sessionToken })
        await User.findByIdAndUpdate(user.id, {$set:{challenge:""},
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