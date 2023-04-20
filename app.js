import express from 'express'
import cors from 'cors'
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import bcrypt from 'bcrypt'
import uniqid from 'uniqid'
import { setCurrentChallenge, pushUser, queryUser, updateUser, queryChallenge, uint8Tobase64url, postAuthentication } from './helper.js';

const rpName = 'SimpleWebAuthn Example';

const rpID = 'localhost';

const origin = `http://${rpID}:5173`;

const app = express()

app.use(cors())
app.use(express.json())

app.get('/', async (req, res) => {
    res.status(200).json({ message: "hello world" })
})

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body
        const salt = await bcrypt.genSalt(15)
        const hashPassword = await bcrypt.hash(password, salt)
        pushUser({
            id: uniqid(),
            username,
            password: hashPassword,
            devices: []
        })
        res.status(200).json({ message: "your account has been created" })
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ error: "Internal Server Error" })
    }
})
app.post('/generate-register-option', async (req, res) => {
    try {
        const { username } = req.body
        const users = queryUser()
        const user = users.find(user => user.username === username)
        const authenticators = user.devices
        const options = generateRegistrationOptions({
            rpName,
            rpID,
            userID: user.id,
            userName: username,
            attestationType: "none",
            excludeCredentials: authenticators.map(authenticator => ({
                id: authenticator.credentialdID,
                type: "public-key",
                transports: authenticator.transports
            }))
        })
        setCurrentChallenge(user.id, options.challenge)
        res.status(200).json(options)
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ error: "Internal Server Error" })
    }
})

app.post('/Verify-Registration', async (req, res) => {
    const { registrationBody: body, username } = req.body
    const user = queryUser().find(user => user.username === username)
    const { challenge: expectedChallenge } = queryChallenge(user.id)
    let verification
    try {
        verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ error: "Internal Server Error" })
    }
    const { verified, registrationInfo } = verification
    res.status(200).json({ verified })
    console.log(registrationInfo)
    const { credentialID, counter, credentialPublicKey, transports } = registrationInfo
    updateUser(user.id, {
        credentialID,
        counter,
        credentialPublicKey,
    })
})

app.post('/generate-authenticate-option', async (req, res) => {
    try {
        const { username } = req.body
        const users = queryUser()
        const user = users.find(user => user.username === username)
        const authenticators = user.devices
        const allowCredentials = []
        authenticators.forEach(authenticator => {
            allowCredentials.push({
                id: Object.values(authenticator.credentialID),
                type: "public-key",
                transports: authenticator.transports
            })
        })
        const options = generateAuthenticationOptions({
            allowCredentials,
            rpID,
            userVerification: "preferred"
        })
        setCurrentChallenge(user.id, options.challenge)
        res.status(200).json(options)
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ error: "Internal Server Error" })
    }
})
app.post('/Verify-Authentication', async (req, res) => {
    try {
        const { authenticationBody: body, username } = req.body
        const users = queryUser()
        const user = users.find(user => user.username === username)
        const { challenge: expectedChallenge } = queryChallenge(user.id)
        // return console.log(uint8Tobase64url(Object.values(user.devices[0].credentialID)))
        const authenticator = user.devices.find(device => uint8Tobase64url(Object.values(device.credentialID)) === body.id
        )
        if (!authenticator) {
            return res.status(400).json({ status: "failed", message: "No authenticator found" })
        }
        console.log(body)
        let verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator:{
                ...authenticator,
                credentialID:Object.values(authenticator.credentialID),
                credentialPublicKey:new Uint8Array(Object.values(authenticator.credentialPublicKey))
            }
        })
        const { verified, authenticationInfo } = verification
        console.log(verified)
        const { newCounter } = authenticationInfo
        res.status(200).json({ verified })
        postAuthentication(user.id, authenticator.credentialID, newCounter)
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ error: "Internal Server Error" })
    }
})

app.listen(3000, () => {
    console.log("server is running on http://localhost:3000")
})