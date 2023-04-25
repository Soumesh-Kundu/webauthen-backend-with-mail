import express from 'express'
import {
    generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import User from '../models/User.js';
import JWT from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import {config} from 'dotenv'
import { authenticator } from '../middleware/authenticator.js';
import { base64urlToUint8, uint8Tobase64url } from '../helpers/helper.js';
export const route=express.Router()

config()
const JWT_SECRET=process.env.SINGING_SECRET
const rpName=process.env.RP_NAME
const rpID=process.env.RP_ID
const origin=`http://${rpID}`

route.post('/',async(req,res)=>{
    const {username,password}=req.body
    try {
        const {password:hashPassword}=await User.findOne({username})
        const verified=await bcrypt.compare(password,hashPassword)
        if(!verified){
            return res.status(400).json({success:"false",message:"Incorrect Credentials"})
        }
        res.status(200).json({success:true,message:"You are authenticated"})
    } catch (error) {
        console.log(error)
    }
})

route.post('/generate-authenticate-option',async (req, res) => {
    const {username}=req.body
    try {
        const user = await User.findOne({username})
        const authenticators = user.devices
        const allowCredentials = []
        authenticators.forEach(authenticator => {
            allowCredentials.push({
                id: base64urlToUint8(authenticator.credentialID),
                type: "public-key",
                transports: authenticator.transports
            })
        })
        const options = generateAuthenticationOptions({
            allowCredentials,
            rpID,
            userVerification: "preferred"
        })
        res.status(200).json(options)
        await User.findByIdAndUpdate(user.id,{$set:{challenge:options.challenge}})
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ error: "Internal Server Error" })
    }
})
route.post('/Verify-Authentication', async (req, res) => {
    const { authenticationBody: body,username } = req.body 
    try {
        const user = await User.findOne({username})
        const {challenge:expectedChallenge} = user
        const authenticator = user.devices.find(device => device.credentialID === body.id)
        if (!authenticator) {
            return res.status(401).json({ status: "failed", message: "No authenticator found" })
        }
        let verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator:{
                ...authenticator,
                credentialID:base64urlToUint8(authenticator.credentialID),
                credentialPublicKey:base64urlToUint8(authenticator.PublicKey)
            }
        })
        const { verified, authenticationInfo } = verification
        if(!verified){
            return res.status(401).json({verified,error:"Unauthorize access"})
        }
        const data={
            user:{
                id:user.id
            }
        }
        const sessionToken=JWT.sign(data,JWT_SECRET)
        const { newCounter } = authenticationInfo
        res.status(200).json({ verified,sessionToken })
        await User.findByIdAndUpdate(user.id,{$set:{challenge:""}})
        await User.findOneAndUpdate({_id:user.id,"devices._id":authenticator.id},{$set:{"devices.$.counter":newCounter}})
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ error: "Internal Server Error" })
    }
})