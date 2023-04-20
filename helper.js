import fs from 'fs'
import uniqid from 'uniqid'

export function pushUser(data){
    const users= JSON.parse(fs.readFileSync('user.json'))
    users.push(data)
    fs.writeFileSync('user.json',JSON.stringify(users))
}
export function updateUser(id,data){
    const users= JSON.parse(fs.readFileSync('user.json'))
    const Index=users.findIndex(user=>user.id===id)
    const devices=users[Index].devices
    users[Index].devices=[...devices,data]
    fs.writeFileSync('user.json',JSON.stringify(users))
    const challenges=JSON.parse(fs.readFileSync('challenge.json'))
    const updatedChallenges=challenges.filter(challenge=>challenge.user!==id)
    fs.writeFileSync(JSON.stringify(updatedChallenges))
}
export function queryUser(){
    return JSON.parse(fs.readFileSync('user.json'))
}
export function queryChallenge(id){
    return JSON.parse(fs.readFileSync('challenge.json')).find(current=>current.user===id)
}
export function setCurrentChallenge(id,challenge){
    const data=JSON.parse(fs.readFileSync('challenge.json'))
    data.push({
        id:uniqid(),
        user:id,
        challenge
    })
    fs.writeFileSync('challenge.json',JSON.stringify(data))
}
export function postAuthentication(userID,credentialID,counter){
    const users=JSON.parse(fs.readFileSync('user.json'))
    const user=users.find(user=>user.id===userID)
    const authenticator=user.devices.find(device=>uint8Tobase64url(Object.values(device.credentialID))===uint8Tobase64url(Object.values(credentialID)))
    authenticator.counter=counter
    fs.writeFileSync('user.json',JSON.stringify(users))
    let datas=JSON.parse(fs.readFileSync('challenge.json'))
    datas=datas.filter(data=>data.user!==userID)
    fs.writeFileSync('challenge.json',JSON.stringify(datas))
}
export function uint8Tobase64url(uintArray){
    return new Buffer.from(uintArray).toString('base64url')
}