import google from '@googleapis/gmail'
import fs from 'fs'
import Credentails from '../OAUTH2_credentials.json' assert {type: "json"}

const code = '4/0AbUR2VPmZr8m15rf_QBvfdI0DAk6PJjxOEqkw9GbqsfH6jy1SNr3kRc98muxC6hm4fgSQw'
const { client_id, client_secret, redirect_uris } = Credentails.web
const OAUTH2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0])
OAUTH2Client.getToken(code).then(({ tokens }) => {
    fs.writeFileSync('token.json', JSON.stringify(tokens))
    console.log('access token and refresh token stored in token.json')
})