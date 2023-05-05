import google from '@googleapis/gmail'
import Credentials from '../OAUTH2_credentials.json' assert {type:"json"}

const {client_id,client_secret,redirect_uris}=Credentials.web
const OAUTH2Client=new google.auth.OAuth2(client_id,client_secret,redirect_uris[0])
const url=OAUTH2Client.generateAuthUrl({
    access_type:"offline",
    prompt:"consent",
    scope:['https://www.googleapis.com/auth/gmail.send']
})
console.log(url)