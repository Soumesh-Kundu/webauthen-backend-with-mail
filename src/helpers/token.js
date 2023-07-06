import google from '@googleapis/gmail'
import fs from 'fs'
import credentials from '../../credentials/Credential.json' assert {type:'json'};

const code ='4/0AZEOvhVDD-Lmd-HyUmTYEV-P6OVq6IikTYJB1MJ89x1DS1Il-go9yCvszj5TtdIb-KfQFQ'

const { client_secret, client_id, redirect_uris } = credentials.web;
const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);

oAuth2Client.getToken(code).then(({ tokens }) => {
  console.log(tokens)
  fs.writeFileSync('credentials/token.json', JSON.stringify(tokens));
  console.log('Access token and refresh token stored to token.json');
});