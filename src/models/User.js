import mongoose from 'mongoose'
const UserSchema=mongoose.Schema({
    username:{type:String,require:true,unique:true},
    password:{type:String,require:true},
    devices:{
        type:[{
            credentialID:{type:String},
            counter:{type:Number},
            PublicKey:{type:String}
        }],default:[]
    },
    challenge:{type:String}
})
export default mongoose.model("User",UserSchema)