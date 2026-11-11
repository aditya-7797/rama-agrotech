import 'dotenv/config'
import bcrypt from 'bcryptjs'
import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({ email: { type: String, unique: true }, passwordHash: String, name: String }, { timestamps: true })
const User = mongoose.model('User', userSchema)

const [, , email, password, name = 'Store owner'] = process.argv
if (!email || !password) throw new Error('Usage: npm run seed:admin -- owner@example.com a-strong-password "Owner name"')
if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is required')

await mongoose.connect(process.env.MONGODB_URI)
await User.findOneAndUpdate({ email: email.toLowerCase() }, { email: email.toLowerCase(), passwordHash: await bcrypt.hash(password, 12), name }, { upsert: true, new: true, setDefaultsOnInsert: true })
console.log(`Admin account ready for ${email}`)
await mongoose.disconnect()
