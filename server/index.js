import 'dotenv/config'
import bcrypt from 'bcryptjs'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import express from 'express'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'

const app = express()
const port = process.env.PORT || 4000
const clientOrigin = process.env.CLIENT_ORIGIN || 'http://localhost:5173'
let databaseStatus = 'not-configured'

app.use(cors({ origin: clientOrigin, credentials: true }))
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())

const money = (value) => Math.round(Number(value) * 100) / 100
const idSchema = { type: String, unique: true, index: true }

const userSchema = new mongoose.Schema({ email: { type: String, required: true, unique: true, lowercase: true }, passwordHash: { type: String, required: true }, name: { type: String, required: true } }, { timestamps: true })
const productSchema = new mongoose.Schema({ productId: idSchema, name: { type: String, required: true, trim: true }, sku: { type: String, required: true, unique: true, index: true, uppercase: true }, description: String, sellingPrice: { type: Number, min: 0, default: 0 }, weightedAverageCost: { type: Number, min: 0, default: 0 }, stockQuantity: { type: Number, min: 0, default: 0 }, minimumStock: { type: Number, min: 0, default: 0 }, isActive: { type: Boolean, default: true } }, { timestamps: true })
const stockMovementSchema = new mongoose.Schema({ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true, index: true }, movementType: { type: String, required: true }, quantityChange: { type: Number, required: true }, quantityBefore: { type: Number, required: true }, quantityAfter: { type: Number, required: true }, referenceType: String, referenceId: mongoose.Schema.Types.ObjectId, reason: String, notes: String, createdBy: mongoose.Schema.Types.ObjectId }, { timestamps: true })
const purchaseSchema = new mongoose.Schema({ purchaseId: idSchema, purchaseDate: { type: Date, default: Date.now, index: true }, supplier: { type: String, required: true }, items: [{ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, productNameSnapshot: String, skuSnapshot: String, quantity: { type: Number, min: 1 }, unitCost: { type: Number, min: 0 }, lineTotal: { type: Number, min: 0 } }], totalAmount: { type: Number, min: 0 }, notes: String, status: { type: String, enum: ['COMPLETED', 'CANCELLED'], default: 'COMPLETED' } }, { timestamps: true })
const saleSchema = new mongoose.Schema({ invoiceId: idSchema, saleDate: { type: Date, default: Date.now, index: true }, customerName: String, customerPhone: String, items: [{ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, productNameSnapshot: String, skuSnapshot: String, quantity: { type: Number, min: 1 }, sellingPrice: { type: Number, min: 0 }, costPriceSnapshot: { type: Number, min: 0 }, lineTotal: { type: Number, min: 0 } }], totalAmount: { type: Number, min: 0 }, amountPaid: { type: Number, min: 0, default: 0 }, balanceDue: { type: Number, min: 0, default: 0, index: true }, paymentStatus: { type: String, enum: ['PAID', 'PARTIAL', 'UDHARI'], required: true }, dueDate: Date, notes: String, status: { type: String, enum: ['COMPLETED', 'CANCELLED'], default: 'COMPLETED' } }, { timestamps: true })
const paymentSchema = new mongoose.Schema({ sale: { type: mongoose.Schema.Types.ObjectId, ref: 'Sale', required: true, index: true }, amount: { type: Number, required: true, min: 0.01 }, paymentDate: { type: Date, default: Date.now, index: true }, paymentMethod: { type: String, enum: ['CASH', 'UPI', 'CARD', 'BANK_TRANSFER', 'OTHER'], required: true }, notes: String, status: { type: String, enum: ['COMPLETED', 'REVERSED'], default: 'COMPLETED' } }, { timestamps: true })
const expenseSchema = new mongoose.Schema({ expenseId: idSchema, expenseDate: { type: Date, required: true, index: true }, category: { type: String, required: true }, description: String, amount: { type: Number, required: true, min: 0.01 }, paymentMethod: String, notes: String }, { timestamps: true })

const User = mongoose.model('User', userSchema)
const Product = mongoose.model('Product', productSchema)
const StockMovement = mongoose.model('StockMovement', stockMovementSchema)
const Sale = mongoose.model('Sale', saleSchema)
const Payment = mongoose.model('Payment', paymentSchema)
const Purchase = mongoose.model('Purchase', purchaseSchema)
mongoose.model('Expense', expenseSchema)

const auth = (req, res, next) => {
  try {
    const token = req.cookies.inventory_token
    if (!token) return res.status(401).json({ message: 'Authentication required' })
    req.user = jwt.verify(token, process.env.JWT_SECRET)
    next()
  } catch { res.status(401).json({ message: 'Invalid or expired session' }) }
}
const nextId = async (Model, field, prefix) => { const latest = await Model.findOne({ [field]: new RegExp(`^${prefix}-`) }).sort({ createdAt: -1 }).select(field).lean(); const number = latest ? Number(latest[field].split('-').at(-1)) + 1 : 1001; return `${prefix}-${number}` }
const requireCreditDetails = (totalAmount, amountPaid, customerName, dueDate) => { const balanceDue = money(totalAmount - amountPaid); if (balanceDue > 0 && (!customerName || !dueDate)) throw new Error('Customer name and due date are required for an outstanding balance'); return balanceDue }

app.get('/api/health', (req, res) => {
  const ok = databaseStatus === 'connected'
  res.status(ok ? 200 : 503).json({ ok, service: 'retail-inventory-api', database: databaseStatus })
})
app.get('/api/auth/me', auth, async (req, res) => { const user = await User.findById(req.user.id).select('name email'); if (!user) return res.status(401).json({ message: 'Authentication required' }); res.json({ user }) })
app.post('/api/auth/login', async (req, res) => { const user = await User.findOne({ email: req.body.email?.toLowerCase() }); if (!user || !(await bcrypt.compare(req.body.password || '', user.passwordHash))) return res.status(401).json({ message: 'Invalid email or password' }); const token = jwt.sign({ id: user.id, name: user.name }, process.env.JWT_SECRET, { expiresIn: '8h' }); res.cookie('inventory_token', token, { httpOnly: true, sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }); res.json({ user: { name: user.name, email: user.email } }) })
app.post('/api/auth/logout', (req, res) => { res.clearCookie('inventory_token'); res.status(204).end() })

app.get('/api/products', auth, async (req, res) => { const query = { isActive: true, ...(req.query.search ? { $or: [{ name: new RegExp(req.query.search, 'i') }, { sku: new RegExp(req.query.search, 'i') }, { productId: new RegExp(req.query.search, 'i') }] } : {}) }; res.json(await Product.find(query).sort({ name: 1 })) })
const productFields = (body) => {
  const name = body.name?.trim()
  const sku = body.sku?.trim()
  const sellingPrice = Number(body.sellingPrice)
  if (!name || !sku) throw new Error('Name and SKU are required')
  if (!Number.isFinite(sellingPrice) || sellingPrice < 0) throw new Error('Enter a valid selling price')
  return { name, sku, sellingPrice }
}
const desiredStock = (body) => {
  const raw = body.stock ?? body.stockQuantity ?? body.initialStock
  const stock = Number(raw)
  if (raw === undefined || raw === '' || !Number.isInteger(stock) || stock < 0) throw new Error('Stock must be a whole number of 0 or more')
  return stock
}
const applyStock = async ({ session, product, stock, userId, reason }) => {
  const delta = stock - product.stockQuantity
  if (!delta) return product
  return moveStock({ session, productId: product._id, delta, movementType: delta > 0 ? 'ADJUSTMENT_IN' : 'ADJUSTMENT_OUT', referenceType: 'ADJUSTMENT', referenceId: new mongoose.Types.ObjectId(), reason, userId })
}
const apiError = (res, error) => {
  if (error?.code === 11000) return res.status(409).json({ message: 'A product with that SKU already exists' })
  res.status(error.status || 400).json({ message: error.message })
}

app.post('/api/products', auth, async (req, res) => {
  try {
    const fields = productFields(req.body)
    const product = await Product.create({ ...fields, productId: await nextId(Product, 'productId', 'PRD'), minimumStock: 0, stockQuantity: 0 })
    res.status(201).json(product)
  } catch (error) { apiError(res, error) }
})
app.post('/api/products/with-stock', auth, async (req, res) => {
  const session = await mongoose.startSession()
  try {
    let product
    await session.withTransaction(async () => {
      const fields = productFields(req.body)
      const stock = desiredStock(req.body)
      product = await Product.findOne({ sku: fields.sku.toUpperCase() }).session(session)
      if (product) {
        Object.assign(product, fields, { isActive: true })
        await product.save({ session })
      } else {
        product = (await Product.create([{ ...fields, productId: await nextId(Product, 'productId', 'PRD'), minimumStock: 0, stockQuantity: 0 }], { session }))[0]
      }
      product = await applyStock({ session, product, stock, userId: req.user.id, reason: 'Stock set from product form' })
    })
    res.status(201).json(product)
  } catch (error) { apiError(res, error) } finally { await session.endSession() }
})
app.patch('/api/products/:id', auth, async (req, res) => {
  const session = await mongoose.startSession()
  try {
    let product
    await session.withTransaction(async () => {
      product = await Product.findById(req.params.id).session(session)
      if (!product) throw Object.assign(new Error('Product not found'), { status: 404 })
      Object.assign(product, productFields(req.body))
      await product.save({ session })
      product = await applyStock({ session, product, stock: desiredStock(req.body), userId: req.user.id, reason: 'Stock updated' })
    })
    res.json(product)
  } catch (error) { apiError(res, error) } finally { await session.endSession() }
})
app.delete('/api/products/:id', auth, async (req, res) => { const product = await Product.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true }); if (!product) return res.status(404).json({ message: 'Product not found' }); res.json({ message: 'Product deactivated' }) })

// All quantity changes use this service so a product update cannot bypass the audit trail.
const moveStock = async ({ session, productId, delta, movementType, referenceType, referenceId, reason, userId }) => { const product = await Product.findById(productId).session(session); if (!product) throw new Error('Product not found'); const before = product.stockQuantity; const after = before + delta; if (after < 0) throw new Error(`Insufficient stock for ${product.name}`); product.stockQuantity = after; await product.save({ session }); await StockMovement.create([{ product: product._id, movementType, quantityChange: delta, quantityBefore: before, quantityAfter: after, referenceType, referenceId, reason, createdBy: userId }], { session }); return product }
app.post('/api/inventory/adjustments', auth, async (req, res) => { const session = await mongoose.startSession(); try { let movement; await session.withTransaction(async () => { const delta = Number(req.body.quantity) * (req.body.direction === 'OUT' ? -1 : 1); const adjustmentId = new mongoose.Types.ObjectId(); movement = await moveStock({ session, productId: req.body.productId, delta, movementType: delta > 0 ? 'ADJUSTMENT_IN' : 'ADJUSTMENT_OUT', referenceType: 'ADJUSTMENT', referenceId: adjustmentId, reason: req.body.reason, userId: req.user.id }) }); res.status(201).json(movement) } catch (error) { res.status(400).json({ message: error.message }) } finally { await session.endSession() } })
app.get('/api/purchases', auth, async (req, res) => { res.json(await Purchase.find({ status: 'COMPLETED' }).populate('items.product').sort({ purchaseDate: -1 })) })
app.delete('/api/purchases/:id', auth, async (req, res) => { const session = await mongoose.startSession(); try { let purchase; await session.withTransaction(async () => { purchase = await Purchase.findOne({ _id: req.params.id, status: 'COMPLETED' }).session(session); if (!purchase) throw new Error('Purchase not found or already cancelled'); for (const item of purchase.items) { const product = await Product.findById(item.product).session(session); if (!product || product.stockQuantity < item.quantity) throw new Error(`Cannot cancel ${purchase.purchaseId}: current stock for ${item.productNameSnapshot} is lower than the purchased quantity`); await moveStock({ session, productId: item.product, delta: -item.quantity, movementType: 'REVERSAL', referenceType: 'PURCHASE', referenceId: purchase._id, reason: 'Purchase cancelled', userId: req.user.id }) } purchase.status = 'CANCELLED'; await purchase.save({ session }) }); res.json({ message: 'Purchase cancelled' }) } catch (error) { res.status(400).json({ message: error.message }) } finally { await session.endSession() } })
app.post('/api/purchases', auth, async (req, res) => { const session = await mongoose.startSession(); try { let purchase; await session.withTransaction(async () => { if (!req.body.supplier?.trim() || !Array.isArray(req.body.items) || req.body.items.length === 0) throw new Error('Supplier and at least one product are required'); const items = []; for (const input of req.body.items) { const product = await Product.findOne({ _id: input.product, isActive: true }).session(session); const quantity = Number(input.quantity); const unitCost = Number(input.unitCost); if (!product || !Number.isInteger(quantity) || quantity <= 0 || !Number.isFinite(unitCost) || unitCost < 0) throw new Error('Each purchase item must have a valid product, quantity, and cost'); items.push({ product: product._id, productNameSnapshot: product.name, skuSnapshot: product.sku, quantity, unitCost, lineTotal: money(quantity * unitCost) }) } purchase = (await Purchase.create([{ purchaseId: await nextId(Purchase, 'purchaseId', 'PUR'), purchaseDate: req.body.purchaseDate || new Date(), supplier: req.body.supplier.trim(), items, totalAmount: money(items.reduce((sum, item) => sum + item.lineTotal, 0)), notes: req.body.notes }], { session }))[0]; for (const item of items) { const product = await Product.findById(item.product).session(session); const oldValue = product.stockQuantity * product.weightedAverageCost; const newValue = item.quantity * item.unitCost; const newQuantity = product.stockQuantity + item.quantity; product.weightedAverageCost = money(newQuantity ? (oldValue + newValue) / newQuantity : item.unitCost); await product.save({ session }); await moveStock({ session, productId: item.product, delta: item.quantity, movementType: 'PURCHASE_IN', referenceType: 'PURCHASE', referenceId: purchase._id, reason: 'Supplier purchase', userId: req.user.id }) } }); res.status(201).json(purchase) } catch (error) { res.status(400).json({ message: error.message }) } finally { await session.endSession() } })
app.get('/api/sales', auth, async (req, res) => { res.json(await Sale.find({ status: 'COMPLETED' }).sort({ saleDate: -1 }).limit(100)) })
app.delete('/api/sales/:id', auth, async (req, res) => { const session = await mongoose.startSession(); try { let sale; await session.withTransaction(async () => { sale = await Sale.findOne({ _id: req.params.id, status: 'COMPLETED' }).session(session); if (!sale) throw new Error('Sale not found or already cancelled'); for (const item of sale.items) await moveStock({ session, productId: item.product, delta: item.quantity, movementType: 'REVERSAL', referenceType: 'SALE', referenceId: sale._id, reason: 'Sale cancelled', userId: req.user.id }); sale.status = 'CANCELLED'; await sale.save({ session }) }); res.json({ message: 'Sale cancelled' }) } catch (error) { res.status(400).json({ message: error.message }) } finally { await session.endSession() } })

app.post('/api/sales', auth, async (req, res) => { const session = await mongoose.startSession(); try { let sale; await session.withTransaction(async () => { if (!Array.isArray(req.body.items) || req.body.items.length === 0) throw new Error('At least one sale item is required'); const items = []; const reserved = new Map(); for (const input of req.body.items) { const product = await Product.findOne({ _id: input.product, isActive: true }).session(session); const quantity = Number(input.quantity); const sellingPrice = input.sellingPrice === undefined || input.sellingPrice === '' ? product?.sellingPrice : Number(input.sellingPrice); const already = reserved.get(String(input.product)) || 0; if (!product || !Number.isInteger(quantity) || quantity <= 0 || !Number.isFinite(sellingPrice) || sellingPrice < 0) throw new Error('Each sale item must have a valid product, quantity, and rate'); if (product.stockQuantity < quantity + already) throw new Error(`Insufficient stock for ${product.name}`); reserved.set(String(product._id), already + quantity); items.push({ product: product._id, productNameSnapshot: product.name, skuSnapshot: product.sku, quantity, sellingPrice, costPriceSnapshot: product.weightedAverageCost, lineTotal: money(quantity * sellingPrice) }) } const totalAmount = money(items.reduce((sum, item) => sum + item.lineTotal, 0)); const amountPaid = money(Number(req.body.amountPaid || 0)); const balanceDue = requireCreditDetails(totalAmount, amountPaid, req.body.customerName, req.body.dueDate); const paymentStatus = balanceDue === 0 ? 'PAID' : amountPaid > 0 ? 'PARTIAL' : 'UDHARI'; sale = (await Sale.create([{ invoiceId: await nextId(Sale, 'invoiceId', 'INV'), saleDate: req.body.saleDate || new Date(), customerName: req.body.customerName, customerPhone: req.body.customerPhone, items, totalAmount, amountPaid, balanceDue, paymentStatus, dueDate: req.body.dueDate, notes: req.body.notes }], { session }))[0]; for (const item of items) await moveStock({ session, productId: item.product, delta: -item.quantity, movementType: 'SALE_OUT', referenceType: 'SALE', referenceId: sale._id, userId: req.user.id }); if (amountPaid > 0) await Payment.create([{ sale: sale._id, amount: amountPaid, paymentMethod: req.body.paymentMethod || 'OTHER' }], { session }) }); res.status(201).json(sale) } catch (error) { res.status(400).json({ message: error.message }) } finally { await session.endSession() } })
app.post('/api/sales/:id/payments', auth, async (req, res) => { const session = await mongoose.startSession(); try { let sale; await session.withTransaction(async () => { sale = await Sale.findOne({ _id: req.params.id, status: 'COMPLETED' }).session(session); if (!sale || sale.balanceDue <= 0) throw new Error('Invoice has no outstanding balance'); const amount = money(req.body.amount); if (!amount || amount > sale.balanceDue) throw new Error('Payment must be greater than zero and cannot exceed the balance'); await Payment.create([{ sale: sale._id, amount, paymentDate: req.body.paymentDate || new Date(), paymentMethod: req.body.paymentMethod || 'OTHER', notes: req.body.notes }], { session }); sale.amountPaid = money(sale.amountPaid + amount); sale.balanceDue = money(sale.totalAmount - sale.amountPaid); sale.paymentStatus = sale.balanceDue === 0 ? 'PAID' : 'PARTIAL'; await sale.save({ session }) }); res.json(sale) } catch (error) { res.status(400).json({ message: error.message }) } finally { await session.endSession() } })
app.get('/api/dashboard', auth, async (req, res) => { const [products, sales, outstanding, profitByProduct, profitByMonth] = await Promise.all([Product.find({ isActive: true }).lean(), Sale.find({ status: 'COMPLETED' }).sort({ saleDate: -1 }).limit(5).lean(), Sale.aggregate([{ $match: { status: 'COMPLETED', balanceDue: { $gt: 0 } } }, { $group: { _id: null, total: { $sum: '$balanceDue' }, count: { $sum: 1 } } }]), Sale.aggregate([{ $match: { status: 'COMPLETED' } }, { $unwind: '$items' }, { $group: { _id: '$items.productNameSnapshot', revenue: { $sum: '$items.lineTotal' }, cogs: { $sum: { $multiply: ['$items.quantity', '$items.costPriceSnapshot'] } } } }, { $project: { _id: 0, product: '$_id', revenue: 1, profit: { $subtract: ['$revenue', '$cogs'] } } }, { $sort: { profit: -1 } }]), Sale.aggregate([{ $match: { status: 'COMPLETED' } }, { $unwind: '$items' }, { $group: { _id: { $dateToString: { format: '%Y-%m', date: '$saleDate', timezone: 'Asia/Kolkata' } }, revenue: { $sum: '$items.lineTotal' }, cogs: { $sum: { $multiply: ['$items.quantity', '$items.costPriceSnapshot'] } } } }, { $project: { _id: 0, month: '$_id', revenue: 1, profit: { $subtract: ['$revenue', '$cogs'] } } }, { $sort: { month: 1 } }])]); res.json({ products, recentSales: sales, outstanding: outstanding[0] || { total: 0, count: 0 }, profitByProduct, profitByMonth }) })

app.use((error, req, res, _next) => { if (error?.code === 11000) return res.status(409).json({ message: 'A record with that identifier already exists' }); res.status(500).json({ message: 'Unexpected server error' }) })

const server = app.listen(port, () => console.log(`Retail inventory API listening on ${port}`))

if (process.env.MONGODB_URI) {
  databaseStatus = 'connecting'
  mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 })
    .then(() => { databaseStatus = 'connected'; console.log('MongoDB Atlas connected') })
    .catch((error) => { databaseStatus = 'error'; console.error(`MongoDB connection failed: ${error.message}`); console.error('Check Atlas Network Access and allow this machine IP address.') })
} else {
  console.warn('MONGODB_URI is not configured; database features are unavailable')
}

process.on('SIGTERM', async () => { await mongoose.disconnect(); server.close(() => process.exit(0)) })

export { app, moveStock }
