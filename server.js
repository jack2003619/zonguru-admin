const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();

app.use(cors({ origin: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_JWT_SECRET';
const MONGO_URL = process.env.MONGO_URL;
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || 'admin').trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '');

if (!MONGO_URL) {
  console.error('ERROR: MONGO_URL is not set.');
  process.exit(1);
}
if (!ADMIN_PASSWORD) {
  console.error('ERROR: ADMIN_PASSWORD is not set.');
  process.exit(1);
}

function cleanUser(user) {
  if (!user) return null;
  const data = user.toObject ? user.toObject() : { ...user };
  delete data.passwordHash;
  return data;
}

const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, default: '' },
  phone: { type: String, default: '' },
  passwordHash: String,
  role: String,
  balance: { type: Number, default: 0 },
  frozenAmount: { type: Number, default: 0 },
  creditPoints: { type: Number, default: 0 },
  creditScore: { type: Number, default: 100 },
  currency: { type: String, default: 'USDT' },
  totalProfit: { type: Number, default: 0 },
  referralCode: String,
  referredBy: String,
  avatarUrl: { type: String, default: '' },
  vipLevel: { type: Number, default: 0, min: 0, max: 3 },
  createdAt: { type: Date, default: Date.now }
}, { collection: 'users', strict: false });

const productSchema = new mongoose.Schema({
  name: String,
  category: String,
  price: Number,
  profitRate: Number,
  active: { type: Boolean, default: true }
}, { collection: 'products', strict: false });

const txSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  type: String,
  amount: Number,
  status: String,
  note: String,
  createdAt: { type: Date, default: Date.now }
}, { collection: 'transactions', strict: false });

const msgSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  subject: { type: String, default: 'Customer Service' },
  sender: String,
  text: String,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
}, { collection: 'messages', strict: false });

const auditSchema = new mongoose.Schema({
  adminId: mongoose.Schema.Types.ObjectId,
  action: String,
  targetUserId: mongoose.Schema.Types.ObjectId,
  targetTransactionId: mongoose.Schema.Types.ObjectId,
  details: String,
  createdAt: { type: Date, default: Date.now }
}, { collection: 'admin_audits', strict: false });

const User = mongoose.model('AdminUser', userSchema);
const Product = mongoose.model('AdminProduct', productSchema);
const Transaction = mongoose.model('AdminTransaction', txSchema);
const Message = mongoose.model('AdminMessage', msgSchema);
const Audit = mongoose.model('AdminAudit', auditSchema);

function tokenFor(admin) {
  return jwt.sign(
    { id: admin.id, username: admin.username, role: 'admin' },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Admin login required' });
  }
  try {
    req.admin = jwt.verify(header.slice(7), JWT_SECRET);
    if (req.admin.role !== 'admin') throw new Error('Admin access required');
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired admin token' });
  }
}

async function audit(admin, action, details, extra = {}) {
  try {
    await Audit.create({
      adminId: mongoose.isValidObjectId(admin.id) ? admin.id : undefined,
      action,
      details,
      targetUserId: extra.targetUserId,
      targetTransactionId: extra.targetTransactionId
    });
  } catch (error) {
    console.error('Audit error:', error.message);
  }
}

app.get('/', (req, res) => {
  res.json({
    success: true,
    service: 'Zonguru Admin Server',
    status: 'online'
  });
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
      return res.status(401).json({
        success: false,
        message: 'Invalid admin username or password'
      });
    }

    const admin = {
      id: '000000000000000000000000',
      username: ADMIN_USERNAME,
      role: 'admin'
    };

    res.json({
      success: true,
      token: tokenFor(admin),
      admin
    });
  } catch (error) {
    console.error('Admin login error:', error.message);
    res.status(500).json({ success: false, message: 'Admin login failed' });
  }
});

app.get('/api/admin/me', auth, async (req, res) => {
  res.json({
    success: true,
    admin: {
      id: req.admin.id,
      username: req.admin.username,
      role: req.admin.role
    }
  });
});

app.get('/api/admin/users', auth, async (req, res) => {
  try {
    const users = await User.find({ role: 'user' })
      .select('-passwordHash')
      .sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (error) {
    console.error('Load users:', error.message);
    res.status(500).json({ success: false, message: 'Failed to load users' });
  }
});

async function adjustBalance(req, res) {
  try {
    const delta = Number(req.body.delta);
    if (!Number.isFinite(delta) || delta === 0) {
      return res.status(400).json({ success: false, message: 'Invalid balance adjustment' });
    }

    const user = await User.findOne({ _id: req.params.id, role: 'user' });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const nextBalance = Number((Number(user.balance || 0) + delta).toFixed(2));
    if (nextBalance < 0) {
      return res.status(400).json({ success: false, message: 'Balance cannot be negative' });
    }

    user.balance = nextBalance;
    await user.save();

    await audit(
      req.admin,
      delta > 0 ? 'BALANCE_ADD' : 'BALANCE_SUBTRACT',
      `${delta > 0 ? '+' : ''}${delta.toFixed(2)} ${user.currency}; new balance ${nextBalance.toFixed(2)}`,
      { targetUserId: user._id }
    );

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        balance: user.balance,
        currency: user.currency
      }
    });
  } catch (error) {
    console.error('Balance update:', error.message);
    res.status(500).json({ success: false, message: 'Balance update failed' });
  }
}

app.post('/api/admin/users/:id/balance-adjust', auth, adjustBalance);
app.post('/api/admin/users/:id/balance', auth, adjustBalance);

app.post('/api/admin/users/:id/financial-settings', auth, async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.params.id, role: 'user' });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const frozenAmount = Number(req.body.frozenAmount);
    const creditScore = Number(req.body.creditScore);

    if (!Number.isFinite(frozenAmount) || frozenAmount < 0) {
      return res.status(400).json({
        success: false,
        message: 'Frozen amount must be 0 or greater'
      });
    }

    if (!Number.isFinite(creditScore) || creditScore < 0 || creditScore > 100) {
      return res.status(400).json({
        success: false,
        message: 'Credit score must be between 0 and 100'
      });
    }

    user.frozenAmount = Number(frozenAmount.toFixed(2));
    user.creditScore = Number(creditScore.toFixed(0));
    await user.save();

    await audit(
      req.admin,
      'FINANCIAL_SETTINGS_UPDATE',
      `Frozen Amount=${user.frozenAmount}; Credit Score=${user.creditScore}`,
      { targetUserId: user._id }
    );

    res.json({
      success: true,
      message: 'Financial settings updated',
      user: cleanUser(user)
    });
  } catch (error) {
    console.error('Financial settings:', error.message);
    res.status(500).json({
      success: false,
      message: 'Financial settings update failed'
    });
  }
});


app.post('/api/admin/users/:id/vip', auth, async (req, res) => {
  try {
    const vipLevel = Number(req.body.vipLevel);
    if (!Number.isInteger(vipLevel) || vipLevel < 0 || vipLevel > 3) {
      return res.status(400).json({ success:false, message:'VIP level must be 0, 1, 2 or 3' });
    }
    const user = await User.findOne({ _id:req.params.id, role:'user' });
    if (!user) return res.status(404).json({ success:false, message:'User not found' });
    user.vipLevel = vipLevel;
    await user.save();
    await audit(req.admin, 'VIP_LEVEL_UPDATE', `VIP ${vipLevel}`, { targetUserId:user._id });
    res.json({ success:true, user:cleanUser(user) });
  } catch (error) {
    console.error('VIP update:', error.message);
    res.status(500).json({ success:false, message:'VIP level update failed' });
  }
});


app.get('/api/admin/transactions', auth, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .sort({ createdAt: -1 })
      .limit(500);
    res.json({ success: true, transactions });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to load transactions'
    });
  }
});

app.post('/api/admin/transactions/:id/approve', auth, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);

    if (!transaction || transaction.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Transaction is not pending'
      });
    }

    const user = await User.findById(transaction.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const amount = Number(transaction.amount || 0);
    const type = String(transaction.type || '').toLowerCase();

    if (type === 'deposit') {
      user.balance = Number((Number(user.balance || 0) + amount).toFixed(2));
    }

    if (type === 'withdraw' || type === 'withdrawal') {
      if (Number(user.balance || 0) < amount) {
        return res.status(400).json({
          success: false,
          message: 'User balance is insufficient'
        });
      }
      user.balance = Number((Number(user.balance || 0) - amount).toFixed(2));
    }

    transaction.status = 'approved';
    await user.save();
    await transaction.save();

    await Message.create({
      userId: user._id,
      subject: 'Customer Service',
      sender: 'admin',
      text: type === 'deposit'
        ? 'Deposit request was approved.'
        : 'Withdrawal request was approved.',
      read: false
    });

    await audit(
      req.admin,
      'TRANSACTION_APPROVE',
      `${transaction.type} ${amount}`,
      {
        targetUserId: user._id,
        targetTransactionId: transaction._id
      }
    );

    res.json({ success: true, message: 'Transaction approved' });
  } catch (error) {
    console.error('Approve transaction:', error.message);
    res.status(500).json({
      success: false,
      message: 'Transaction approval failed'
    });
  }
});

app.post('/api/admin/transactions/:id/reject', auth, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);

    if (!transaction || transaction.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Transaction is not pending'
      });
    }

    transaction.status = 'rejected';

    const note = String(req.body.note || '').trim();
    if (note) {
      transaction.note =
        `${transaction.note || ''}${transaction.note ? ' | ' : ''}${note}`;
    }

    await transaction.save();

    await Message.create({
      userId: transaction.userId,
      subject: 'Customer Service',
      sender: 'admin',
      text: transaction.type === 'deposit'
        ? 'Deposit request was rejected.'
        : 'Withdrawal request was rejected.',
      read: false
    });

    await audit(
      req.admin,
      'TRANSACTION_REJECT',
      `${transaction.type} ${transaction.amount}${note ? ' - ' + note : ''}`,
      {
        targetUserId: transaction.userId,
        targetTransactionId: transaction._id
      }
    );

    res.json({ success: true, message: 'Transaction rejected' });
  } catch (error) {
    console.error('Reject transaction:', error.message);
    res.status(500).json({
      success: false,
      message: 'Transaction rejection failed'
    });
  }
});

app.get('/api/admin/products', auth, async (req, res) => {
  try {
    const products = await Product.find().sort({ price: 1 });
    res.json({ success: true, products });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to load products'
    });
  }
});

app.post('/api/admin/products', auth, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const category = String(req.body.category || 'General').trim();
    const price = Number(req.body.price);
    const profitRate = Number(req.body.profitRate);

    if (
      !name ||
      !Number.isFinite(price) ||
      price <= 0 ||
      !Number.isFinite(profitRate) ||
      profitRate < 0
    ) {
      return res.status(400).json({
        success: false,
        message: 'Invalid product data'
      });
    }

    const product = await Product.create({
      name,
      category,
      price,
      profitRate,
      active: true
    });

    await audit(req.admin, 'PRODUCT_CREATE', name);

    res.status(201).json({ success: true, product });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Product creation failed'
    });
  }
});

async function updateProduct(req, res) {
  try {
    const update = {};

    if (req.body.name !== undefined) {
      update.name = String(req.body.name).trim();
    }

    if (req.body.category !== undefined) {
      update.category = String(req.body.category).trim();
    }

    if (req.body.price !== undefined) {
      update.price = Number(req.body.price);
    }

    if (req.body.profitRate !== undefined) {
      update.profitRate = Number(req.body.profitRate);
    }

    if (req.body.active !== undefined) {
      update.active = Boolean(req.body.active);
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      update,
      { new: true }
    );

    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    await audit(req.admin, 'PRODUCT_UPDATE', product.name);

    res.json({ success: true, product });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Product update failed'
    });
  }
}

app.patch('/api/admin/products/:id', auth, updateProduct);
app.put('/api/admin/products/:id', auth, updateProduct);

app.delete('/api/admin/products/:id', auth, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);

    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    await audit(req.admin, 'PRODUCT_DELETE', product.name);

    res.json({
      success: true,
      message: 'Product deleted'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Product deletion failed'
    });
  }
});

app.post('/api/admin/messages', auth, async (req, res) => {
  try {
    const userId = String(req.body.userId || '');
    const text = String(req.body.text || '').trim();

    if (!mongoose.isValidObjectId(userId) || !text) {
      return res.status(400).json({
        success: false,
        message: 'User and message are required'
      });
    }

    if (text.length > 2000) {
      return res.status(400).json({
        success: false,
        message: 'Message is too long'
      });
    }

    const user = await User.findOne({
      _id: userId,
      role: 'user'
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const message = await Message.create({
      userId,
      subject: 'Customer Service',
      sender: 'admin',
      text,
      read: false
    });

    await audit(req.admin, 'MESSAGE_SEND', text, {
      targetUserId: user._id
    });

    res.status(201).json({
      success: true,
      message
    });
  } catch (error) {
    console.error('Admin message:', error.message);
    res.status(500).json({
      success: false,
      message: 'Message sending failed'
    });
  }
});

app.get('/api/admin/chat/:userId', auth, async (req, res) => {
  try {
    const user = await User.findOne({
      _id: req.params.userId,
      role: 'user'
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const messages = await Message.find({
      userId: req.params.userId,
      $or: [
        { subject: 'Customer Service' },
        { sender: 'admin' },
        { sender: 'user' }
      ]
    }).sort({ createdAt: 1 });

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email || '',
        phone: user.phone || '',
        balance: Number(user.balance || 0),
        frozenAmount: Number(user.frozenAmount || 0),
        creditScore: Number(user.creditScore ?? 100),
        creditPoints: Number(user.creditPoints || 0),
        currency: user.currency || 'USDT'
      },
      messages
    });
  } catch (error) {
    console.error('Load chat:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to load chat'
    });
  }
});

app.post('/api/admin/chat/:userId/reply', auth, async (req, res) => {
  try {
    const text = String(req.body?.text || '').trim();

    if (!text) {
      return res.status(400).json({
        success: false,
        message: 'Reply is required'
      });
    }

    if (text.length > 2000) {
      return res.status(400).json({
        success: false,
        message: 'Reply is too long'
      });
    }

    const user = await User.findOne({
      _id: req.params.userId,
      role: 'user'
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const message = await Message.create({
      userId: user._id,
      subject: 'Customer Service',
      sender: 'admin',
      text,
      read: false
    });

    await audit(req.admin, 'CHAT_REPLY', text, {
      targetUserId: user._id
    });

    res.status(201).json({
      success: true,
      message
    });
  } catch (error) {
    console.error('Chat reply:', error.message);
    res.status(500).json({
      success: false,
      message: 'Reply sending failed'
    });
  }
});

app.get('/api/admin/audits', auth, async (req, res) => {
  try {
    const audits = await Audit.find()
      .sort({ createdAt: -1 })
      .limit(500);

    res.json({
      success: true,
      audits
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to load audit logs'
    });
  }
});

mongoose
  .connect(MONGO_URL)
  .then(() => {
    console.log('MongoDB connected successfully');

    app.listen(PORT, () => {
      console.log(
        `Zonguru admin server running on port ${PORT}`
      );
    });
  })
  .catch(error => {
    console.error(
      'MongoDB connection failed:',
      error.message
    );
    process.exit(1);
  });
