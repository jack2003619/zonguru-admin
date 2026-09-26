const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();

app.use(cors({ origin: true }));
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || 'CHANGE_THIS_JWT_SECRET';
const MONGO_URL = process.env.MONGO_URL;

const ADMIN_USERNAME =
  String(process.env.ADMIN_USERNAME || 'admin').trim();

const ADMIN_PASSWORD =
  String(process.env.ADMIN_PASSWORD || '');

if (!MONGO_URL) {
  console.error('ERROR: MONGO_URL is not set.');
  process.exit(1);
}

if (!ADMIN_PASSWORD) {
  console.error('ERROR: ADMIN_PASSWORD is not set.');
  process.exit(1);
}

/* =========================
   PASSWORD
========================= */

function verifyPassword(password, storedValue) {
  try {
    const [salt, storedHash] =
      String(storedValue || '').split(':');

    if (!salt || !storedHash) {
      return false;
    }

    const hash = crypto
      .scryptSync(password, salt, 64)
      .toString('hex');

    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(storedHash, 'hex');

    return (
      a.length === b.length &&
      crypto.timingSafeEqual(a, b)
    );
  } catch {
    return false;
  }
}

/* =========================
   SCHEMAS
========================= */

const userSchema = new mongoose.Schema(
  {
    username: String,
    email: String,
    phone: String,
    passwordHash: String,
    role: String,
    balance: {
      type: Number,
      default: 0
    },
    currency: {
      type: String,
      default: 'USDT'
    },
    totalProfit: {
      type: Number,
      default: 0
    },
    frozenAmount: {
      type: Number,
      default: 0
    },
    creditPoints: {
      type: Number,
      default: 0
    },
    creditScore: {
      type: Number,
      default: 100
    },
    avatarUrl: {
      type: String,
      default: ''
    },
    referralCode: String,
    referredBy: String,
    createdAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    collection: 'users'
  }
);

const productSchema = new mongoose.Schema(
  {
    name: String,
    category: String,
    price: Number,
    profitRate: Number,
    active: {
      type: Boolean,
      default: true
    }
  },
  {
    collection: 'products'
  }
);

const txSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    type: String,
    amount: Number,
    status: String,
    note: String,
    createdAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    collection: 'transactions'
  }
);

const msgSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    sender: String,
    text: String,
    read: {
      type: Boolean,
      default: false
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    collection: 'messages'
  }
);

const auditSchema = new mongoose.Schema(
  {
    adminId: mongoose.Schema.Types.ObjectId,
    action: String,
    targetUserId: mongoose.Schema.Types.ObjectId,
    targetTransactionId:
      mongoose.Schema.Types.ObjectId,
    details: String,
    createdAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    collection: 'admin_audits'
  }
);

const User = mongoose.model('AdminUser', userSchema);
const Product = mongoose.model('AdminProduct', productSchema);
const Transaction = mongoose.model('AdminTransaction', txSchema);
const Message = mongoose.model('AdminMessage', msgSchema);
const Audit = mongoose.model('AdminAudit', auditSchema);

/* =========================
   TOKEN
========================= */

function tokenFor(admin) {
  return jwt.sign(
    {
      id: admin.id,
      username: admin.username,
      role: 'admin'
    },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
}

/* =========================
   ADMIN AUTH
========================= */

function auth(req, res, next) {
  const header = req.headers.authorization || '';

  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Admin login required'
    });
  }

  try {
    const token = header.slice(7);

    req.admin = jwt.verify(token, JWT_SECRET);

    if (req.admin.role !== 'admin') {
      throw new Error('Admin access required');
    }

    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired admin token'
    });
  }
}

/* =========================
   AUDIT
========================= */

async function audit(admin, action, details, extra = {}) {
  try {
    const adminId =
      mongoose.isValidObjectId(admin.id)
        ? admin.id
        : undefined;

    await Audit.create({
      adminId,
      action,
      details,
      targetUserId: extra.targetUserId,
      targetTransactionId: extra.targetTransactionId
    });
  } catch (error) {
    console.error('Audit error:', error.message);
  }
}

/* =========================
   HEALTH
========================= */

app.get('/', (req, res) => {
  res.json({
    success: true,
    service: 'Zonguru Admin Server',
    status: 'online'
  });
});

/* =========================
   ADMIN LOGIN
========================= */

app.post('/api/admin/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (
      username !== ADMIN_USERNAME ||
      password !== ADMIN_PASSWORD
    ) {
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

    const token = tokenFor(admin);

    res.json({
      success: true,
      token,
      admin
    });
  } catch (error) {
    console.error('Admin login error:', error.message);

    res.status(500).json({
      success: false,
      message: 'Admin login failed'
    });
  }
});

/* =========================
   CURRENT ADMIN
========================= */

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

/* =========================
   USERS
========================= */

app.get('/api/admin/users', auth, async (req, res) => {
  try {
    const users = await User.find({
      role: 'user'
    })
      .select('-passwordHash')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to load users'
    });
  }
});

/* =========================
   FINANCIAL SETTINGS
========================= */

app.post(
  '/api/admin/users/:id/financial-settings',
  auth,
  async (req, res) => {
    try {
      const frozenAmount = Number(req.body.frozenAmount);
      const creditScore = Number(req.body.creditScore);

      if (!Number.isFinite(frozenAmount) || frozenAmount < 0) {
        return res.status(400).json({
          success: false,
          message: 'Frozen amount must be 0 or greater'
        });
      }

      if (
        !Number.isFinite(creditScore) ||
        creditScore < 0 ||
        creditScore > 100
      ) {
        return res.status(400).json({
          success: false,
          message: 'Credit score must be between 0 and 100'
        });
      }

      const user = await User.findOne({
        _id: req.params.id,
        role: 'user'
      });

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      user.frozenAmount = Number(frozenAmount.toFixed(2));
      user.creditScore = Math.round(creditScore);

      await user.save();

      await audit(
        req.admin,
        'FINANCIAL_SETTINGS_UPDATE',
        `Frozen ${user.frozenAmount.toFixed(2)} ${user.currency}; Credit Score ${user.creditScore}`,
        { targetUserId: user._id }
      );

      res.json({
        success: true,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          phone: user.phone,
          balance: user.balance,
          currency: user.currency,
          frozenAmount: user.frozenAmount,
          creditScore: user.creditScore
        }
      });
    } catch (error) {
      console.error(
        'Financial settings update error:',
        error.message
      );

      res.status(500).json({
        success: false,
        message: 'Financial settings update failed'
      });
    }
  }
);

/* =========================
   BALANCE ADJUST
========================= */

app.post(
  '/api/admin/users/:id/balance-adjust',
  auth,
  async (req, res) => {
    try {
      const delta = Number(req.body.delta);

      if (!Number.isFinite(delta) || delta === 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid balance adjustment'
        });
      }

      const user = await User.findOne({
        _id: req.params.id,
        role: 'user'
      });

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const current = Number(user.balance || 0);
      const nextBalance = Number((current + delta).toFixed(2));

      if (nextBalance < 0) {
        return res.status(400).json({
          success: false,
          message: 'Balance cannot be negative'
        });
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
      res.status(500).json({
        success: false,
        message: 'Balance update failed'
      });
    }
  }
);

/* =========================
   TRANSACTIONS
========================= */

app.get('/api/admin/transactions', auth, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .sort({ createdAt: -1 })
      .limit(500);

    res.json({
      success: true,
      transactions
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to load transactions'
    });
  }
});

/* =========================
   APPROVE TRANSACTION
========================= */

app.post(
  '/api/admin/transactions/:id/approve',
  auth,
  async (req, res) => {
    try {
      const transaction =
        await Transaction.findById(req.params.id);

      if (
        !transaction ||
        transaction.status !== 'pending'
      ) {
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

      if (transaction.type === 'deposit') {
        user.balance = Number(
          (Number(user.balance || 0) + amount).toFixed(2)
        );
      }

      if (transaction.type === 'withdraw') {
        if (Number(user.balance || 0) < amount) {
          return res.status(400).json({
            success: false,
            message: 'User balance is insufficient'
          });
        }

        user.balance = Number(
          (Number(user.balance || 0) - amount).toFixed(2)
        );
      }

      transaction.status = 'approved';

      await user.save();
      await transaction.save();

      await Message.create({
        userId: user._id,
        sender: 'admin',
        text:
          transaction.type === 'deposit'
            ? 'Deposit request was approved.'
            : 'Withdrawal request was approved.'
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

      res.json({
        success: true,
        message: 'Transaction approved'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Transaction approval failed'
      });
    }
  }
);

/* =========================
   REJECT TRANSACTION
========================= */

app.post(
  '/api/admin/transactions/:id/reject',
  auth,
  async (req, res) => {
    try {
      const transaction =
        await Transaction.findById(req.params.id);

      if (
        !transaction ||
        transaction.status !== 'pending'
      ) {
        return res.status(400).json({
          success: false,
          message: 'Transaction is not pending'
        });
      }

      transaction.status = 'rejected';

      const note = String(req.body.note || '').trim();

      if (note) {
        transaction.note =
          `${transaction.note || ''} | ${note}`;
      }

      await transaction.save();

      await Message.create({
        userId: transaction.userId,
        sender: 'admin',
        text:
          transaction.type === 'deposit'
            ? 'Deposit request was rejected.'
            : 'Withdrawal request was rejected.'
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

      res.json({
        success: true,
        message: 'Transaction rejected'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Transaction rejection failed'
      });
    }
  }
);

/* =========================
   PRODUCTS
========================= */

app.get('/api/admin/products', auth, async (req, res) => {
  try {
    const products = await Product.find().sort({ price: 1 });

    res.json({
      success: true,
      products
    });
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

    res.status(201).json({
      success: true,
      product
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Product creation failed'
    });
  }
});

app.patch('/api/admin/products/:id', auth, async (req, res) => {
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

    res.json({
      success: true,
      product
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Product update failed'
    });
  }
});

app.delete('/api/admin/products/:id', auth, async (req, res) => {
  try {
    const product =
      await Product.findByIdAndDelete(req.params.id);

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

/* =========================
   MESSAGES
========================= */

app.post('/api/admin/messages', auth, async (req, res) => {
  try {
    const userId = String(req.body.userId || '');
    const text = String(req.body.text || '').trim();

    if (
      !mongoose.isValidObjectId(userId) ||
      !text
    ) {
      return res.status(400).json({
        success: false,
        message: 'User and message are required'
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
      sender: 'admin',
      text
    });

    await audit(
      req.admin,
      'MESSAGE_SEND',
      text,
      { targetUserId: user._id }
    );

    res.status(201).json({
      success: true,
      message
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Message sending failed'
    });
  }
});

/* =========================
   CUSTOMER SERVICE CHAT
========================= */

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
      userId: req.params.userId
    }).sort({ createdAt: 1 });

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        phone: user.phone
      },
      messages
    });
  } catch (error) {
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
      sender: 'admin',
      text,
      read: false
    });

    res.status(201).json({
      success: true,
      message
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Reply sending failed'
    });
  }
});

/* =========================
   AUDIT LOGS
========================= */

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

/* =========================
   START
========================= */

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
