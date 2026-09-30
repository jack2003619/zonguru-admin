const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();

app.use(cors({ origin: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));
app.disable('x-powered-by');

app.get('/health/db-check', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1)
      return res.status(503).json({ success: false, database: 'disconnected' });
    const count = await User.countDocuments();
    res.json({
      success: true,
      databaseName: mongoose.connection.name,
      userCount: count,
      readyState: mongoose.connection.readyState
    });
  } catch (error) {
    res.status(503).json({ success: false, message: 'Database check failed' });
  }
});

app.get('/health', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        success: false,
        service: 'Zonguru Admin Server',
        status: 'unhealthy',
        database: 'disconnected'
      });
    }

    await mongoose.connection.db.admin().ping();

    res.status(200).json({
      success: true,
      service: 'Zonguru Admin Server',
      status: 'online',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('health check:', error.message);

    res.status(503).json({
      success: false,
      service: 'Zonguru Admin Server',
      status: 'unhealthy',
      database: 'error'
    });
  }
});
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
  vipLevel: { type: Number, default: 0, min: 0, max: 3 },
  currency: { type: String, default: 'USDT' },
  totalProfit: { type: Number, default: 0 },
  referralCode: String,
  referredBy: String,
  avatarUrl: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
}, { collection: 'users', strict: false });

const productSchema = new mongoose.Schema({
  name: String,
  category: String,
  price: Number,
  profitRate: Number,
  requiredVip: { type: Number, default: 0 },
  balanceGuardEnabled: { type: Boolean, default: false },
  specialTask: { type: Boolean, default: false },
  specialTaskNumber: { type: Number, default: 0 },
  specialRequiredAmount: { type: Number, default: 0 },
  specialCommissionMultiplier: { type: Number, default: 1 },
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
  image: { type: String, default: '' },
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
const adminAccountSchema = new mongoose.Schema({
  username: { type: String, unique: true, index: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: 'admin' },
  adminType: { type: String, enum: ['second_admin'], default: 'second_admin' },
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}, { collection: 'admin_accounts', strict: false });

const adminInviteCodeSchema = new mongoose.Schema({
  code: { type: String, unique: true, index: true, trim: true },
  ownerAdminId: { type: String, index: true },
  ownerAdminUsername: { type: String, default: '' },
  active: { type: Boolean, default: true },
  usedBy: { type: mongoose.Schema.Types.ObjectId, default: null },
  usedAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
}, { collection: 'invite_codes', strict: false });

const AdminAccount = mongoose.model('AdminAccount', adminAccountSchema);
const AdminInviteCode = mongoose.model('AdminInviteCode', adminInviteCodeSchema);


const taskProgressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, unique: true },
  productIds: [mongoose.Schema.Types.ObjectId],
  completedIds: [mongoose.Schema.Types.ObjectId],
  startedAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { collection: 'taskprogresses', strict: false });
const TaskProgress = mongoose.model('AdminTaskProgress', taskProgressSchema);

function tokenFor(admin) {
  return jwt.sign(
    {
      id: String(admin.id),
      username: admin.username,
      role: 'admin',
      adminType: admin.adminType || 'superadmin'
    },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(String(password), salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt}$${derivedKey.toString('hex')}`);
    });
  });
}

function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const parts = String(stored || '').split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return resolve(false);
    crypto.scrypt(String(password), parts[1], 64, (err, derivedKey) => {
      if (err) return reject(err);
      try {
        resolve(crypto.timingSafeEqual(Buffer.from(parts[2], 'hex'), derivedKey));
      } catch {
        resolve(false);
      }
    });
  });
}

function isSuperAdmin(req) {
  return req.admin?.adminType === 'superadmin';
}

function scopedUserFilter(req) {
  if (isSuperAdmin(req)) return { role: 'user' };
  return { role: 'user', ownerAdminId: String(req.admin.id) };
}

async function findScopedUser(req, id) {
  if (!mongoose.isValidObjectId(id)) return null;
  return User.findOne({ ...scopedUserFilter(req), _id: id });
}

async function getScopedUserIds(req) {
  if (isSuperAdmin(req)) return null;
  const ids = await User.find(scopedUserFilter(req)).select('_id').lean();
  return ids.map(x => x._id);
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Admin login required' });
  }
  try {
    req.admin = jwt.verify(header.slice(7), JWT_SECRET);
    if (req.admin.role !== 'admin') throw new Error('Admin access required');
    if (!req.admin.adminType) {
      req.admin.adminType = req.admin.id === '000000000000000000000000' ? 'superadmin' : 'second_admin';
    }
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
  res.json({ success: true, service: 'Zonguru Admin Server', status: 'online' });
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      const admin = {
        id: '000000000000000000000000',
        username: ADMIN_USERNAME,
        role: 'admin',
        adminType: 'superadmin'
      };
      return res.json({ success: true, token: tokenFor(admin), admin });
    }

    const account = await AdminAccount.findOne({ username, active: true });
    if (!account || !(await verifyPassword(password, account.passwordHash))) {
      return res.status(401).json({ success: false, message: 'Invalid admin username or password' });
    }

    const admin = {
      id: String(account._id),
      username: account.username,
      role: 'admin',
      adminType: 'second_admin'
    };
    res.json({ success: true, token: tokenFor(admin), admin });
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
      role: req.admin.role,
      adminType: req.admin.adminType || 'superadmin'
    }
  });
});

/* Main admin only: create/list second admins and manage invite codes. */
app.post('/api/admin/second-admins', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    if (!/^[A-Za-z0-9_.-]{3,40}$/.test(username))
      return res.status(400).json({ success: false, message: 'Username must be 3-40 characters and use letters, numbers, _, . or -' });
    if (password.length < 6)
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    if (username === ADMIN_USERNAME)
      return res.status(400).json({ success: false, message: 'That username is reserved for the main admin' });
    if (await AdminAccount.findOne({ username }))
      return res.status(409).json({ success: false, message: 'Admin username already exists' });

    const account = await AdminAccount.create({
      username,
      passwordHash: await hashPassword(password),
      role: 'admin',
      adminType: 'second_admin',
      active: true
    });
    await audit(req.admin, 'SECOND_ADMIN_CREATE', `Created second admin ${username}`);
    res.status(201).json({
      success: true,
      admin: { id: account._id, username: account.username, adminType: account.adminType, active: account.active, createdAt: account.createdAt }
    });
  } catch (error) {
    console.error('Create second admin:', error.message);
    res.status(500).json({ success: false, message: 'Failed to create second admin' });
  }
});

app.post('/api/admin/second-admins/:id/status', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ success: false, message: 'Invalid admin id' });
    const active = req.body.active === true || String(req.body.active).toLowerCase() === 'true';
    const account = await AdminAccount.findByIdAndUpdate(
      req.params.id, { $set: { active } }, { new: true }
    ).select('-passwordHash');
    if (!account) return res.status(404).json({ success: false, message: 'Second admin not found' });
    if (!active) {
      await AdminInviteCode.updateMany({ ownerAdminId: String(account._id), active: true }, { $set: { active: false } });
    }
    await audit(req.admin, active ? 'SECOND_ADMIN_ENABLE' : 'SECOND_ADMIN_DISABLE', `${account.username}`);
    res.json({ success: true, admin: account });
  } catch (error) {
    console.error('Second admin status:', error.message);
    res.status(500).json({ success: false, message: 'Failed to update second admin status' });
  }
});

app.get('/api/admin/second-admins', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    const admins = await AdminAccount.find().select('-passwordHash').sort({ createdAt: -1 }).lean();
    const counts = await Promise.all(admins.map(async a => ({
      ...a,
      userCount: await User.countDocuments({ role: 'user', ownerAdminId: String(a._id) })
    })));
    res.json({ success: true, admins: counts });
  } catch (error) {
    console.error('List second admins:', error.message);
    res.status(500).json({ success: false, message: 'Failed to load second admins' });
  }
});

app.post('/api/admin/invite-codes', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    const ownerId = String(req.body.ownerAdminId || '');
    if (!mongoose.isValidObjectId(ownerId))
      return res.status(400).json({ success: false, message: 'Valid second admin is required' });
    const owner = await AdminAccount.findOne({ _id: ownerId, active: true });
    if (!owner) return res.status(404).json({ success: false, message: 'Second admin not found or inactive' });

    let code = '';
    for (let i = 0; i < 10; i++) {
      code = crypto.randomBytes(5).toString('hex').toUpperCase();
      if (!(await AdminInviteCode.findOne({ code }))) break;
    }
    const invite = await AdminInviteCode.create({
      code,
      ownerAdminId: String(owner._id),
      ownerAdminUsername: owner.username,
      active: true
    });
    await audit(req.admin, 'INVITE_CODE_CREATE', `Invite ${code} for ${owner.username}`);
    res.status(201).json({ success: true, invite });
  } catch (error) {
    console.error('Create invite code:', error.message);
    res.status(500).json({ success: false, message: 'Failed to create invite code' });
  }
});

app.get('/api/admin/invite-codes', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    const invites = await AdminInviteCode.find().sort({ createdAt: -1 }).lean();
    res.json({ success: true, invites });
  } catch (error) {
    console.error('List invite codes:', error.message);
    res.status(500).json({ success: false, message: 'Failed to load invite codes' });
  }
});

app.post('/api/admin/invite-codes/:id/revoke', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ success: false, message: 'Invalid invite code id' });
    const invite = await AdminInviteCode.findByIdAndUpdate(
      req.params.id, { $set: { active: false } }, { new: true }
    );
    if (!invite) return res.status(404).json({ success: false, message: 'Invite code not found' });
    await audit(req.admin, 'INVITE_CODE_REVOKE', `Invite ${invite.code} revoked`);
    res.json({ success: true, invite });
  } catch (error) {
    console.error('Revoke invite code:', error.message);
    res.status(500).json({ success: false, message: 'Failed to revoke invite code' });
  }
});

app.get('/api/admin/users', auth, async (req, res) => {
  try {
    const users = await User.find(scopedUserFilter(req)).select('-passwordHash').sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (error) {
    console.error('Load users:', error.message);
    res.status(500).json({ success: false, message: 'Failed to load users' });
  }
});

async function adjustBalance(req, res) {
  try {
    const delta = Number(req.body.delta);
    if (!Number.isFinite(delta) || delta === 0) return res.status(400).json({ success: false, message: 'Invalid balance adjustment' });
    const user = await findScopedUser(req, req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const nextBalance = Number((Number(user.balance || 0) + delta).toFixed(2));
    if (nextBalance < 0) return res.status(400).json({ success: false, message: 'Balance cannot be negative' });
    user.balance = nextBalance;
    await user.save();
    await audit(req.admin, delta > 0 ? 'BALANCE_ADD' : 'BALANCE_SUBTRACT',
      `${delta > 0 ? '+' : ''}${delta.toFixed(2)} ${user.currency}; new balance ${nextBalance.toFixed(2)}`,
      { targetUserId: user._id });
    res.json({ success: true, user: { id: user._id, username: user.username, balance: user.balance, currency: user.currency } });
  } catch (error) {
    console.error('Balance update:', error.message);
    res.status(500).json({ success: false, message: 'Balance update failed' });
  }
}
app.post('/api/admin/users/:id/balance-adjust', auth, adjustBalance);
app.post('/api/admin/users/:id/balance', auth, adjustBalance);

app.get('/api/admin/users/:id/insufficient-balance', auth, async (req, res) => {
  try {
    const user = await findScopedUser(req, req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, rule: { enabled: Boolean(user.insufficientBalanceEnabled), taskNumber: Number(user.insufficientBalanceTaskNumber || 0), requiredAmount: Number(user.insufficientBalanceRequiredAmount || 0), commissionMultiplier: Number(user.insufficientBalanceCommissionMultiplier || 1) } });
  } catch (error) {
    console.error('Read user insufficient-balance rule:', error.message);
    res.status(500).json({ success: false, message: 'Failed to load user insufficient-balance rule' });
  }
});

app.post('/api/admin/users/:id/insufficient-balance', auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ success: false, message: 'Invalid user id' });
    const enabled = req.body.enabled === true || String(req.body.enabled).toLowerCase() === 'true';
    const taskNumber = Number(req.body.taskNumber || 0);
    const requiredAmount = Number(req.body.requiredAmount || 0);
    const commissionMultiplier = Number(req.body.commissionMultiplier || 1);
    if (enabled && (!Number.isInteger(taskNumber) || taskNumber < 1 || taskNumber > 5)) return res.status(400).json({ success: false, message: 'Task number must be between 1 and 5' });
    if (enabled && (!Number.isFinite(requiredAmount) || requiredAmount <= 0)) return res.status(400).json({ success: false, message: 'Required amount must be greater than 0' });
    if (enabled && (!Number.isFinite(commissionMultiplier) || commissionMultiplier < 1 || commissionMultiplier > 20)) return res.status(400).json({ success: false, message: 'Commission multiplier must be between 1 and 20x' });
    const set = { insufficientBalanceEnabled: enabled, insufficientBalanceTaskNumber: enabled ? taskNumber : 0, insufficientBalanceRequiredAmount: enabled ? Number(requiredAmount.toFixed(2)) : 0, insufficientBalanceCommissionMultiplier: enabled ? Number(commissionMultiplier) : 1 };
    const user = await User.findOneAndUpdate({ ...scopedUserFilter(req), _id: req.params.id }, { $set: set }, { new: true, runValidators: true });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    await audit(req.admin, 'USER_INSUFFICIENT_BALANCE_RULE', enabled ? `user=${user.username}; task=${taskNumber}; required=${requiredAmount}; commission=${commissionMultiplier}x` : `user=${user.username}; disabled`, { targetUserId: user._id });
    res.json({ success: true, message: enabled ? `Insufficient-balance rule enabled for ${user.username} — Task ${taskNumber}` : 'Insufficient-balance rule disabled for this user', user: cleanUser(user) });
  } catch (error) {
    console.error('User insufficient-balance rule:', error.stack || error.message);
    res.status(500).json({ success: false, message: 'User insufficient-balance rule update failed' });
  }
});

app.post('/api/admin/users/:id/financial-settings', auth, async (req, res) => {
  try {
    const user = await findScopedUser(req, req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const frozenAmount = Number(req.body.frozenAmount);
    const creditScore = Number(req.body.creditScore);
    if (!Number.isFinite(frozenAmount) || frozenAmount < 0)
      return res.status(400).json({ success: false, message: 'Frozen amount must be 0 or greater' });
    if (!Number.isFinite(creditScore) || creditScore < 0 || creditScore > 100)
      return res.status(400).json({ success: false, message: 'Credit score must be between 0 and 100' });
    user.frozenAmount = Number(frozenAmount.toFixed(2));
    user.creditScore = Number(creditScore.toFixed(0));
    await user.save();
    await audit(req.admin, 'FINANCIAL_SETTINGS_UPDATE',
      `Frozen Amount=${user.frozenAmount}; Credit Score=${user.creditScore}`, { targetUserId: user._id });
    res.json({ success: true, message: 'Financial settings updated', user: cleanUser(user) });
  } catch (error) {
    console.error('Financial settings:', error.message);
    res.status(500).json({ success: false, message: 'Financial settings update failed' });
  }
});

app.post('/api/admin/users/:id/vip', auth, async (req, res) => {
  try {
    const level = Number(req.body.vipLevel);
    if (!Number.isInteger(level) || level < 0 || level > 3)
      return res.status(400).json({ success: false, message: 'VIP level must be 0, 1, 2 or 3' });
    const user = await findScopedUser(req, req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    user.vipLevel = level;
    await user.save();
    await TaskProgress.deleteOne({ userId: user._id });
    await audit(req.admin, 'VIP_UPDATE', `VIP level changed to ${level}; task reset to 0`, { targetUserId: user._id });
    res.json({ success: true, user: cleanUser(user) });
  } catch (error) {
    console.error('VIP update:', error.message);
    res.status(500).json({ success: false, message: 'VIP update failed' });
  }
});

app.post('/api/admin/users/:id/task-reset', auth, async (req, res) => {
  try {
    const user = await findScopedUser(req, req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    await TaskProgress.deleteOne({ userId: user._id });
    await audit(req.admin, 'TASK_RESET', 'Task progress reset to 0; previous orders, balance and profits preserved.', { targetUserId: user._id });
    res.json({ success: true, message: 'Task reset to 0. Previous orders and profits were preserved.' });
  } catch (error) {
    console.error('Task reset:', error.message);
    res.status(500).json({ success: false, message: 'Task reset failed' });
  }
});

app.get('/api/admin/transactions', auth, async (req, res) => {
  try {
    const userIds = await getScopedUserIds(req);
    const filter = userIds ? { userId: { $in: userIds } } : {};
    const transactions = await Transaction.find(filter).sort({ createdAt: -1 }).limit(500).lean();
    const ids=[...new Set(transactions.map(t=>String(t.userId||'')).filter(Boolean))];
    const usersById=new Map((await User.find({_id:{$in:ids}}).select('username email phone').lean()).map(u=>[String(u._id),u]));
    const enriched=transactions.map(t=>{
      const u=usersById.get(String(t.userId||''));
      return {...t,user:{id:t.userId,username:u?.username||'',email:u?.email||'',phone:u?.phone||''}};
    });
    res.json({ success: true, transactions:enriched });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to load transactions' });
  }
});

app.post('/api/admin/transactions/:id/approve', auth, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction || transaction.status !== 'pending')
      return res.status(400).json({ success: false, message: 'Transaction is not pending' });
    const user = await findScopedUser(req, transaction.userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found or not assigned to this admin' });
    const amount = Number(transaction.amount || 0);
    const type = String(transaction.type || '').toLowerCase();
    if (type === 'deposit') user.balance = Number((Number(user.balance || 0) + amount).toFixed(2));
    if (type === 'withdraw' || type === 'withdrawal') {
      if (Number(user.balance || 0) < amount)
        return res.status(400).json({ success: false, message: 'User balance is insufficient' });
      user.balance = Number((Number(user.balance || 0) - amount).toFixed(2));
    }
    transaction.status = 'approved';
    await user.save();
    await transaction.save();
    await Message.create({
      userId: user._id, subject: 'Customer Service', sender: 'admin',
      text: type === 'deposit' ? 'Deposit request was approved.' : 'Withdrawal request was approved.',
      read: false
    });
    await audit(req.admin, 'TRANSACTION_APPROVE', `${transaction.type} ${amount}`,
      { targetUserId: user._id, targetTransactionId: transaction._id });
    res.json({ success: true, message: 'Transaction approved' });
  } catch (error) {
    console.error('Approve transaction:', error.message);
    res.status(500).json({ success: false, message: 'Transaction approval failed' });
  }
});

app.post('/api/admin/transactions/:id/reject', auth, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction || transaction.status !== 'pending')
      return res.status(400).json({ success: false, message: 'Transaction is not pending' });
    if (!await findScopedUser(req, transaction.userId))
      return res.status(404).json({ success: false, message: 'User not found or not assigned to this admin' });
    transaction.status = 'rejected';
    const note = String(req.body.note || '').trim();
    if (note) transaction.note = `${transaction.note || ''}${transaction.note ? ' | ' : ''}${note}`;
    await transaction.save();
    await Message.create({
      userId: transaction.userId, subject: 'Customer Service', sender: 'admin',
      text: transaction.type === 'deposit' ? 'Deposit request was rejected.' : 'Withdrawal request was rejected.',
      read: false
    });
    await audit(req.admin, 'TRANSACTION_REJECT',
      `${transaction.type} ${transaction.amount}${note ? ' - ' + note : ''}`,
      { targetUserId: transaction.userId, targetTransactionId: transaction._id });
    res.json({ success: true, message: 'Transaction rejected' });
  } catch (error) {
    console.error('Reject transaction:', error.message);
    res.status(500).json({ success: false, message: 'Transaction rejection failed' });
  }
});

app.get('/api/admin/products', auth, async (req, res) => {
  try {
    const products = await Product.find().sort({ price: 1 });
    res.json({ success: true, products });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to load products' });
  }
});

app.post('/api/admin/products', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    const name = String(req.body.name || '').trim();
    const category = String(req.body.category || 'General').trim();
    const price = Number(req.body.price);
    const profitRate = Number(req.body.profitRate);
    if (!name || !Number.isFinite(price) || price <= 0 || !Number.isFinite(profitRate) || profitRate < 0)
      return res.status(400).json({ success: false, message: 'Invalid product data' });
    const product = await Product.create({
      name, category, price, profitRate,
      requiredVip: Number(req.body.requiredVip || 0),
      balanceGuardEnabled: Boolean(req.body.balanceGuardEnabled),
      active: true
    });
    await audit(req.admin, 'PRODUCT_CREATE', name);
    res.status(201).json({ success: true, product });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Product creation failed' });
  }
});

async function updateProduct(req, res) {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    const update = {};
    if (req.body.name !== undefined) update.name = String(req.body.name).trim();
    if (req.body.category !== undefined) update.category = String(req.body.category).trim();
    if (req.body.price !== undefined) update.price = Number(req.body.price);
    if (req.body.profitRate !== undefined) update.profitRate = Number(req.body.profitRate);
    if (req.body.requiredVip !== undefined) update.requiredVip = Number(req.body.requiredVip);
    if (req.body.balanceGuardEnabled !== undefined) update.balanceGuardEnabled = Boolean(req.body.balanceGuardEnabled);
    if (req.body.active !== undefined) update.active = Boolean(req.body.active);
    const product = await Product.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    await audit(req.admin, 'PRODUCT_UPDATE', product.name);
    res.json({ success: true, product });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Product update failed' });
  }
}
app.patch('/api/admin/products/:id', auth, updateProduct);
app.put('/api/admin/products/:id', auth, updateProduct);

/* Insufficient-balance rule: safe block, never create a negative balance. */
async function saveInsufficientBalanceRule(req, res) {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });

    const enabled = Boolean(req.body.enabled);
    const taskNumber = Number(req.body.taskNumber || 0);
    const requiredAmount = Number(req.body.requiredAmount || 0);
    const multiplier = Number(req.body.commissionMultiplier || 1);

    if (enabled && (!Number.isInteger(taskNumber) || taskNumber < 1 || taskNumber > 5))
      return res.status(400).json({ success: false, message: 'Task number must be 1-5' });
    if (enabled && (!Number.isFinite(requiredAmount) || requiredAmount <= 0))
      return res.status(400).json({ success: false, message: 'Required amount must be greater than 0' });
    if (!Number.isFinite(multiplier) || multiplier < 1 || multiplier > 20)
      return res.status(400).json({ success: false, message: 'Commission multiplier must be between 1 and 20x' });

    product.specialTask = enabled;
    product.specialTaskNumber = enabled ? taskNumber : 0;
    product.specialRequiredAmount = enabled ? Number(requiredAmount.toFixed(2)) : 0;
    product.specialCommissionMultiplier = enabled ? multiplier : 1;
    await product.save();

    await audit(req.admin, 'INSUFFICIENT_BALANCE_RULE_UPDATE',
      `enabled=${enabled}; task=${taskNumber}; required=${requiredAmount}; commission=${multiplier}x`,
      { details: product.name });

    res.json({
      success: true,
      message: enabled
        ? `Task ${taskNumber} insufficient-balance rule saved`
        : 'Insufficient-balance rule disabled',
      product
    });
  } catch (error) {
    console.error('Insufficient-balance rule:', error.message);
    res.status(500).json({ success: false, message: 'Insufficient-balance rule update failed' });
  }
}

app.post('/api/admin/products/:id/special-task', auth, saveInsufficientBalanceRule);
app.post('/api/admin/products/:id/insufficient-balance', auth, saveInsufficientBalanceRule);

app.delete('/api/admin/products/:id', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    await audit(req.admin, 'PRODUCT_DELETE', product.name);
    res.json({ success: true, message: 'Product deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Product deletion failed' });
  }
});

app.post('/api/admin/messages', auth, async (req, res) => {
  try {
    const userId = String(req.body.userId || '');
    const text = String(req.body.text || '').trim();
    if (!mongoose.isValidObjectId(userId) || !text)
      return res.status(400).json({ success: false, message: 'User and message are required' });
    if (text.length > 2000)
      return res.status(400).json({ success: false, message: 'Message is too long' });
    const user = await findScopedUser(req, userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const message = await Message.create({ userId, subject: 'Customer Service', sender: 'admin', text, read: false });
    await audit(req.admin, 'MESSAGE_SEND', text, { targetUserId: user._id });
    res.status(201).json({ success: true, message });
  } catch (error) {
    console.error('Admin message:', error.message);
    res.status(500).json({ success: false, message: 'Message sending failed' });
  }
});

app.get('/api/admin/chat/:userId', auth, async (req, res) => {
  try {
    const user = await findScopedUser(req, req.params.userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const messages = await Message.find({
      userId: req.params.userId,
      $or: [{ subject: 'Customer Service' }, { sender: 'admin' }, { sender: 'user' }]
    }).sort({ createdAt: 1 });
    res.json({
      success: true,
      user: {
        id: user._id, username: user.username, email: user.email || '', phone: user.phone || '',
        balance: Number(user.balance || 0), frozenAmount: Number(user.frozenAmount || 0),
        creditScore: Number(user.creditScore ?? 100), creditPoints: Number(user.creditPoints || 0),
        currency: user.currency || 'USDT'
      },
      messages
    });
  } catch (error) {
    console.error('Load chat:', error.message);
    res.status(500).json({ success: false, message: 'Failed to load chat' });
  }
});

app.post('/api/admin/chat/:userId/reply', auth, async (req, res) => {
  try {
    const text = String(req.body?.text || '').trim();
    if (!text) return res.status(400).json({ success: false, message: 'Reply is required' });
    if (text.length > 2000) return res.status(400).json({ success: false, message: 'Reply is too long' });
    const user = await findScopedUser(req, req.params.userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const message = await Message.create({
      userId: user._id, subject: 'Customer Service', sender: 'admin', text, read: false
    });
    await audit(req.admin, 'CHAT_REPLY', text, { targetUserId: user._id });
    res.status(201).json({ success: true, message });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Reply sending failed' });
  }
});

app.get('/api/admin/config', auth, async (req, res) => {
  res.json({
    success: true,
    controls: {
      balanceAdjustment: true,
      vipLevels: [0, 1, 2, 3],
      creditScoreRange: [0, 100],
      frozenAmountMin: 0,
      taskResetPreservesHistory: true,
      insufficientBalanceRule: 'safe-block',
      negativeBalances: false,
      insufficientBalanceEndpoint: '/api/admin/products/:id/insufficient-balance'
    }
  });
});

app.get('/api/admin/audits', auth, async (req, res) => {
  try {
    const userIds = await getScopedUserIds(req);
    const filter = userIds ? { $or: [{ targetUserId: { $in: userIds } }, { targetUserId: { $exists: false } }] } : {};
    const audits = await Audit.find(filter).sort({ createdAt: -1 }).limit(500);
    res.json({ success: true, audits });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to load audit logs' });
  }
});

mongoose.connect(MONGO_URL)
  .then(() => {
    console.log('MongoDB connected successfully');
    app.listen(PORT, () => console.log(`Zonguru admin server running on port ${PORT}`));
  })
  .catch(error => {
    console.error('MongoDB connection failed:', error.message);
    process.exit(1);
  });
