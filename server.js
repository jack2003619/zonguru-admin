const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();

app.use(cors({ origin: true }));
app.use(express.json({ limit: '14mb' }));
app.use(express.static('public', { setHeaders: (res) => { res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); res.setHeader('Pragma', 'no-cache'); res.setHeader('Expires', '0'); } }));

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
const AdminActivity = mongoose.model('AdminActivity', new mongoose.Schema({
  eventType:String,userId:mongoose.Schema.Types.ObjectId,username:String,email:String,phone:String,
  ip:String,device:String,ownerAdminId:String,createdAt:Date
},{collection:'admin_activity',strict:false}));
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

const platformSettingSchema = new mongoose.Schema({
  key: { type: String, unique: true, index: true },
  value: { type: mongoose.Schema.Types.Mixed, default: null },
  updatedAt: { type: Date, default: Date.now }
}, { collection: 'platform_settings', strict: false });
const PlatformSetting = mongoose.model('AdminPlatformSetting', platformSettingSchema);

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


const announcementSchema = new mongoose.Schema({
  title: { type: String, default: '' },
  text: { type: String, default: '' },
  image: { type: String, default: '' },
  audience: { type: String, enum: ['all', 'selected'], default: 'all' },
  recipientIds: [{ type: mongoose.Schema.Types.ObjectId }],
  dismissedBy: [{ type: mongoose.Schema.Types.ObjectId }],
  active: { type: Boolean, default: true },
  createdBy: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
}, { collection: 'announcements', strict: false });
const Announcement = mongoose.model('AdminAnnouncement', announcementSchema);

app.get('/api/admin/announcements', auth, async (req, res) => {
  try {
    const filter = {};
    if (!isSuperAdmin(req)) {
      const ids = await getScopedUserIds(req);
      filter.$or = [
        { audience: 'all', createdBy: req.admin.username },
        { audience: 'selected', recipientIds: { $in: ids || [] } }
      ];
    }
    const announcements = await Announcement.find(filter).sort({ createdAt: -1 }).limit(300).lean();
    res.json({ success: true, announcements });
  } catch (error) {
    console.error('List announcements:', error.stack || error.message);
    res.status(500).json({ success: false, message: 'Failed to load announcements' });
  }
});

app.post('/api/admin/announcements', auth, async (req, res) => {
  try {
    const title = String(req.body?.title || '').trim();
    const text = String(req.body?.text || '').trim();
    const image = String(req.body?.image || '').trim();
    const requestedAudience = String(req.body?.audience || 'all').toLowerCase();
    const suppliedIds = Array.isArray(req.body?.recipientIds) ? req.body.recipientIds.map(String) : [];
    if (!title && !text && !image)
      return res.status(400).json({ success: false, message: 'Add announcement text or an image' });
    if (title.length > 120 || text.length > 5000)
      return res.status(400).json({ success: false, message: 'Announcement text is too long' });
    if (image && (!/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(image) || image.length > 14000000))
      return res.status(400).json({ success: false, message: 'Image must be PNG, JPG, WEBP or GIF and no larger than 10 MB' });
    if (!['all', 'selected'].includes(requestedAudience))
      return res.status(400).json({ success: false, message: 'Invalid announcement audience' });

    let audience = requestedAudience;
    let recipientIds = [];
    if (isSuperAdmin(req)) {
      if (audience === 'selected') {
        if (!suppliedIds.length) return res.status(400).json({ success: false, message: 'Select at least one user' });
        const validUsers = await User.find({ role: 'user', _id: { $in: suppliedIds.filter(mongoose.isValidObjectId) } }).select('_id').lean();
        recipientIds = validUsers.map(user => user._id);
        if (recipientIds.length !== new Set(suppliedIds).size)
          return res.status(400).json({ success: false, message: 'One or more selected users are invalid' });
      }
    } else {
      const scopedIds = await getScopedUserIds(req) || [];
      const scopeSet = new Set(scopedIds.map(id => String(id)));
      if (audience === 'all') {
        audience = 'selected';
        recipientIds = scopedIds;
        if (!recipientIds.length) return res.status(400).json({ success: false, message: 'No users are assigned to this admin' });
      } else {
        if (!suppliedIds.length || suppliedIds.some(id => !mongoose.isValidObjectId(id) || !scopeSet.has(id)))
          return res.status(403).json({ success: false, message: 'Selected users must belong to your invite-code user list' });
        recipientIds = suppliedIds;
      }
    }

    const announcement = await Announcement.create({
      title, text, image, audience, recipientIds,
      active: true, createdBy: String(req.admin.username || req.admin.id)
    });
    await audit(req.admin, 'ANNOUNCEMENT_CREATE',
      'Created announcement for ' + (audience === 'all' ? 'all users' : recipientIds.length + ' selected users'));
    res.status(201).json({ success: true, announcement });
  } catch (error) {
    console.error('Create announcement:', error.stack || error.message);
    res.status(500).json({ success: false, message: 'Failed to send announcement' });
  }
});

app.patch('/api/admin/announcements/:id/status', auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ success: false, message: 'Invalid announcement id' });
    if (typeof req.body?.active !== 'boolean') return res.status(400).json({ success: false, message: 'Active status must be true or false' });
    const announcement = await Announcement.findById(req.params.id);
    if (!announcement) return res.status(404).json({ success: false, message: 'Announcement not found' });
    if (!isSuperAdmin(req)) {
      const ids = await getScopedUserIds(req) || [];
      const allowed = announcement.createdBy === req.admin.username ||
        (announcement.audience === 'selected' && announcement.recipientIds.some(id => ids.some(own => String(own) === String(id))));
      if (!allowed) return res.status(403).json({ success: false, message: 'You cannot change this announcement' });
    }
    announcement.active = req.body.active;
    await announcement.save();
    await audit(req.admin, req.body.active ? 'ANNOUNCEMENT_ENABLE' : 'ANNOUNCEMENT_DISABLE', (req.body.active ? 'Enabled' : 'Disabled') + ' announcement ' + String(announcement._id));
    res.json({ success: true, announcement });
  } catch (error) {
    console.error('Update announcement status:', error.stack || error.message);
    res.status(500).json({ success: false, message: 'Failed to update announcement status' });
  }
});

app.delete('/api/admin/announcements/:id', auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ success: false, message: 'Invalid announcement id' });
    const announcement = await Announcement.findById(req.params.id);
    if (!announcement) return res.status(404).json({ success: false, message: 'Announcement not found' });
    if (!isSuperAdmin(req)) {
      const ids = await getScopedUserIds(req) || [];
      const allowed = announcement.createdBy === req.admin.username ||
        (announcement.audience === 'selected' && announcement.recipientIds.some(id => ids.some(own => String(own) === String(id))));
      if (!allowed) return res.status(403).json({ success: false, message: 'You cannot delete this announcement' });
    }
    await Announcement.deleteOne({ _id: announcement._id });
    await audit(req.admin, 'ANNOUNCEMENT_DELETE', 'Deleted announcement ' + String(announcement._id));
    res.json({ success: true, message: 'Announcement deleted' });
  } catch (error) {
    console.error('Delete announcement:', error.stack || error.message);
    res.status(500).json({ success: false, message: 'Failed to delete announcement' });
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({ success: true, status: 'ok' });
});

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
  const adminType = req.admin.adminType || 'superadmin';
  const isMainAdmin = adminType === 'superadmin';
  res.json({
    success: true,
    admin: {
      id: req.admin.id,
      username: req.admin.username,
      role: req.admin.role,
      adminType,
      roleLabel: isMainAdmin ? 'Main Admin' : 'Second Admin',
      displayName: isMainAdmin ? 'Owner' : String(req.admin.username || 'Second Admin')
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

app.put('/api/admin/second-admins/:id/password', auth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ success: false, message: 'Main admin only' });
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ success: false, message: 'Invalid admin id' });

    const password = String(req.body?.password ?? '');
    if (password.length < 6 || password.length > 128)
      return res.status(400).json({ success: false, message: 'Password must be 6-128 characters' });

    const account = await AdminAccount.findById(req.params.id);
    if (!account) return res.status(404).json({ success: false, message: 'Second admin not found' });
    if ((account.adminType || 'second_admin') !== 'second_admin')
      return res.status(403).json({ success: false, message: 'Only Second Admin passwords can be changed here' });

    account.passwordHash = await hashPassword(password);
    await account.save();
    await audit(req.admin, 'SECOND_ADMIN_PASSWORD_RESET', 'Reset login password for Second Admin ' + account.username);

    res.json({
      success: true,
      message: 'Second Admin password updated successfully',
      admin: { id: String(account._id), username: account.username }
    });
  } catch (error) {
    console.error('Second admin password reset:', error.message);
    res.status(500).json({ success: false, message: 'Failed to change Second Admin password' });
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

const DEFAULT_TELEGRAM_SUPPORT_URL='https://t.me/Zonguru_support';
function normalizeTelegramSupportUrl(input){
  let value=String(input||'').trim();
  if(!value)value=DEFAULT_TELEGRAM_SUPPORT_URL;
  if(/^@?[A-Za-z0-9_]{5,32}$/.test(value)) value='https://t.me/'+value.replace(/^@/,'');
  if(!/^https?:\/\//i.test(value)) value='https://'+value;
  let parsed;try{parsed=new URL(value)}catch{return null}
  if(parsed.protocol!=='https:' || !['t.me','www.t.me'].includes(parsed.hostname.toLowerCase()) || !/^\/[A-Za-z0-9_]{5,32}\/?$/.test(parsed.pathname) || parsed.search || parsed.hash)return null;
  return 'https://t.me/'+parsed.pathname.split('/').filter(Boolean)[0];
}
app.get('/api/public/telegram-support',async(req,res)=>{
  try{
    const s=await PlatformSetting.findOne({key:'telegram_support_url'}).lean();
    res.set('Cache-Control','no-store');
    res.json({success:true,url:normalizeTelegramSupportUrl(s?.value?.url)||DEFAULT_TELEGRAM_SUPPORT_URL});
  }catch(e){res.json({success:true,url:DEFAULT_TELEGRAM_SUPPORT_URL});}
});
app.get('/api/admin/events',auth,async(req,res)=>{try{const r=await fetch(BACKEND_URL+'/api/public/events',{headers:{'Cache-Control':'no-store'}});const data=await r.json().catch(()=>({}));if(!r.ok||data.success!==true)return res.status(r.status||502).json({success:false,message:data.message||'Unable to load Events content'});res.json(data)}catch(e){res.status(502).json({success:false,message:'Platform backend unavailable'})}});
app.put('/api/admin/events',auth,async(req,res)=>{try{const bridge=String(process.env.BACKEND_BRIDGE_SECRET||'');if(!bridge)return res.status(503).json({success:false,message:'Backend bridge secret is not configured'});const r=await fetch(BACKEND_URL+'/api/internal/events',{method:'PUT',headers:{'Content-Type':'application/json','x-deposit-settings-key':bridge},body:JSON.stringify(req.body||{})});const data=await r.json().catch(()=>({}));if(!r.ok||data.success!==true)return res.status(r.status||502).json({success:false,message:data.message||'Unable to save Events content'});await audit(req.admin,'EVENTS_CONTENT_UPDATE','Updated Events page content');res.json(data)}catch(e){res.status(502).json({success:false,message:'Platform backend unavailable'})}});
app.get('/api/admin/telegram-support',auth,async(req,res)=>{
  if(!isSuperAdmin(req))return res.status(403).json({success:false,message:'Main admin only'});
  try{const s=await PlatformSetting.findOne({key:'telegram_support_url'}).lean();res.json({success:true,url:normalizeTelegramSupportUrl(s?.value?.url)||DEFAULT_TELEGRAM_SUPPORT_URL})}
  catch(e){res.status(500).json({success:false,message:'Failed to load Telegram CS account'})}
});
app.put('/api/admin/telegram-support',auth,async(req,res)=>{
  if(!isSuperAdmin(req))return res.status(403).json({success:false,message:'Main admin only'});
  const url=normalizeTelegramSupportUrl(req.body?.url);
  if(!url)return res.status(400).json({success:false,message:'Enter a valid Telegram t.me username link, e.g. https://t.me/Zonguru_support'});
  try{
    await PlatformSetting.findOneAndUpdate({key:'telegram_support_url'},{$set:{value:{url},updatedAt:new Date()}},{upsert:true,new:true,setDefaultsOnInsert:true});
    await audit(req.admin,'TELEGRAM_SUPPORT_UPDATE','Updated Telegram Customer Service link to '+url);
    res.json({success:true,url,message:'Telegram CS account saved'});
  }catch(e){res.status(500).json({success:false,message:'Failed to save Telegram CS account'})}
});


const DEFAULT_PLATFORM_BRANDING={name:'Zonguru',logoDataUrl:''};
const MAX_PLATFORM_LOGO_BYTES=2*1024*1024;
function cleanPlatformBranding(value){
  const stored=value&&typeof value==='object'?value:{};
  const name=String(stored.name||DEFAULT_PLATFORM_BRANDING.name).trim().slice(0,40)||DEFAULT_PLATFORM_BRANDING.name;
  const logoDataUrl=typeof stored.logoDataUrl==='string'&&/^data:image\/(png|jpeg|webp|gif);base64,/i.test(stored.logoDataUrl)?stored.logoDataUrl:'';
  return {name,logoDataUrl};
}
app.get('/api/public/branding',async(req,res)=>{
  res.set('Cache-Control','no-store, no-cache, must-revalidate');
  try{
    const setting=await PlatformSetting.findOne({key:'platform_branding'}).lean();
    res.json({success:true,branding:cleanPlatformBranding(setting?.value)});
  }catch(error){
    console.error('Public platform branding:',error.message);
    res.json({success:true,branding:DEFAULT_PLATFORM_BRANDING});
  }
});
app.get('/api/admin/branding',auth,async(req,res)=>{
  if(!isSuperAdmin(req))return res.status(403).json({success:false,message:'Main admin only'});
  try{
    const setting=await PlatformSetting.findOne({key:'platform_branding'}).lean();
    res.set('Cache-Control','no-store');
    res.json({success:true,branding:cleanPlatformBranding(setting?.value)});
  }catch(error){
    console.error('Load platform branding:',error.message);
    res.status(500).json({success:false,message:'Failed to load platform branding'});
  }
});
app.put('/api/admin/branding',auth,async(req,res)=>{
  if(!isSuperAdmin(req))return res.status(403).json({success:false,message:'Main admin only'});
  try{
    const body=req.body&&typeof req.body==='object'?req.body:{};
    const name=String(body.name||'').trim();
    if(name.length<2||name.length>40)
      return res.status(400).json({success:false,message:'Platform name must be 2 to 40 characters'});
    const current=await PlatformSetting.findOne({key:'platform_branding'}).lean();
    let logoDataUrl=typeof body.logoDataUrl==='string'?body.logoDataUrl.trim():String(current?.value?.logoDataUrl||'');
    if(logoDataUrl){
      const match=logoDataUrl.match(/^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/]+={0,2})$/i);
      if(!match)return res.status(400).json({success:false,message:'Logo must be PNG, JPG, WEBP or GIF'});
      const bytes=Buffer.from(match[2],'base64');
      if(!bytes.length||bytes.length>MAX_PLATFORM_LOGO_BYTES)
        return res.status(400).json({success:false,message:'Logo image must be no larger than 2 MB'});
    }
    const branding={name,logoDataUrl};
    await PlatformSetting.findOneAndUpdate(
      {key:'platform_branding'},
      {$set:{value:branding,updatedAt:new Date()}},
      {upsert:true,new:true,setDefaultsOnInsert:true}
    );
    await audit(req.admin,'PLATFORM_BRANDING_UPDATE','Updated platform name and logo');
    res.set('Cache-Control','no-store');
    res.json({success:true,branding,message:'Platform branding saved'});
  }catch(error){
    console.error('Save platform branding:',error.stack||error.message);
    res.status(500).json({success:false,message:'Failed to save platform branding'});
  }
});

const DEPOSIT_ADDRESS_DEFAULTS={'USDT-TRC20':'TS3fFhpyCECAtEnV7gurRyojgKVznieun5','USDT-ERC20':'0x84a872810ab213eacb8ac8e9e962faf34cd9a72b','ETH-ERC20':'0x84a872810ab213eacb8ac8e9e962faf34cd9a72b','BTC-BTC':'176xzWWVLW5KsHoikVPatuinJJ6vMrvifW'};
app.get('/api/admin/deposit-addresses', auth, async (req,res)=>{try{if(!isSuperAdmin(req))return res.status(403).json({success:false,message:'Main admin only'});const s=await PlatformSetting.findOne({key:'deposit_addresses'}).lean();res.json({success:true,addresses:{...DEPOSIT_ADDRESS_DEFAULTS,...(s?.value||{})}})}catch(e){console.error('Load deposit addresses:',e.message);res.status(500).json({success:false,message:'Failed to load deposit addresses'})}});
app.put('/api/admin/deposit-addresses', auth, async (req,res)=>{try{if(!isSuperAdmin(req))return res.status(403).json({success:false,message:'Main admin only'});const body=req.body||{};const addresses={};for(const k of Object.keys(DEPOSIT_ADDRESS_DEFAULTS)){const v=String(body[k]??'').trim();if(!v)return res.status(400).json({success:false,message:'All deposit addresses are required.'});addresses[k]=v}const s=await PlatformSetting.findOneAndUpdate({key:'deposit_addresses'},{$set:{value:addresses,updatedAt:new Date()}},{upsert:true,new:true,setDefaultsOnInsert:true});await audit(req.admin,'DEPOSIT_ADDRESSES_UPDATE','Updated all deposit addresses');res.json({success:true,addresses:s.value})}catch(e){console.error('Save deposit addresses:',e.stack||e.message);res.status(500).json({success:false,message:'Failed to save deposit addresses'})}});


/* Admin data is handled directly against the same Zonguru MongoDB used by the platform backend.
   Keep these routes local so admin actions do not depend on a missing /api/internal bridge. */
/* Core platform data is authoritative in the deployed Zonguru backend database. */
const BACKEND_URL=String(process.env.BACKEND_URL||'https://zonguru-jack-api.onrender.com').replace(/\/$/,'');
async function proxyBackend(req,res,targetPath){
  try{
    const headers={'Content-Type':'application/json'};
    if(req.headers.authorization) headers.Authorization=req.headers.authorization;
    const bridge=String(process.env.BACKEND_BRIDGE_SECRET||'');
    if(bridge) headers['x-deposit-settings-key']=bridge;
    const opts={method:req.method,headers};
    if(!['GET','HEAD'].includes(req.method)) opts.body=JSON.stringify(req.body||{});
    const r=await fetch(BACKEND_URL+targetPath,opts);
    const text=await r.text();
    let data;try{data=JSON.parse(text)}catch{data={success:false,message:'Backend returned non-JSON response'}}
    return res.status(r.status).json(data);
  }catch(e){console.error('Backend proxy:',e.message);return res.status(502).json({success:false,message:'Main backend unavailable'});}
}
app.use('/api/admin', auth, async (req,res,next)=>{
  const p=req.path;
  const txPath=p==='/transactions' || p.startsWith('/transactions/');
  const productPath=p.startsWith('/products');
  // User and Customer Service routes are handled locally below against the
  // shared admin MongoDB. Do not proxy them to the platform backend, because
  // the platform backend does not expose the admin chat/user-control routes.
  // Transactions must stay on this server so second-admin ownership
  // checks are applied to lists and approve/reject actions. Only proof-image
  // reads are proxied to the platform backend.
  const isCore=(txPath&&(req.method==='GET'||req.method==='POST'))
    ||((req.method==='GET'||req.method==='POST')&&productPath)
    ||((req.method==='GET'||req.method==='PUT'||req.method==='PATCH'||req.method==='DELETE')&&p==='/deposit-addresses');
  const ruleMatch=p.match(/^\/users\/([^/]+)\/insufficient-balance$/);
  if(ruleMatch && (req.method==='GET' || req.method==='POST')){
    try{
      const headers={'Content-Type':'application/json'};
      if(req.headers.authorization) headers.Authorization=req.headers.authorization;
      const listResponse=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});
      const listText=await listResponse.text();let listData={};try{listData=JSON.parse(listText)}catch{}
      if(!listResponse.ok || listData.success!==true || !Array.isArray(listData.users))
        return res.status(listResponse.status||502).json({success:false,message:listData.message||'Unable to verify user in platform backend'});
      const target=listData.users.find(u=>String(u._id||u.id)===String(ruleMatch[1]) && u.role==='user');
      if(!target)return res.status(404).json({success:false,message:'User not found in platform backend'});
      if(!isSuperAdmin(req) && String(target.ownerAdminId||'')!==String(req.admin.id))
        return res.status(403).json({success:false,message:'This user is outside your invite-code scope'});
      return proxyBackend(req,res,'/api/admin'+p);
    }catch(e){console.error('Insufficient-balance proxy:',e.message);return res.status(502).json({success:false,message:'Main backend unavailable; insufficient-balance rule was not changed'});}
  }
  const spinTicketMatch=p.match(/^\/users\/([^/]+)\/lucky-spin\/tickets$/);
  if(spinTicketMatch && (req.method==='POST')){
    try{
      const headers={'Content-Type':'application/json'};if(req.headers.authorization)headers.Authorization=req.headers.authorization;
      const listResponse=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});const listText=await listResponse.text();let listData={};try{listData=JSON.parse(listText)}catch{}
      if(!listResponse.ok||listData.success!==true||!Array.isArray(listData.users))return res.status(listResponse.status||502).json({success:false,message:listData.message||'Unable to verify user in platform backend'});
      const target=listData.users.find(u=>String(u._id||u.id)===String(spinTicketMatch[1])&&u.role==='user');
      if(!target)return res.status(404).json({success:false,message:'User not found in platform backend'});
      if(!isSuperAdmin(req)&&String(target.ownerAdminId||'')!==String(req.admin.id))return res.status(403).json({success:false,message:'This user is outside your invite-code scope'});
      const result=await fetch(BACKEND_URL+'/api/admin/users/'+encodeURIComponent(spinTicketMatch[1])+'/lucky-spin/tickets',{method:'POST',headers,body:JSON.stringify(req.body||{})});
      const raw=await result.text();let data;try{data=JSON.parse(raw)}catch{data={success:false,message:'Backend returned non-JSON response'}};
      if(result.ok&&data.success===true)await audit(req.admin,'LUCKY_SPIN_TICKETS_UPDATE','Adjusted Lucky Spin tickets for '+target.username,{targetUserId:spinTicketMatch[1],delta:Number(req.body?.delta||0),freeTickets:data.freeTickets});
      return res.status(result.status).json(data);
    }catch(e){console.error('Lucky Spin ticket proxy:',e.message);return res.status(502).json({success:false,message:'Main backend unavailable; tickets were not changed'});}
  }
  const wheelSettingMatch=p.match(/^\/users\/([^/]+)\/lucky-spin\/setting$/);
  if(wheelSettingMatch && req.method==='POST'){
    try{
      const headers={'Content-Type':'application/json'};if(req.headers.authorization)headers.Authorization=req.headers.authorization;
      const listResponse=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});
      const listText=await listResponse.text();let listData={};try{listData=JSON.parse(listText)}catch{}
      if(!listResponse.ok||listData.success!==true||!Array.isArray(listData.users))return res.status(listResponse.status||502).json({success:false,message:listData.message||'Unable to verify user in platform backend'});
      const target=listData.users.find(u=>String(u._id||u.id)===String(wheelSettingMatch[1])&&u.role==='user');
      if(!target)return res.status(404).json({success:false,message:'User not found in platform backend'});
      if(!isSuperAdmin(req)&&String(target.ownerAdminId||'')!==String(req.admin.id))return res.status(403).json({success:false,message:'This user is outside your invite-code scope'});
      const result=await fetch(BACKEND_URL+'/api/admin/users/'+encodeURIComponent(wheelSettingMatch[1])+'/lucky-spin/setting',{method:'POST',headers,body:JSON.stringify(req.body||{})});
      const raw=await result.text();let data;try{data=JSON.parse(raw)}catch{data={success:false,message:'Backend returned non-JSON response'}};
      if(result.ok&&data.success===true)await audit(req.admin,'LUCKY_SPIN_SETTING_UPDATE','Updated Lucky Spin wheel setting for '+target.username,{targetUserId:wheelSettingMatch[1],mode:data.mode});
      return res.status(result.status).json(data);
    }catch(e){console.error('Lucky Spin setting proxy:',e.message);return res.status(502).json({success:false,message:'Main backend unavailable; wheel setting was not changed'});}
  }
  const passwordResetMatch=p.match(/^\/users\/([^/]+)\/reset-password$/);
  if(passwordResetMatch && req.method==='POST'){
    try{
      const headers={'Content-Type':'application/json'};
      if(req.headers.authorization) headers.Authorization=req.headers.authorization;
      const listResponse=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});
      const listText=await listResponse.text();let listData={};try{listData=JSON.parse(listText)}catch{}
      if(!listResponse.ok || listData.success!==true || !Array.isArray(listData.users))
        return res.status(listResponse.status||502).json({success:false,message:listData.message||'Unable to verify user in platform backend'});
      const target=listData.users.find(u=>String(u._id||u.id)===String(passwordResetMatch[1]) && u.role==='user');
      if(!target)return res.status(404).json({success:false,message:'User not found in platform backend'});
      if(!isSuperAdmin(req) && String(target.ownerAdminId||'')!==String(req.admin.id))
        return res.status(403).json({success:false,message:'This user is outside your invite-code scope'});
      await audit(req.admin,'USER_PASSWORD_RESET_REQUEST',`Requested platform login password reset for user ${target.username}`,{targetUserId:passwordResetMatch[1]});
      return proxyBackend(req,res,'/api/admin'+p);
    }catch(e){console.error('User password-reset proxy:',e.message);return res.status(502).json({success:false,message:'Main backend unavailable; password was not confirmed changed'});}
  }
  if(p.startsWith('/users/') && p.endsWith('/bank-accounts') && req.method==='PUT'){
    try{
      const userId=p.split('/')[2];
      const headers={'Content-Type':'application/json'};
      if(req.headers.authorization) headers.Authorization=req.headers.authorization;
      const listResponse=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});
      const listText=await listResponse.text();let listData={};try{listData=JSON.parse(listText)}catch{}
      if(!listResponse.ok || listData.success!==true || !Array.isArray(listData.users))
        return res.status(listResponse.status||502).json({success:false,message:listData.message||'Unable to verify user in platform backend'});
      const target=listData.users.find(u=>String(u._id||u.id)===String(userId) && u.role==='user');
      if(!target)return res.status(404).json({success:false,message:'User not found in platform backend'});
      if(!isSuperAdmin(req) && String(target.ownerAdminId||'')!==String(req.admin.id))
        return res.status(403).json({success:false,message:'This user is outside your invite-code scope'});
      await audit(req.admin,'USER_BANK_ACCOUNTS_UPDATE_REQUEST','Requested bank information update for '+target.username,{targetUserId:userId});
      return proxyBackend(req,res,'/api/admin'+p);
    }catch(e){
      console.error('User bank-accounts proxy:',e.stack||e.message);
      return res.status(502).json({success:false,message:'Main backend unavailable; bank information was not confirmed saved'});
    }
  }
  if(!isCore) return next();
  if(p==='/deposit-addresses'){
    if(req.method==='GET') return proxyBackend(req,res,'/api/public/deposit-addresses');
    return proxyBackend(req,res,'/api/internal/deposit-addresses');
  }
  // Read legacy transaction/chat records from both the Admin DB and the
  // deployed platform backend. This preserves older records if they were
  // written before the two services were separated.
  if(req.method==='GET' && p==='/chat-users'){
    try{
      const headers={'Content-Type':'application/json'};
      if(req.headers.authorization) headers.Authorization=req.headers.authorization;
      const r=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});
      const text=await r.text(); let remote={}; try{remote=JSON.parse(text)}catch{}
      const remoteUsers=Array.isArray(remote.users)?remote.users:[];
      const localUsers=await User.find(scopedUserFilter(req)).select('-passwordHash').sort({createdAt:-1}).lean();
      const merged=[...remoteUsers,...localUsers],seen=new Set();
      const users=merged.filter(u=>{const id=String(u._id||u.id||'');if(!id||seen.has(id))return false;seen.add(id);return true;});
      return res.json({success:true,users});
    }catch(e){
      const users=await User.find(scopedUserFilter(req)).select('-passwordHash').sort({createdAt:-1}).lean();
      return res.json({success:true,users});
    }
  }
  if(req.method==='POST' && p.startsWith('/users/') && p.endsWith('/task-reset')){
    try{
      const id=p.split('/')[2];
      const headers={'Content-Type':'application/json'};
      if(req.headers.authorization) headers.Authorization=req.headers.authorization;
      const list=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});
      const body=await list.text(); let data={}; try{data=JSON.parse(body)}catch{}
      const user=(Array.isArray(data.users)?data.users:[]).find(u=>String(u._id||u.id)===String(id));
      if(!user)return res.status(404).json({success:false,message:'User not found'});
      const r=await fetch(BACKEND_URL+'/api/admin/users/'+id+'/vip',{method:'POST',headers,body:JSON.stringify({vipLevel:Number(user.vipLevel||0)})});
      const text=await r.text(); let out; try{out=JSON.parse(text)}catch{out={success:false,message:'Backend returned non-JSON response'}}
      return res.status(r.status).json(r.ok?{...out,taskReset:true,message:'Task reset to 0. Previous orders and profits were preserved.'}:out);
    }catch(e){return res.status(502).json({success:false,message:'Main backend unavailable'});}
  }
  if(req.method==='GET' && p==='/transactions'){
    try{
      const headers={'Content-Type':'application/json'};
      if(req.headers.authorization) headers.Authorization=req.headers.authorization;
      const [r,userResponse]=await Promise.all([
        fetch(BACKEND_URL+'/api/admin/transactions',{method:'GET',headers}),
        fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers})
      ]);
      const [txText,userText]=await Promise.all([r.text(),userResponse.text()]);
      let remote={},userData={};try{remote=JSON.parse(txText)}catch{}try{userData=JSON.parse(userText)}catch{}
      if(!r.ok||remote.success!==true||!Array.isArray(remote.transactions))
        return res.status(r.status||502).json({success:false,message:remote.message||'Unable to load transactions from platform backend'});
      if(!userResponse.ok||userData.success!==true||!Array.isArray(userData.users))
        return res.status(userResponse.status||502).json({success:false,message:userData.message||'Unable to verify transaction ownership'});
      const visibleUsers=userData.users.filter(u=>u.role==='user'&&(isSuperAdmin(req)||String(u.ownerAdminId||'')===String(req.admin.id)));
      const visibleIds=new Set(visibleUsers.map(u=>String(u._id||u.id)));
      const remoteRows=remote.transactions.filter(t=>isSuperAdmin(req)||visibleIds.has(String(t.userId?._id||t.userId||'')));
      const local=await Transaction.find(isSuperAdmin(req)?{}:{userId:{$in:[...visibleIds]}}).sort({createdAt:-1}).limit(500).lean();

      // The Admin service may still contain legacy copies of transactions that
      // are now served by the platform backend. Their Mongo IDs can differ even
      // when they represent the same user submission. Keep the platform copy
      // and suppress only matching cross-database legacy copies; never collapse
      // two rows that both came from the same source.
      const transactionType=t=>{
        const type=String(t?.type||'').trim().toLowerCase();
        return type==='withdraw'?'withdrawal':type;
      };
      const canonicalValue=value=>{
        if(Array.isArray(value))return value.map(canonicalValue);
        if(value&&typeof value==='object'){
          return Object.keys(value).sort().reduce((out,key)=>{out[key]=canonicalValue(value[key]);return out;},{});
        }
        return value;
      };
      const stableDetails=t=>{
        const value=t?.details;
        if(!value||typeof value!=='object')return '';
        return JSON.stringify(canonicalValue(value));
      };
      const isLegacyCopyOfRemote=(legacy,current)=>{
        const legacyId=String(legacy?._id||legacy?.id||'');
        const currentId=String(current?._id||current?.id||'');
        if(legacyId&&currentId&&legacyId===currentId)return true;

        const legacyUser=String(legacy?.userId?._id||legacy?.userId||'');
        const currentUser=String(current?.userId?._id||current?.userId||'');
        if(!legacyUser||legacyUser!==currentUser)return false;
        if(transactionType(legacy)!==transactionType(current))return false;

        const legacyAmount=Number(legacy?.amount),currentAmount=Number(current?.amount);
        if(!Number.isFinite(legacyAmount)||!Number.isFinite(currentAmount)||
           Math.round(legacyAmount*100)!==Math.round(currentAmount*100))return false;
        const legacyCurrency=String(legacy?.currency||'USDT').trim().toUpperCase();
        const currentCurrency=String(current?.currency||'USDT').trim().toUpperCase();
        if(legacyCurrency!==currentCurrency)return false;

        const legacyTime=new Date(legacy?.createdAt||0).getTime();
        const currentTime=new Date(current?.createdAt||0).getTime();
        if(!Number.isFinite(legacyTime)||!Number.isFinite(currentTime)||!legacyTime||!currentTime||
           Math.abs(legacyTime-currentTime)>15000)return false;

        const legacyMethod=String(legacy?.method||'').trim().toLowerCase();
        const currentMethod=String(current?.method||'').trim().toLowerCase();
        if(legacyMethod&&currentMethod&&legacyMethod!==currentMethod)return false;

        const legacyDetails=stableDetails(legacy),currentDetails=stableDetails(current);
        if(legacyDetails&&currentDetails&&legacyDetails!==currentDetails)return false;

        const legacyProof=String(legacy?.proofImage||legacy?.details?.proofImage||legacy?.details?.screenshot||'');
        const currentProof=String(current?.proofImage||current?.details?.proofImage||current?.details?.screenshot||'');
        if(legacyProof&&currentProof&&legacyProof!==currentProof)return false;

        const legacyDebit=Number(legacy?.debitedAmount||0),currentDebit=Number(current?.debitedAmount||0);
        if(legacyDebit>0&&currentDebit>0&&Math.round(legacyDebit*100)!==Math.round(currentDebit*100))return false;
        const legacyDebitCurrency=String(legacy?.debitedCurrency||'').trim().toUpperCase();
        const currentDebitCurrency=String(current?.debitedCurrency||'').trim().toUpperCase();
        if(legacyDebitCurrency&&currentDebitCurrency&&legacyDebitCurrency!==currentDebitCurrency)return false;

        return true;
      };
      const legacyOnly=local.filter(legacy=>!remoteRows.some(current=>isLegacyCopyOfRemote(legacy,current)));
      const transactions=[...remoteRows,...legacyOnly]
        .sort((a,b)=>new Date(b.createdAt||0)-new Date(a.createdAt||0)).slice(0,500);
      return res.json({success:true,transactions});
    }catch(e){
      console.error('Load transactions from platform backend:',e.message);
      return res.status(502).json({success:false,message:'Unable to load current platform transactions'});
    }
  }
if(txPath&&req.method==='POST'&&(p.endsWith('/approve')||p.endsWith('/reject'))){
    try{
      const headers={'Content-Type':'application/json'};
      if(req.headers.authorization)headers.Authorization=req.headers.authorization;
      const id=p.split('/')[2];
      const [r,userResponse]=await Promise.all([
        fetch(BACKEND_URL+'/api/admin/transactions',{method:'GET',headers}),
        fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers})
      ]);
      const [txText,userText]=await Promise.all([r.text(),userResponse.text()]);
      let remote={},userData={};try{remote=JSON.parse(txText)}catch{}try{userData=JSON.parse(userText)}catch{}
      if(!r.ok||!Array.isArray(remote.transactions)||!userResponse.ok||!Array.isArray(userData.users))
        return res.status(502).json({success:false,message:'Unable to verify this transaction with the platform backend'});
      const transaction=remote.transactions.find(t=>String(t._id||t.id)===id);
      if(!transaction)return res.status(404).json({success:false,message:'Transaction not found in platform backend'});
      const user=userData.users.find(u=>String(u._id||u.id)===String(transaction.userId?._id||transaction.userId||''));
      if(!user||user.role!=='user'||(!isSuperAdmin(req)&&String(user.ownerAdminId||'')!==String(req.admin.id)))
        return res.status(403).json({success:false,message:'This transaction is outside your admin scope'});
      return proxyBackend(req,res,'/api/admin'+p);
    }catch(e){
      console.error('Review platform transaction:',e.message);
      return res.status(502).json({success:false,message:'Unable to review transaction with the platform backend'});
    }
  }
  if(req.method==='GET' && p.startsWith('/chat/')){
    try{
      const userId=p.split('/')[2];
      const headers={'Content-Type':'application/json'};
      if(req.headers.authorization) headers.Authorization=req.headers.authorization;
      const r=await fetch(BACKEND_URL+p,{method:'GET',headers});
      const text=await r.text(); let remote={}; try{remote=JSON.parse(text)}catch{}
      const local=await Message.find({userId}).sort({createdAt:1}).lean();
      const merged=[...(Array.isArray(remote.messages)?remote.messages:[]),...local];
      const seen=new Set();
      const messages=merged.filter(m=>{
        const key=String(m._id||'')+'|'+String(m.userId||'')+'|'+String(m.createdAt||'')+'|'+String(m.sender||'')+'|'+String(m.text||'');
        if(seen.has(key))return false; seen.add(key); return true;
      }).sort((a,b)=>new Date(a.createdAt||0)-new Date(b.createdAt||0));
      return res.status(r.ok?200:r.status).json({success:r.ok||messages.length>0,messages});
    }catch(e){
      const messages=await Message.find({userId:p.split('/')[2]}).sort({createdAt:1});
      return res.json({success:true,messages});
    }
  }
  return proxyBackend(req,res,'/api/admin'+p);
});



app.post('/api/admin/notifications',auth,async(req,res)=>{
  try{
    const headers={'Content-Type':'application/json'};if(req.headers.authorization)headers.Authorization=req.headers.authorization;
    const response=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});
    const raw=await response.text();let data={};try{data=JSON.parse(raw)}catch{}
    if(!response.ok||data.success!==true||!Array.isArray(data.users))return res.status(response.status||502).json({success:false,message:data.message||'Unable to verify notification recipients'});
    let allowed=data.users.filter(u=>u.role==='user');if(!isSuperAdmin(req))allowed=allowed.filter(u=>String(u.ownerAdminId||'')===String(req.admin.id));
    const requested=String(req.body?.target||'all'),ids=requested==='all'?allowed.map(u=>String(u._id||u.id)):Array.isArray(req.body?.userIds)?req.body.userIds.map(String):[];
    const valid=ids.filter(id=>allowed.some(u=>String(u._id||u.id)===id));
    if(!valid.length)return res.status(400).json({success:false,message:'No eligible users selected for this admin scope'});
    const body={...(req.body||{}),target:'selected',userIds:valid};
    const r=await fetch(BACKEND_URL+'/api/admin/notifications',{method:'POST',headers,body:JSON.stringify(body)});
    const rawResult=await r.text();let result={};try{result=JSON.parse(rawResult)}catch{}
    return res.status(r.status).json(result);
  }catch(e){console.error('Admin notification proxy:',e.message);return res.status(502).json({success:false,message:'Main backend unavailable; notification was not sent'});}
});

app.get('/api/admin/bonuses',auth,async(req,res)=>{
  return proxyBackend(req,res,'/api/admin/bonuses');
});
app.post('/api/admin/bonuses',auth,async(req,res)=>{
  try{
    const headers={'Content-Type':'application/json'};if(req.headers.authorization)headers.Authorization=req.headers.authorization;
    const response=await fetch(BACKEND_URL+'/api/admin/users',{method:'GET',headers});
    const raw=await response.text();let data={};try{data=JSON.parse(raw)}catch{}
    if(!response.ok||data.success!==true||!Array.isArray(data.users))return res.status(response.status||502).json({success:false,message:data.message||'Unable to verify bonus recipients'});
    let allowed=data.users.filter(u=>u.role==='user');
    if(!isSuperAdmin(req))allowed=allowed.filter(u=>String(u.ownerAdminId||'')===String(req.admin.id));
    const requested=String(req.body?.target||'all');
    const ids=requested==='all'?allowed.map(u=>String(u._id||u.id)):Array.isArray(req.body?.userIds)?req.body.userIds.map(String):[];
    const valid=ids.filter(id=>allowed.some(u=>String(u._id||u.id)===id));
    if(!valid.length)return res.status(400).json({success:false,message:'No eligible users selected for this admin scope'});
    const body={...(req.body||{}),target:'selected',userIds:valid};
    const r=await fetch(BACKEND_URL+'/api/admin/bonuses',{method:'POST',headers,body:JSON.stringify(body)});
    const rawResult=await r.text();let result={};try{result=JSON.parse(rawResult)}catch{}
    return res.status(r.status).json(result);
  }catch(e){console.error('Bonus admin proxy:',e.message);return res.status(502).json({success:false,message:'Main backend unavailable; bonus was not sent'});}
});

app.get('/api/admin/users', auth, async (req, res) => {
  try {
    // User accounts and their balances are authoritative in the platform backend.
    // Never display the admin server's potentially stale local copy as the balance source.
    const headers = { 'Content-Type': 'application/json' };
    if (req.headers.authorization) headers.Authorization = req.headers.authorization;
    const remote = await fetch(BACKEND_URL + '/api/admin/users', { method: 'GET', headers });
    const rawText = await remote.text();
    let result;
    try { result = JSON.parse(rawText); }
    catch { result = { success: false, message: 'Backend returned non-JSON response' }; }
    if (!remote.ok || result.success !== true || !Array.isArray(result.users)) {
      return res.status(remote.status || 502).json({
        success: false,
        message: result.message || 'Unable to load authoritative users from platform backend'
      });
    }
    let users = result.users.filter(user =>
      user.role === 'user' &&
      (isSuperAdmin(req) || String(user.ownerAdminId || '') === String(req.admin.id))
    );
    // Only Main Admin receives the originating Second Admin name.
    if (isSuperAdmin(req)) {
      const ownerIds = [...new Set(users.map(u => String(u.ownerAdminId || '')).filter(Boolean))];
      const owners = ownerIds.length
        ? await AdminAccount.find({ _id: { $in: ownerIds } }).select('username').lean()
        : [];
      const ownerNames = new Map(owners.map(a => [String(a._id), a.username]));
      users = users.map(user => ({
        ...user,
        secondAdminName: ownerNames.get(String(user.ownerAdminId || '')) || user.ownerAdminUsername || ''
      }));
    }
    return res.json({ success: true, users, source: 'platform-backend' });
  } catch (error) {
    console.error('Load users from platform backend:', error.message);
    return res.status(502).json({ success: false, message: 'Main backend unavailable; user balances were not loaded from a stale copy' });
  }
});

const ADMIN_CURRENCY_RATES={USDT:1,USD:1,MXN:18.5,EUR:0.86,GBP:0.75,CAD:1.38,AUD:1.51,JPY:148,CNY:7.1,SGD:1.28,THB:32.5,MYR:4.25,BRL:5.35,INR:88,EGP:51.75};
function adminCurrency(v){const c=String(v||'USDT').trim().toUpperCase();return Object.prototype.hasOwnProperty.call(ADMIN_CURRENCY_RATES,c)?c:'USDT'}
function toUSDT(amount,currency){const c=adminCurrency(currency);return Number(amount||0)/(ADMIN_CURRENCY_RATES[c]||1)}
async function adjustBalance(req, res) {
  try {
    const rawDelta = Number(req.body.amount ?? req.body.delta);
    if (!Number.isFinite(rawDelta) || rawDelta === 0) {
      return res.status(400).json({ success: false, message: 'Enter a non-zero balance change' });
    }
    const inputCurrency = adminCurrency(req.body.currency || 'USDT');
    const headers = { 'Content-Type': 'application/json' };
    if (req.headers.authorization) headers.Authorization = req.headers.authorization;

    // Confirm the selected account exists in the authoritative backend and
    // enforce the second-admin ownership boundary before changing its balance.
    const listResponse = await fetch(BACKEND_URL + '/api/admin/users', { method: 'GET', headers });
    const listText = await listResponse.text();
    let listResult;
    try { listResult = JSON.parse(listText); }
    catch { listResult = { success: false, message: 'Backend returned non-JSON response' }; }
    if (!listResponse.ok || listResult.success !== true || !Array.isArray(listResult.users)) {
      return res.status(listResponse.status || 502).json({
        success: false,
        message: listResult.message || 'Unable to verify user in platform backend; balance was not changed'
      });
    }
    const target = listResult.users.find(user => String(user._id || user.id) === String(req.params.id) && user.role === 'user');
    if (!target) return res.status(404).json({ success: false, message: 'User not found in platform backend' });
    if (!isSuperAdmin(req) && String(target.ownerAdminId || '') !== String(req.admin.id)) {
      return res.status(403).json({ success: false, message: 'This user is outside your invite-code scope' });
    }

    const remote = await fetch(BACKEND_URL + '/api/admin/users/' + encodeURIComponent(req.params.id) + '/balance', {
      method: 'POST',
      headers,
      body: JSON.stringify({ amount: rawDelta, currency: inputCurrency })
    });
    const rawText = await remote.text();
    let result;
    try { result = JSON.parse(rawText); }
    catch { result = { success: false, message: 'Backend returned non-JSON response' }; }

    if (!remote.ok || result.success !== true) {
      return res.status(remote.status || 502).json({
        success: false,
        message: result.message || 'The platform backend did not confirm the balance update. No balance was changed by the admin server.'
      });
    }

    const usdtDelta = Number(result.amount ?? result.conversion?.usdtAmount ?? toUSDT(rawDelta, inputCurrency));
    const newBalance = Number(result.newBalance ?? result.balances?.USDT ?? result.user?.balances?.USDT ?? result.user?.balance ?? 0);
    const targetId = result.user?.id || result.user?._id || target._id;
    await audit(req.admin, usdtDelta > 0 ? 'BALANCE_ADD' : 'BALANCE_SUBTRACT',
      `${usdtDelta > 0 ? '+' : ''}${usdtDelta.toFixed(2)} USDT primary balance; input ${rawDelta.toFixed(2)} ${inputCurrency}; backend-confirmed balance ${newBalance.toFixed(2)} USDT`,
      { targetUserId: targetId });

    return res.json({
      ...result,
      success: true,
      conversion: { inputAmount: rawDelta, inputCurrency, usdtAmount: usdtDelta },
      source: 'platform-backend'
    });
  } catch (error) {
    console.error('Balance update proxy:', error.message);
    return res.status(502).json({
      success: false,
      message: 'Main backend unavailable. The balance was not changed by the admin server; check the user account before retrying.'
    });
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

app.post('/api/admin/users/:id/currency', auth, async (req, res) => {
  try {
    const currency = String(req.body?.currency || 'USDT').trim().toUpperCase();
    if (!['USDT','BTC','ETH'].includes(currency))
      return res.status(400).json({ success:false, message:'Currency must be USDT, BTC or ETH' });
    const user = await findScopedUser(req, req.params.id);
    if (!user) return res.status(404).json({ success:false, message:'User not found' });
    user.currency = currency;
    await user.save();
    await audit(req.admin, 'USER_CURRENCY_UPDATE', 'Currency changed to ' + currency, { targetUserId:user._id });
    res.json({ success:true, user:cleanUser(user) });
  } catch (error) {
    console.error('Currency update:', error.message);
    res.status(500).json({ success:false, message:'Currency update failed' });
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

app.get('/api/admin/users/:id/history', auth, async (req,res)=>{
 try{
  const user=await findScopedUser(req,req.params.id);
  if(!user)return res.status(404).json({success:false,message:'User not found'});
  const [txs,audits,activity]=await Promise.all([
   Transaction.find({userId:user._id}).sort({createdAt:-1}).limit(500).lean(),
   Audit.find({targetUserId:user._id}).sort({createdAt:-1}).limit(500).lean(),
   AdminActivity.find({userId:user._id,eventType:{$in:['register','login']}}).sort({createdAt:-1}).limit(500).lean()
  ]);
  const history=[...txs.map(t=>({createdAt:t.createdAt,type:t.type,amount:t.amount,status:t.status,note:t.note||''})),...audits.map(x=>({createdAt:x.createdAt,type:x.action,amount:0,status:'audit',details:x.details||''}))].sort((x,y)=>new Date(y.createdAt)-new Date(x.createdAt));
  const registrations=activity.filter(x=>x.eventType==='register').sort((x,y)=>new Date(x.createdAt)-new Date(y.createdAt));
  const logins=activity.filter(x=>x.eventType==='login');
  const latestLogin=logins[0]||null;
  const registration=registrations[0]||null;
  res.set('Cache-Control','no-store');
  res.json({success:true,user:{id:user._id,username:user.username,balance:Number(user.balance||0)},history,
   accessInfo:{register:{date:registration?.createdAt||null,ip:registration?.ip||null,device:registration?.device||null},
    latestLogin:latestLogin?{date:latestLogin.createdAt,ip:latestLogin.ip||null,device:latestLogin.device||null}:null,
    loginHistory:logins.map(x=>({date:x.createdAt,ip:x.ip||null,device:x.device||null}))}});
 }catch(e){console.error('User history:',e.message);res.status(500).json({success:false,message:'Failed to load user history'})}
});

app.get('/api/admin/dashboard/income', auth, async (req, res) => {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (req.headers.authorization) headers.Authorization = req.headers.authorization;
    const remote = await fetch(BACKEND_URL + '/api/admin/dashboard/income', { method: 'GET', headers });
    const rawText = await remote.text();
    let result;
    try { result = JSON.parse(rawText); }
    catch { result = { success: false, message: 'Backend returned non-JSON response' }; }
    if (!remote.ok || result.success !== true) {
      return res.status(remote.status || 502).json({
        success: false,
        message: result.message || 'Unable to load dashboard summary from platform backend'
      });
    }
    const scopedIds = await getScopedUserIds(req);
    const allowed = scopedIds ? new Set(scopedIds.map(id => String(id))) : null;
    const scopedRows = rows => (Array.isArray(rows) ? rows : []).filter(row =>
      !allowed || allowed.has(String(row.userId || ''))
    );
    const sumRows = (rows, predicate = () => true) => scopedRows(rows).reduce((sum, row) => {
      if (!predicate(row)) return sum;
      const amount = Number(row.amountUSDT || 0);
      return sum + (Number.isFinite(amount) && amount > 0 ? amount : 0);
    }, 0);
    const allTime = scopedRows(result.allTimeTransactionsByUser);
    const monthly = scopedRows(result.monthlyTransactionsByUser);
    const dailyMap = new Map();
    for (const row of scopedRows(result.dailyDepositsByUser)) {
      const amount = Number(row.amountUSDT || 0);
      if (Number.isFinite(amount) && amount > 0) dailyMap.set(row.day, (dailyMap.get(row.day) || 0) + amount);
    }
    const typeIs = (row, type) => String(row.type || '').toLowerCase() === type;
    res.set('Cache-Control', 'no-store');
    return res.json({
      success: true,
      currentMonthIncomeUSDT: Number(sumRows(result.currentMonthByUser).toFixed(2)),
      previousMonthIncomeUSDT: Number(sumRows(result.previousMonthByUser).toFixed(2)),
      totalDepositUSDT: Number(sumRows(allTime, row => typeIs(row, 'deposit')).toFixed(2)),
      totalWithdrawalUSDT: Number(sumRows(allTime, row => ['withdrawal', 'withdraw'].some(type => typeIs(row, type))).toFixed(2)),
      currentMonthDepositUSDT: Number(sumRows(monthly, row => typeIs(row, 'deposit') && row.period === 'current').toFixed(2)),
      previousMonthDepositUSDT: Number(sumRows(monthly, row => typeIs(row, 'deposit') && row.period === 'previous').toFixed(2)),
      currentMonthWithdrawalUSDT: Number(sumRows(monthly, row => ['withdrawal', 'withdraw'].some(type => typeIs(row, type)) && row.period === 'current').toFixed(2)),
      previousMonthWithdrawalUSDT: Number(sumRows(monthly, row => ['withdrawal', 'withdraw'].some(type => typeIs(row, type)) && row.period === 'previous').toFixed(2)),
      dailyDeposits: [...dailyMap.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([day, amountUSDT]) => ({ day, amountUSDT: Number(amountUSDT.toFixed(2)) })),
      estimatedLegacyOrders: isSuperAdmin(req) ? Number(result.estimatedLegacyOrders || 0) : null,
      currentMonthStart: result.currentMonthStart || null,
      previousMonthStart: result.previousMonthStart || null
    });
  } catch (error) {
    console.error('Dashboard financial summary proxy:', error.message);
    return res.status(502).json({ success: false, message: 'Unable to load dashboard financial summary' });
  }
});

app.get('/api/admin/transactions', auth, async (req, res) => {
  try {
    const userIds = await getScopedUserIds(req);
    const filter = userIds ? { userId: { $in: userIds } } : {};
    const transactions = await Transaction.find(filter).sort({ createdAt: -1 }).limit(500);
    res.json({ success: true, transactions });
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
    const currency = adminCurrency(transaction.currency || 'USDT');
    const type = String(transaction.type || '').toLowerCase();
    if (!Number.isFinite(amount) || amount <= 0)
      return res.status(400).json({ success: false, message: 'Invalid transaction amount' });

    if (!user.balances || typeof user.balances !== 'object' || Array.isArray(user.balances)) user.balances = {};

    if (type === 'deposit') {
      const current = Number(user.balances[currency] || 0);
      user.balances[currency] = Number((current + amount).toFixed(2));
    } else if (type === 'withdraw' || type === 'withdrawal') {
      // New withdrawals are already reserved/debited when the user submits.
      // Approve must NOT deduct again.
      if (!transaction.reserved) {
        const debitCurrency = adminCurrency(transaction.debitedCurrency || currency);
        const debitAmount = Number(transaction.debitedAmount || amount);
        const current = Number(user.balances[debitCurrency] || 0);
        if (current < debitAmount)
          return res.status(400).json({ success: false, message: 'User balance is insufficient', currency: debitCurrency });
        user.balances[debitCurrency] = Number((current - debitAmount).toFixed(2));
      }
    } else {
      return res.status(400).json({ success: false, message: 'Unsupported transaction type' });
    }

    if (type === 'deposit') {
      // Keep the primary legacy field synchronized only for USDT deposits.
      if (currency === 'USDT') user.balance = Number(user.balances.USDT || 0);
    } else if ((transaction.debitedCurrency || currency) === 'USDT') {
      user.balance = Number(user.balances.USDT || 0);
    }

    transaction.status = 'approved';
    transaction.reviewedAt = new Date();
    await user.save();
    await transaction.save();

    const label = amount.toFixed(2) + ' ' + currency;
    await Message.create({
      userId: user._id, subject: 'Customer Service', sender: 'admin',
      text: type === 'deposit'
        ? 'Deposit request approved: ' + label + ' was added to your balance.'
        : 'Withdrawal request approved: ' + label + ' was processed.',
      read: false
    });
    await audit(req.admin, 'TRANSACTION_APPROVE',
      type + ' ' + label + (transaction.reserved ? ' (withdrawal already reserved)' : ''),
      { targetUserId: user._id, targetTransactionId: transaction._id });
    res.json({ success: true, message: 'Transaction approved', currency, amount });
  } catch (error) {
    console.error('Approve transaction:', error.stack || error.message);
    res.status(500).json({ success: false, message: 'Transaction approval failed' });
  }
});

app.post('/api/admin/transactions/:id/reject', auth, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction || transaction.status !== 'pending')
      return res.status(400).json({ success: false, message: 'Transaction is not pending' });
    const user = await findScopedUser(req, transaction.userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found or not assigned to this admin' });

    const reason = String(req.body.reason ?? req.body.note ?? '').trim();
    if (!reason) return res.status(400).json({ success: false, message: 'Rejection reason is required' });

    const type = String(transaction.type || '').toLowerCase();
    const currency = adminCurrency(transaction.currency || 'USDT');
    const amount = Number(transaction.amount || 0);

    if (!user.balances || typeof user.balances !== 'object' || Array.isArray(user.balances)) user.balances = {};

    if ((type === 'withdraw' || type === 'withdrawal') && transaction.reserved) {
      const refundCurrency = adminCurrency(transaction.debitedCurrency || currency);
      const refundAmount = Number(transaction.debitedAmount || amount);
      user.balances[refundCurrency] = Number((Number(user.balances[refundCurrency] || 0) + refundAmount).toFixed(2));
      if (refundCurrency === 'USDT') user.balance = Number(user.balances.USDT || 0);
    }

    transaction.status = 'rejected';
    transaction.rejectionReason = reason;
    transaction.note = reason;
    transaction.reviewedAt = new Date();
    await user.save();
    await transaction.save();

    const refundText = (type === 'withdraw' || type === 'withdrawal') && transaction.reserved
      ? ' Your submitted amount was returned to your ' + adminCurrency(transaction.debitedCurrency || currency) + ' balance.'
      : '';
    await Message.create({
      userId: user._id, subject: 'Customer Service', sender: 'admin',
      text: (type === 'deposit' ? 'Deposit request rejected.' : 'Withdrawal request rejected.') +
        ' Reason: ' + reason + refundText,
      read: false
    });
    await audit(req.admin, 'TRANSACTION_REJECT',
      type + ' ' + amount.toFixed(2) + ' ' + currency + ' - ' + reason,
      { targetUserId: user._id, targetTransactionId: transaction._id });
    res.json({ success: true, message: 'Transaction rejected', reason, refunded: type === 'withdraw' || type === 'withdrawal' ? Boolean(transaction.reserved) : false });
  } catch (error) {
    console.error('Reject transaction:', error.stack || error.message);
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

// Start HTTP immediately so Render health checks can succeed even while MongoDB connects.
const server = app.listen(PORT, () => console.log(`Zonguru admin server running on port ${PORT}`));

mongoose.connect(MONGO_URL)
  .then(() => {
    console.log('MongoDB connected successfully');
  })
  .catch(error => {
    console.error('MongoDB connection failed:', error.message);
    // Keep the HTTP server alive for Render health checks; database-dependent
    // requests will return their normal error responses until MongoDB recovers.
  });

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});
