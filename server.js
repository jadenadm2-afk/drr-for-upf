const express = require('express');
const path = require('path');
const { Sequelize, DataTypes, Op } = require('sequelize');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'upf-secure-jwt-key-2026-zalingei-council-secret-token';

// ═══════════════════════════════════════════════════════
// SECURITY HARDENING MIDDLEWARES
// ═══════════════════════════════════════════════════════
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { ok: false, error: 'تم حظر محاولات الدخول مؤقتاً لكثرة المحاولات الخاطئة. الرجاء المحاولة بعد 15 دقيقة.' },
  standardHeaders: true,
  legacyHeaders: false
});

const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 35,
  message: { ok: false, error: 'تم استقبال عدد كبير من الاستمارات من هذا الجهاز. يرجى الانتظار قليلاً.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// ═══════════════════════════════════════════════════════
// SEQUELIZE DATABASE INITIALIZATION
// ═══════════════════════════════════════════════════════
const databaseUrl = process.env.DATABASE_URL;
let sequelize;

if (databaseUrl) {
  console.log('Connecting to PostgreSQL via DATABASE_URL...');
  const isLocalhost = databaseUrl.includes('localhost') || databaseUrl.includes('127.0.0.1');
  sequelize = new Sequelize(databaseUrl, {
    dialect: 'postgres',
    dialectOptions: isLocalhost ? {} : {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    },
    logging: false
  });
} else {
  console.log('No DATABASE_URL set. Using local SQLite database as fallback...');
  sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: path.join(__dirname, 'database.sqlite'),
    logging: false
  });
}

// ═══════════════════════════════════════════════════════
// SEQUELIZE MODELS
// ═══════════════════════════════════════════════════════
const Member = sequelize.define('Member', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  full_name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  nickname: { type: DataTypes.STRING },
  college: { type: DataTypes.STRING },
  specialization: { type: DataTypes.STRING },
  date_of_birth: { type: DataTypes.STRING },
  place_of_birth: { type: DataTypes.STRING },
  current_residence: { type: DataTypes.STRING },
  state: { type: DataTypes.STRING },
  region: { type: DataTypes.STRING },
  locality: { type: DataTypes.STRING },
  phone: { type: DataTypes.STRING },
  email: { type: DataTypes.STRING },
  photo_base64: { type: DataTypes.TEXT },
  organizational_role: { type: DataTypes.STRING },
  join_date: { type: DataTypes.STRING },
  executive_sector: { type: DataTypes.STRING },
  first_sector: { type: DataTypes.STRING },
  current_sector: { type: DataTypes.STRING },
  membership_status: {
    type: DataTypes.STRING,
    defaultValue: 'pending'
  },
  last_record_update: { type: DataTypes.STRING },
  notes: { type: DataTypes.TEXT }
}, {
  tableName: 'members',
  timestamps: true
});

// System Users Model with Roles ('admin' and 'viewer')
const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  username: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  },
  role: {
    type: DataTypes.STRING, // 'admin' or 'viewer'
    allowNull: false,
    defaultValue: 'viewer'
  },
  display_name: {
    type: DataTypes.STRING
  }
}, {
  tableName: 'users',
  timestamps: true
});

function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/<[^>]*>?/gm, '').trim();
}

// ═══════════════════════════════════════════════════════
// AUTHENTICATION & ROLE MIDDLEWARES
// ═══════════════════════════════════════════════════════
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ ok: false, error: 'غير مصرح: يجب تسجيل الدخول أولاً' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.user;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: 'انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.userRole !== 'admin') {
      return res.status(403).json({
        ok: false,
        error: 'صلاحية مرفوضة: حسابك يمتلك صلاحية المشاهدة فقط (Read-only) ولا يمكنه تعديل أو حذف البيانات.'
      });
    }
    next();
  });
}

// ═══════════════════════════════════════════════════════
// SEED DEFAULT USERS (ADMIN & VIEWER)
// ═══════════════════════════════════════════════════════
async function initSystemUsers() {
  try {
    const adminExists = await User.findOne({ where: { username: 'admin' } });
    if (!adminExists) {
      const hashedAdminPass = bcrypt.hashSync('upf@2026', 10);
      await User.create({
        username: 'admin',
        password: hashedAdminPass,
        role: 'admin',
        display_name: 'المسؤول التنفيذي الكامل'
      });
      console.log('✅ Default Admin account created: admin / upf@2026');
    }

    const viewerExists = await User.findOne({ where: { username: 'viewer' } });
    if (!viewerExists) {
      const hashedViewerPass = bcrypt.hashSync('view@2026', 10);
      await User.create({
        username: 'viewer',
        password: hashedViewerPass,
        role: 'viewer',
        display_name: 'مشاهد (صلاحية عرض وطباعة فقط)'
      });
      console.log('✅ Default Viewer account created: viewer / view@2026');
    }
  } catch (err) {
    console.error('Error seeding users:', err);
  }
}

// ═══════════════════════════════════════════════════════
// REST API ROUTES
// ═══════════════════════════════════════════════════════

// Status / Health check (Public)
app.get('/api/status', async (req, res) => {
  try {
    await sequelize.authenticate();
    const count = await Member.count();
    const dialect = sequelize.getDialect();
    res.json({
      ok: true,
      dialect: dialect === 'postgres' ? 'PostgreSQL' : 'SQLite',
      isPostgres: dialect === 'postgres',
      membersCount: count
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'خطأ في الاتصال بقاعدة البيانات' });
  }
});

// Submit Member Registration Form (Public)
app.post('/api/members', registrationLimiter, async (req, res) => {
  try {
    const {
      full_name, nickname, college, specialization, date_of_birth, place_of_birth, current_residence,
      state, region, locality, phone, email, photo_base64,
      organizational_role, join_date, executive_sector, first_sector,
      current_sector, membership_status, last_record_update, notes
    } = req.body;

    const cleanName = sanitize(full_name);
    if (!cleanName) {
      return res.status(400).json({ ok: false, error: 'الاسم الكامل مطلوب' });
    }

    let safePhoto = null;
    if (photo_base64 && typeof photo_base64 === 'string') {
      if (photo_base64.startsWith('data:image/')) {
        safePhoto = photo_base64;
      }
    }

    const member = await Member.create({
      full_name: cleanName,
      nickname: sanitize(nickname),
      college: sanitize(college),
      specialization: sanitize(specialization),
      date_of_birth: sanitize(date_of_birth),
      place_of_birth: sanitize(place_of_birth),
      current_residence: sanitize(current_residence),
      state: sanitize(state),
      region: sanitize(region),
      locality: sanitize(locality),
      phone: sanitize(phone),
      email: sanitize(email),
      photo_base64: safePhoto,
      organizational_role: sanitize(organizational_role),
      join_date: sanitize(join_date),
      executive_sector: sanitize(executive_sector),
      first_sector: sanitize(first_sector),
      current_sector: sanitize(current_sector),
      membership_status: sanitize(membership_status) || 'pending',
      last_record_update: sanitize(last_record_update),
      notes: sanitize(notes)
    });

    res.json({ ok: true, id: member.id });
  } catch (err) {
    console.error('Error creating member:', err);
    res.status(500).json({ ok: false, error: 'حدث خطأ أثناء حفظ البيانات' });
  }
});

// Admin & Viewer Login
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { user, pass } = req.body;
    if (!user || !pass) {
      return res.status(400).json({ ok: false, error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    }

    const trimmedUser = user.trim();
    const account = await User.findOne({ where: { username: trimmedUser } });

    if (!account) {
      return res.status(401).json({ ok: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    // Compare with bcrypt hash
    const isMatch = bcrypt.compareSync(pass, account.password);
    if (!isMatch) {
      return res.status(401).json({ ok: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    // Generate signed JWT token with role information
    const token = jwt.sign(
      { user: account.username, role: account.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      ok: true,
      token,
      user: account.username,
      role: account.role,
      displayName: account.display_name || account.username
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ ok: false, error: 'خطأ أثناء تسجيل الدخول' });
  }
});

// Get Members List (Accessible to both Admin & Viewer)
app.get('/api/members', requireAuth, async (req, res) => {
  try {
    const members = await Member.findAll({
      order: [['createdAt', 'DESC']]
    });
    res.json({ ok: true, data: members, userRole: req.userRole });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'تعذر جلب البيانات' });
  }
});

// Get Single Member (Accessible to both Admin & Viewer for printing/viewing)
app.get('/api/members/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const member = await Member.findByPk(id);
    if (!member) {
      return res.status(404).json({ ok: false, error: 'السجل غير موجود' });
    }
    res.json({ ok: true, data: member });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'تعذر جلب السجل' });
  }
});

// Update Member (RESTRICTED TO ADMIN ONLY)
app.put('/api/members/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const member = await Member.findByPk(id);
    if (!member) {
      return res.status(404).json({ ok: false, error: 'السجل غير موجود' });
    }

    const {
      full_name, nickname, college, specialization, date_of_birth, place_of_birth, current_residence,
      state, region, locality, phone, email, photo_base64,
      organizational_role, join_date, executive_sector, first_sector,
      current_sector, membership_status, last_record_update, notes
    } = req.body;

    const cleanName = sanitize(full_name);
    if (!cleanName) {
      return res.status(400).json({ ok: false, error: 'الاسم الكامل مطلوب' });
    }

    let safePhoto = member.photo_base64;
    if (photo_base64 !== undefined) {
      if (photo_base64 && typeof photo_base64 === 'string' && photo_base64.startsWith('data:image/')) {
        safePhoto = photo_base64;
      } else if (photo_base64 === null || photo_base64 === '') {
        safePhoto = null;
      }
    }

    await member.update({
      full_name: cleanName,
      nickname: sanitize(nickname),
      college: sanitize(college),
      specialization: sanitize(specialization),
      date_of_birth: sanitize(date_of_birth),
      place_of_birth: sanitize(place_of_birth),
      current_residence: sanitize(current_residence),
      state: sanitize(state),
      region: sanitize(region),
      locality: sanitize(locality),
      phone: sanitize(phone),
      email: sanitize(email),
      photo_base64: safePhoto,
      organizational_role: sanitize(organizational_role),
      join_date: sanitize(join_date),
      executive_sector: sanitize(executive_sector),
      first_sector: sanitize(first_sector),
      current_sector: sanitize(current_sector),
      membership_status: sanitize(membership_status) || member.membership_status,
      last_record_update: sanitize(last_record_update) || new Date().toISOString().split('T')[0],
      notes: sanitize(notes)
    });

    res.json({ ok: true, member, message: 'تم تحديث بيانات العضو بنجاح' });
  } catch (err) {
    console.error('Update member error:', err);
    res.status(500).json({ ok: false, error: 'تعذر تعديل بيانات العضو' });
  }
});

// Delete Member (RESTRICTED TO ADMIN ONLY)
app.delete('/api/members/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Member.destroy({ where: { id } });
    if (deleted) {
      res.json({ ok: true, message: 'تم الحذف بنجاح' });
    } else {
      res.status(404).json({ ok: false, error: 'السجل غير موجود' });
    }
  } catch (err) {
    res.status(500).json({ ok: false, error: 'تعذر حذف السجل' });
  }
});

// Change Password (RESTRICTED TO ADMIN ONLY)
app.post('/api/change-password', requireAdmin, async (req, res) => {
  try {
    const { target_user, new_user, new_pass } = req.body;
    if (!new_pass || new_pass.length < 4) {
      return res.status(400).json({ ok: false, error: 'كلمة المرور يجب ألا تقل عن 4 أحرف' });
    }

    const usernameToUpdate = target_user || req.user;
    const account = await User.findOne({ where: { username: usernameToUpdate } });

    if (!account) {
      return res.status(404).json({ ok: false, error: 'المستخدم غير موجود' });
    }

    const hashedPassword = bcrypt.hashSync(new_pass, 10);
    const updatedUsername = new_user ? sanitize(new_user) : account.username;

    await account.update({
      username: updatedUsername,
      password: hashedPassword
    });

    // If admin changed their own username/password, generate new token
    let newToken = null;
    if (usernameToUpdate === req.user) {
      newToken = jwt.sign({ user: updatedUsername, role: account.role }, JWT_SECRET, { expiresIn: '24h' });
    }

    res.json({
      ok: true,
      token: newToken,
      user: updatedUsername,
      message: `تم تحديث كلمة مرور (${updatedUsername}) بنجاح`
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'فشل تغيير كلمة المرور' });
  }
});

// ═══════════════════════════════════════════════════════
// STATIC FILES & PAGE ROUTING
// ═══════════════════════════════════════════════════════
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// ═══════════════════════════════════════════════════════
// SERVER BOOTSTRAP
// ═══════════════════════════════════════════════════════
sequelize.sync()
  .then(async () => {
    try {
      const qi = sequelize.getQueryInterface();
      const tableDesc = await qi.describeTable('members');
      if (!tableDesc.nickname) await qi.addColumn('members', 'nickname', { type: DataTypes.STRING });
      if (!tableDesc.college) await qi.addColumn('members', 'college', { type: DataTypes.STRING });
      if (!tableDesc.specialization) await qi.addColumn('members', 'specialization', { type: DataTypes.STRING });
    } catch (migErr) {
      // Column exists or table structure already aligned
    }
    console.log(`Sequelize synchronized successfully with ${sequelize.getDialect()}!`);
    await initSystemUsers();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🔒 UPF Membership System (Role-Protected) is running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to sync database:', err);
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🔒 UPF Membership System running on port ${PORT} (DB sync failed)`);
    });
  });
