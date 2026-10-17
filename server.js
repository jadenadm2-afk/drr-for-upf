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
// 1. Hide server fingerprint
app.disable('x-powered-by');

// 2. Set secure HTTP response headers
app.use(helmet({
  contentSecurityPolicy: false, // Allow Google Fonts & Chart.js CDN
  crossOriginEmbedderPolicy: false
}));

// 3. Rate limiter for Admin Login (Prevents Brute Force Attacks)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Max 10 attempts per IP per 15 minutes
  message: { ok: false, error: 'تم حظر محاولات الدخول مؤقتاً لكثرة المحاولات الخاطئة. الرجاء المحاولة بعد 15 دقيقة.' },
  standardHeaders: true,
  legacyHeaders: false
});

// 4. Rate limiter for Public Registrations (Prevents Spam & Flooding)
const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30, // Max 30 member submissions per 15 mins per IP
  message: { ok: false, error: 'تم استقبال عدد كبير من الاستمارات من هذا الجهاز. يرجى الانتظار قليلاً.' },
  standardHeaders: true,
  legacyHeaders: false
});

// 5. Body parser limits (Strict 10MB limit for image base64)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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

const Setting = sequelize.define('Setting', {
  key: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false
  },
  value: {
    type: DataTypes.TEXT,
    allowNull: false
  }
}, {
  tableName: 'settings',
  timestamps: true
});

// Helper for XSS sanitization
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/<[^>]*>?/gm, '').trim();
}

// ═══════════════════════════════════════════════════════
// JWT AUTHENTICATION MIDDLEWARE
// ═══════════════════════════════════════════════════════
function requireAdminAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ ok: false, error: 'غير مصرح: يجب تسجيل الدخول أولاً' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.adminUser = decoded.user;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: 'انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً' });
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

// Submit Member Registration Form (Public with Rate Limiter & Sanitization)
app.post('/api/members', registrationLimiter, async (req, res) => {
  try {
    const {
      full_name, date_of_birth, place_of_birth, current_residence,
      state, region, locality, phone, email, photo_base64,
      organizational_role, join_date, executive_sector, first_sector,
      current_sector, membership_status, last_record_update, notes
    } = req.body;

    const cleanName = sanitize(full_name);
    if (!cleanName) {
      return res.status(400).json({ ok: false, error: 'الاسم الكامل مطلوب' });
    }

    // Validate photo format if provided
    let safePhoto = null;
    if (photo_base64 && typeof photo_base64 === 'string') {
      if (photo_base64.startsWith('data:image/')) {
        safePhoto = photo_base64;
      }
    }

    const member = await Member.create({
      full_name: cleanName,
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

// Admin Login (Protected with Rate Limiter & Password Hashing)
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { user, pass } = req.body;
    if (!user || !pass) {
      return res.status(400).json({ ok: false, error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    }

    // Retrieve stored credentials
    const userRow = await Setting.findOne({ where: { key: 'admin_user' } });
    const passRow = await Setting.findOne({ where: { key: 'admin_pass' } });

    const correctUser = userRow ? userRow.value : (process.env.ADMIN_USER || 'admin');
    const storedPass = passRow ? passRow.value : (process.env.ADMIN_PASS || 'upf@2026');

    // Check username
    if (user.trim() !== correctUser) {
      return res.status(401).json({ ok: false, error: 'بيانات الدخول غير صحيحة' });
    }

    // Verify password (supports bcrypt hash or legacy plain text with auto-upgrade)
    let isMatch = false;
    if (storedPass.startsWith('$2a$') || storedPass.startsWith('$2b$')) {
      isMatch = bcrypt.compareSync(pass, storedPass);
    } else {
      isMatch = (pass === storedPass);
      // Auto-upgrade plain text to bcrypt hash
      if (isMatch) {
        const hashed = bcrypt.hashSync(pass, 10);
        await Setting.upsert({ key: 'admin_pass', value: hashed });
      }
    }

    if (!isMatch) {
      return res.status(401).json({ ok: false, error: 'بيانات الدخول غير صحيحة' });
    }

    // Generate signed JWT token valid for 24 hours
    const token = jwt.sign({ user: correctUser }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ ok: true, token, user: correctUser });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ ok: false, error: 'خطأ أثناء تسجيل الدخول' });
  }
});

// Get Members List (PROTECTED - Requires JWT Token)
app.get('/api/members', requireAdminAuth, async (req, res) => {
  try {
    const members = await Member.findAll({
      order: [['createdAt', 'DESC']]
    });
    res.json({ ok: true, data: members });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'تعذر جلب البيانات' });
  }
});

// Delete Member (PROTECTED - Requires JWT Token)
app.delete('/api/members/:id', requireAdminAuth, async (req, res) => {
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

// Change Admin Password (PROTECTED - Requires JWT Token + Bcrypt Hashing)
app.post('/api/change-password', requireAdminAuth, async (req, res) => {
  try {
    const { new_user, new_pass } = req.body;
    if (!new_user || !new_pass || new_pass.length < 4) {
      return res.status(400).json({ ok: false, error: 'كلمة المرور يجب ألا تقل عن 4 أحرف' });
    }

    // Hash password before saving to database
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(new_pass, salt);

    await Setting.upsert({ key: 'admin_user', value: sanitize(new_user) });
    await Setting.upsert({ key: 'admin_pass', value: hashedPassword });

    // Generate new token with new user
    const newToken = jwt.sign({ user: sanitize(new_user) }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ ok: true, token: newToken, message: 'تم حفظ وتشفير بيانات الدخول بنجاح' });
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
sequelize.sync({ alter: true })
  .then(() => {
    console.log(`Sequelize synchronized successfully with ${sequelize.getDialect()}!`);
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🔒 UPF Membership System (Secured) is running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to sync database:', err);
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🔒 UPF Membership System running on port ${PORT} (DB sync failed)`);
    });
  });
