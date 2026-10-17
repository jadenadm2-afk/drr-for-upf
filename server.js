const express = require('express');
const path = require('path');
const { Sequelize, DataTypes, Op } = require('sequelize');

const app = express();
const PORT = process.env.PORT || 3000;

// Body parsers with 15MB limit for member photo base64
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

// Helper for admin credentials
async function getAdminCredentials() {
  try {
    const userRow = await Setting.findOne({ where: { key: 'admin_user' } });
    const passRow = await Setting.findOne({ where: { key: 'admin_pass' } });
    return {
      user: userRow ? userRow.value : (process.env.ADMIN_USER || 'admin'),
      pass: passRow ? userRow.value && passRow ? passRow.value : (process.env.ADMIN_PASS || 'upf@2026') : (process.env.ADMIN_PASS || 'upf@2026')
    };
  } catch (e) {
    return { user: 'admin', pass: 'upf@2026' };
  }
}

// ═══════════════════════════════════════════════════════
// REST API ROUTES
// ═══════════════════════════════════════════════════════

// Status / Health check
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
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Submit Member Registration Form (Public)
app.post('/api/members', async (req, res) => {
  try {
    const {
      full_name, date_of_birth, place_of_birth, current_residence,
      state, region, locality, phone, email, photo_base64,
      organizational_role, join_date, executive_sector, first_sector,
      current_sector, membership_status, last_record_update, notes
    } = req.body;

    if (!full_name || !full_name.trim()) {
      return res.status(400).json({ ok: false, error: 'الاسم الكامل مطلوب' });
    }

    const member = await Member.create({
      full_name: full_name.trim(),
      date_of_birth, place_of_birth, current_residence,
      state, region, locality, phone, email, photo_base64,
      organizational_role, join_date, executive_sector, first_sector,
      current_sector,
      membership_status: membership_status || 'pending',
      last_record_update, notes
    });

    res.json({ ok: true, member });
  } catch (err) {
    console.error('Error creating member:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Get Members List (for Admin)
app.get('/api/members', async (req, res) => {
  try {
    const members = await Member.findAll({
      order: [['createdAt', 'DESC']]
    });
    res.json({ ok: true, data: members });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Delete Member (for Admin)
app.delete('/api/members/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Member.destroy({ where: { id } });
    if (deleted) {
      res.json({ ok: true, message: 'تم الحذف بنجاح' });
    } else {
      res.status(404).json({ ok: false, error: 'السجل غير موجود' });
    }
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Admin Login Check
app.post('/api/login', async (req, res) => {
  try {
    const { user, pass } = req.body;
    const creds = await getAdminCredentials();
    if (user === creds.user && pass === creds.pass) {
      res.json({ ok: true, user: creds.user });
    } else {
      res.status(401).json({ ok: false, error: 'بيانات الدخول غير صحيحة' });
    }
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Change Admin Password
app.post('/api/change-password', async (req, res) => {
  try {
    const { new_user, new_pass } = req.body;
    if (!new_user || !new_pass || new_pass.length < 4) {
      return res.status(400).json({ ok: false, error: 'كلمة المرور يجب ألا تقل عن 4 أحرف' });
    }

    await Setting.upsert({ key: 'admin_user', value: new_user.trim() });
    await Setting.upsert({ key: 'admin_pass', value: new_pass });

    res.json({ ok: true, message: 'تم حفظ بيانات الدخول بنجاح' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
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
// SERVER BOOTSTRAP WITH AUTO-SYNC
// ═══════════════════════════════════════════════════════
sequelize.sync({ alter: true })
  .then(() => {
    console.log(`Sequelize models synchronized successfully with ${sequelize.getDialect()}!`);
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 UPF Membership System is running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to sync database:', err);
    // Start server anyway
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 UPF Membership System running on port ${PORT} (DB sync failed)`);
    });
  });
