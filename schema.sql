-- ============================================================
-- UPF Membership System – PostgreSQL / Supabase Schema
-- حركة/جيش تحرير السودان – الجبهة الشعبية المتحدة UPF
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Members Table ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.members (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  created_at    TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

  -- Personal Information
  full_name         TEXT    NOT NULL,
  date_of_birth     DATE,
  place_of_birth    TEXT,
  current_residence TEXT,
  state             TEXT,
  region            TEXT,
  locality          TEXT,
  phone             TEXT,
  email             TEXT,
  photo_base64      TEXT,           -- stored as base64 data URL

  -- Organizational Information
  organizational_role TEXT,
  join_date           DATE,
  executive_sector    TEXT,
  first_sector        TEXT,
  current_sector      TEXT,
  membership_status   TEXT    DEFAULT 'pending'
                      CHECK (membership_status IN ('active','inactive','pending')),
  last_record_update  DATE,
  notes               TEXT
);

-- ─── Indexes ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_members_status    ON public.members(membership_status);
CREATE INDEX IF NOT EXISTS idx_members_state     ON public.members(state);
CREATE INDEX IF NOT EXISTS idx_members_name      ON public.members(full_name);
CREATE INDEX IF NOT EXISTS idx_members_created   ON public.members(created_at DESC);

-- ─── Row Level Security ───────────────────────────────────────
ALTER TABLE public.members ENABLE ROW LEVEL SECURITY;

-- Allow all operations for authenticated users (adjust per your policy)
CREATE POLICY "Allow all for anon"
  ON public.members
  FOR ALL
  USING (true)
  WITH CHECK (true);

-- ─── Statistics View ──────────────────────────────────────────
CREATE OR REPLACE VIEW public.membership_stats AS
SELECT
  COUNT(*)                                            AS total_members,
  COUNT(*) FILTER (WHERE membership_status = 'active')   AS active_members,
  COUNT(*) FILTER (WHERE membership_status = 'inactive')  AS inactive_members,
  COUNT(*) FILTER (WHERE membership_status = 'pending')   AS pending_members,
  COUNT(DISTINCT state)                               AS states_count,
  COUNT(DISTINCT current_sector)                      AS sectors_count,
  MAX(created_at)                                     AS last_registration
FROM public.members;

-- ─── Members by State View ────────────────────────────────────
CREATE OR REPLACE VIEW public.members_by_state AS
SELECT
  COALESCE(state, 'غير محدد') AS state,
  COUNT(*) AS count
FROM public.members
GROUP BY state
ORDER BY count DESC;

-- ─── Members by Role View ─────────────────────────────────────
CREATE OR REPLACE VIEW public.members_by_role AS
SELECT
  COALESCE(organizational_role, 'غير محدد') AS role,
  COUNT(*) AS count
FROM public.members
GROUP BY organizational_role
ORDER BY count DESC;

-- ─── Monthly Registrations View ───────────────────────────────
CREATE OR REPLACE VIEW public.monthly_registrations AS
SELECT
  TO_CHAR(created_at, 'YYYY-MM') AS month,
  COUNT(*) AS count
FROM public.members
GROUP BY TO_CHAR(created_at, 'YYYY-MM')
ORDER BY month DESC
LIMIT 12;

-- ============================================================
-- Sample data (optional – remove in production)
-- ============================================================
/*
INSERT INTO public.members (full_name, state, region, organizational_role, membership_status, join_date)
VALUES
  ('محمد أحمد علي',   'جنوب دارفور', 'جبل مرة', 'كادر تنظيمي', 'active',   '2024-01-15'),
  ('فاطمة إبراهيم موسى', 'وسط دارفور', 'زالنجي',   'عضو عادي',    'active',   '2024-02-20'),
  ('إدريس حسن عمر',   'شمال دارفور', 'كتم',       'قيادي',        'active',   '2023-11-10'),
  ('خديجة آدم يوسف',  'جنوب دارفور', 'نيالا',     'عضو عادي',    'pending',  '2024-03-05');
*/
