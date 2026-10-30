-- ====================================================================
-- PanTools - Cloudflare D1 数据库初始化建表脚本
-- 在 Cloudflare 控制台 -> 存储和数据库 (D1) -> 选中数据库 -> 控制台 (Console) 中粘贴执行
-- ====================================================================

CREATE TABLE IF NOT EXISTS links (
  slug TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  backup_url TEXT DEFAULT '',
  active_target TEXT DEFAULT 'primary',
  auto_switched INTEGER DEFAULT 0,
  only_mobile INTEGER DEFAULT 0,
  title TEXT DEFAULT '',
  clicks INTEGER DEFAULT 0,
  uv INTEGER DEFAULT 0,
  convert_clicks INTEGER DEFAULT 0,
  today_clicks INTEGER DEFAULT 0,
  today_uv INTEGER DEFAULT 0,
  today_convert INTEGER DEFAULT 0,
  today_date TEXT DEFAULT '',
  mobile_clicks INTEGER DEFAULT 0,
  pc_clicks INTEGER DEFAULT 0,
  source_wechat INTEGER DEFAULT 0,
  source_twitter INTEGER DEFAULT 0,
  source_direct INTEGER DEFAULT 0,
  source_other INTEGER DEFAULT 0,
  created_at TEXT DEFAULT '',
  created_timestamp INTEGER DEFAULT 0,
  daily_json TEXT DEFAULT '{}'
);

-- 常用极速查询索引（代码在初次运行时也会自适应静默检测并补齐）
CREATE INDEX IF NOT EXISTS idx_links_created ON links(created_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_links_clicks ON links(clicks DESC);
CREATE INDEX IF NOT EXISTS idx_links_today_clicks ON links(today_clicks DESC);
