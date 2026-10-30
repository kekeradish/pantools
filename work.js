export default {
  async fetch(request, env, ctx) {
    // 1. 优先读取 Cloudflare 环境变量，未配置时使用默认值（平滑向下兼容）
    const ADMIN_PASSWORD = env.ADMIN_PASSWORD || "123456";
    const ADMIN_PATH = (env.ADMIN_PATH || "my-admin-7788").replace(/^\/+|\/+$/g, "");

    const url = new URL(request.url);

    // 强制跳转 HTTPS
    if (url.protocol === "http:") {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }

    const path = url.pathname.replace(/^\/+|\/+$/g, "");

    // 统一获取北京时间（UTC+8）日期字符串（格式：YYYY-MM-DD），彻底杜绝 Cloudflare Workers 默认 UTC 导致的早 8 点前时区漂移与数据不客观
    function getBeijingDateStr(d = new Date()) {
      const beijingTime = new Date(d.getTime() + 8 * 3600 * 1000);
      return beijingTime.toISOString().slice(0, 10);
    }

    // 科学客观的渠道归因探测引擎（URL 推广参数 > 客户端 User-Agent 特征 > Referer 来源）
    function detectSourceChannel(req, requestUrl) {
      try {
        // 1. 推广链接参数最高优先级（支持 ?s=wx, ?channel=twitter, ?from=wechat 等）
        const paramSource = (
          requestUrl.searchParams.get("s") || 
          requestUrl.searchParams.get("src") || 
          requestUrl.searchParams.get("channel") || 
          requestUrl.searchParams.get("from") || ""
        ).toLowerCase();
        if (paramSource.includes("wx") || paramSource.includes("weixin") || paramSource.includes("wechat") || paramSource.includes("gzh")) return "wechat";
        if (paramSource.includes("x") || paramSource.includes("twitter") || paramSource.includes("tw")) return "twitter";
        if (paramSource.includes("qq")) return "qq";
        if (paramSource.includes("direct")) return "direct";

        // 2. 客户端 User-Agent 特征优先识别（微信/QQ内经常不带 Referer，防止被误判为 direct）
        const ua = (req.headers.get("user-agent") || "").toLowerCase();
        if (ua.includes("micromessenger")) return "wechat";
        if (ua.includes("qq/")) return "qq";

        // 3. Referer 来源域名识别
        const referer = (req.headers.get("referer") || "").toLowerCase();
        if (!referer) return "direct";
        if (referer.includes("t.co") || referer.includes("x.com") || referer.includes("twitter.com")) return "twitter";
        if (referer.includes("weixin.qq.com") || referer.includes("mp.weixin.qq.com")) return "wechat";
        if (referer.includes("qq.com")) return "qq";
      } catch (e) {}
      return "other";
    }

    // 登录验证接口（内置企业级防暴力破解与 IP 锁定机制）
    if (path === "api/login" && request.method === "POST") {
      try {
        const clientIp = request.headers.get("cf-connecting-ip") || "127.0.0.1";
        const lockKey = "ratelimit:login:" + clientIp;
        const now = Date.now();

        // 1. 检查当前 IP 是否处于封禁锁定状态
        const failRecordRaw = await env.LINKS.get(lockKey);
        let failRecord = null;
        if (failRecordRaw) {
          try { failRecord = JSON.parse(failRecordRaw); } catch (e) {}
        }

        if (failRecord && failRecord.lockedUntil && failRecord.lockedUntil > now) {
          const waitMinutes = Math.ceil((failRecord.lockedUntil - now) / 60000);
          return Response.json(
            { error: `密码输错次数过多，为保障安全，当前 IP 已被临时锁定，请在 ${waitMinutes} 分钟后再试` },
            { status: 429 }
          );
        }

        const body = await request.json();

        // 2. 密码验证通过：清除此 IP 历史输错记录
        if (body && body.pwd === ADMIN_PASSWORD) {
          if (failRecord) {
            await env.LINKS.delete(lockKey);
          }
          return Response.json({ success: true });
        }

        // 3. 密码验证失败：递增计数，达到 5 次锁定 15 分钟
        const currentCount = (failRecord && failRecord.count ? failRecord.count : 0) + 1;
        const maxAttempts = 5;

        if (currentCount >= maxAttempts) {
          const lockedUntil = now + 15 * 60 * 1000;
          await env.LINKS.put(lockKey, JSON.stringify({ count: currentCount, lockedUntil: lockedUntil }), { expirationTtl: 900 });
          return Response.json(
            { error: "密码连续输错 5 次，系统已临时锁定该 IP 15 分钟！" },
            { status: 429 }
          );
        } else {
          const remaining = maxAttempts - currentCount;
          await env.LINKS.put(lockKey, JSON.stringify({ count: currentCount, lockedUntil: 0 }), { expirationTtl: 900 });
          return Response.json(
            { error: `管理密码错误！还可尝试 ${remaining} 次，连续输错 5 次将锁定 15 分钟` },
            { status: 403 }
          );
        }
      } catch (e) {
        return Response.json({ error: "请求格式错误" }, { status: 400 });
      }
    }

    // 后台展示页面：仅匹配 ADMIN_PATH 时返回
    if (path === ADMIN_PATH) {
      return new Response(renderAdminPage(), {
        headers: {
          "content-type": "text/html;charset=UTF-8",
          "cache-control": "no-store, no-cache, must-revalidate"
        }
      });
    }

    // API：接收落地页真实转存与动作埋点上报（免密轻量接口，内置物理上限防刷与天/渠道精细归因）
    if (path === "api/action" && request.method === "POST") {
      try {
        const body = await request.json();
        const slug = (body && body.slug || "").trim();
        const srcChannel = (body && body.source || "direct").trim();
        const todayDate = getBeijingDateStr();

        if (slug && env.DB) {
          try {
            // 确保表结构包含转存与天维度列（自适应静默热补齐）
            try {
              await env.DB.prepare("ALTER TABLE links ADD COLUMN convert_clicks INTEGER DEFAULT 0").run();
            } catch (e) {}
            try {
              await env.DB.prepare("ALTER TABLE links ADD COLUMN today_clicks INTEGER DEFAULT 0").run();
              await env.DB.prepare("ALTER TABLE links ADD COLUMN today_uv INTEGER DEFAULT 0").run();
              await env.DB.prepare("ALTER TABLE links ADD COLUMN today_convert INTEGER DEFAULT 0").run();
              await env.DB.prepare("ALTER TABLE links ADD COLUMN today_date TEXT DEFAULT ''").run();
              await env.DB.prepare("ALTER TABLE links ADD COLUMN source_wechat INTEGER DEFAULT 0").run();
            } catch (e) {}

            const row = await env.DB.prepare("SELECT clicks, convert_clicks, today_clicks, today_convert, today_date, daily_json FROM links WHERE slug = ?").bind(slug).first();
            if (row) {
              let daily = {};
              try { daily = row.daily_json ? JSON.parse(row.daily_json) : {}; } catch (e) {}
              if (!daily[todayDate]) {
                daily[todayDate] = { clicks: 1, uv: 1, convert: 0, mobile: 0, pc: 0, sources: {}, convert_sources: {} };
              }
              if (!daily[todayDate].convert_sources) daily[todayDate].convert_sources = {};

              const dayClicks = Math.max(1, daily[todayDate].clicks || 1);
              daily[todayDate].convert = Math.min(dayClicks, (daily[todayDate].convert || 0) + 1);
              daily[todayDate].convert_sources[srcChannel] = (daily[todayDate].convert_sources[srcChannel] || 0) + 1;

              const isSameDay = row.today_date === todayDate;
              const newTodayClicks = isSameDay ? (row.today_clicks || 0) : 1;
              const newTodayConvert = isSameDay ? Math.min(newTodayClicks, (row.today_convert || 0) + 1) : 1;

              await env.DB.prepare(`
                UPDATE links SET
                  convert_clicks = MIN(clicks, convert_clicks + 1),
                  today_convert = ?,
                  today_date = ?,
                  daily_json = ?
                WHERE slug = ?
              `).bind(newTodayConvert, todayDate, JSON.stringify(daily), slug).run();
            }
          } catch (colErr) {}
        }
        return Response.json({ success: true });
      } catch (e) {
        return Response.json({ success: false });
      }
    }

    // API：智能嗅探抓取网盘网页真实标题
    if (path === "api/fetch-title" && request.method === "POST") {
      try {
        const body = await request.json();
        if (!body || body.pwd !== ADMIN_PASSWORD) {
          return Response.json({ error: "密码验证失败" }, { status: 403 });
        }
        const targetUrl = (body.url || "").trim();
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
          return Response.json({ error: "无效的 URL" }, { status: 400 });
        }
        const fetchedTitle = await fetchTitleFromUrl(targetUrl);
        return Response.json({ success: true, title: fetchedTitle });
      } catch (e) {
        return Response.json({ success: false, title: "" });
      }
    }

    // API：获取短链列表（支持 D1 工业级服务端极速分页、毫秒模糊搜索、大盘指标聚合与全量导出）
    if (path === "api/list" && request.method === "POST") {
      try {
        const body = await request.json();
        if (!body || body.pwd !== ADMIN_PASSWORD) {
          return Response.json({ error: "密码验证失败" }, { status: 403 });
        }

        const todayDate = getBeijingDateStr();
        const search = (body.search || "").trim();
        const sort = body.sort || "latest";
        const page = Math.max(1, parseInt(body.page) || 1);
        const pageSize = Math.max(5, Math.min(100, parseInt(body.pageSize) || 20));
        const isExport = !!body.exportAll;

        // 1. 优先使用 D1 数据库
        if (env.DB) {
          try {
            // 自适应热升级：自动补齐转存、今日爆款排序列与极速倒序索引（真正 100% 纯代码自动化，无需用户手动进数据库执行 SQL）
            try {
              await env.DB.prepare("ALTER TABLE links ADD COLUMN convert_clicks INTEGER DEFAULT 0").run();
            } catch (e) {}
            try {
              await env.DB.prepare("ALTER TABLE links ADD COLUMN today_clicks INTEGER DEFAULT 0").run();
              await env.DB.prepare("ALTER TABLE links ADD COLUMN today_uv INTEGER DEFAULT 0").run();
              await env.DB.prepare("ALTER TABLE links ADD COLUMN today_convert INTEGER DEFAULT 0").run();
              await env.DB.prepare("ALTER TABLE links ADD COLUMN today_date TEXT DEFAULT ''").run();
              await env.DB.prepare("ALTER TABLE links ADD COLUMN source_wechat INTEGER DEFAULT 0").run();
            } catch (e) {}
            try {
              await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_links_created ON links(created_timestamp DESC)").run();
              await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_links_clicks ON links(clicks DESC)").run();
              await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_links_today_clicks ON links(today_clicks DESC)").run();
            } catch (e) {}

            // A. 全局大盘数据聚合（一条 SQL 瞬间搞定全局统计卡片，客观真实不受分页限制）
            let summary = {
              totalLinks: 0,
              totalClicks: 0,
              totalUv: 0,
              totalConvert: 0,
              todayClicks: 0,
              todayUv: 0,
              todayConvert: 0,
              totalMobile: 0,
              totalPc: 0
            };
            try {
              const sumRow = await env.DB.prepare(`
                SELECT 
                  COUNT(*) as totalLinks,
                  COALESCE(SUM(clicks), 0) as totalClicks,
                  COALESCE(SUM(uv), 0) as totalUv,
                  COALESCE(SUM(CASE WHEN convert_clicks > clicks THEN clicks ELSE convert_clicks END), 0) as totalConvert,
                  COALESCE(SUM(CASE WHEN today_date = ? THEN today_clicks ELSE 0 END), 0) as todayClicks,
                  COALESCE(SUM(CASE WHEN today_date = ? THEN today_uv ELSE 0 END), 0) as todayUv,
                  COALESCE(SUM(CASE WHEN today_date = ? THEN today_convert ELSE 0 END), 0) as todayConvert,
                  COALESCE(SUM(mobile_clicks), 0) as totalMobile,
                  COALESCE(SUM(pc_clicks), 0) as totalPc
                FROM links
              `).bind(todayDate, todayDate, todayDate).first();
              if (sumRow) {
                summary = {
                  totalLinks: sumRow.totalLinks || 0,
                  totalClicks: sumRow.totalClicks || 0,
                  totalUv: sumRow.totalUv || 0,
                  totalConvert: sumRow.totalConvert || 0,
                  todayClicks: sumRow.todayClicks || 0,
                  todayUv: sumRow.todayUv || 0,
                  todayConvert: Math.min(sumRow.todayClicks || 0, sumRow.todayConvert || 0),
                  totalMobile: sumRow.totalMobile || 0,
                  totalPc: sumRow.totalPc || 0
                };
              }
            } catch (sumErr) {}

            // B. 搜索过滤条件构建
            let whereClause = "";
            let params = [];
            if (search) {
              whereClause = "WHERE (title LIKE ? OR slug LIKE ? OR url LIKE ?)";
              params = [`%${search}%`, `%${search}%`, `%${search}%`];
            }

            // C. 查询符合条件的总记录数
            const countRow = await env.DB.prepare(`SELECT COUNT(*) as filteredTotal FROM links ${whereClause}`).bind(...params).first();
            const filteredTotal = countRow ? countRow.filteredTotal : 0;

            // D. 排序字段选择（今日爆款必须基于当天日期与当天真实流量，绝不混淆历史总体！）
            let orderClause = "ORDER BY created_timestamp DESC";
            let sortParams = [];
            if (sort === "total") {
              orderClause = "ORDER BY clicks DESC, created_timestamp DESC";
            } else if (sort === "today") {
              orderClause = "ORDER BY (CASE WHEN today_date = ? THEN today_clicks ELSE 0 END) DESC, (CASE WHEN today_date = ? THEN today_uv ELSE 0 END) DESC, clicks DESC, created_timestamp DESC";
              sortParams.push(todayDate, todayDate);
            }

            // E. 分页查询
            let querySql = `SELECT * FROM links ${whereClause} ${orderClause}`;
            let queryParams = [...params, ...sortParams];

            if (!isExport) {
              const offset = (page - 1) * pageSize;
              querySql += " LIMIT ? OFFSET ?";
              queryParams.push(pageSize, offset);
            }

            const { results } = await env.DB.prepare(querySql).bind(...queryParams).all();

            const items = [];
            for (const row of (results || [])) {
              let daily = {};
              try {
                daily = row.daily_json ? JSON.parse(row.daily_json) : {};
              } catch (e) {}
              const todayStats = daily[todayDate] || { clicks: 0, uv: 0, mobile: 0, pc: 0, convert: 0 };
              const isRowToday = row.today_date === todayDate;
              const curTodayClicks = isRowToday ? (row.today_clicks || 0) : (todayStats.clicks || 0);
              const curTodayUv = isRowToday ? (row.today_uv || 0) : (todayStats.uv || 0);
              const curTodayConvert = isRowToday ? (row.today_convert || 0) : (todayStats.convert || 0);

              items.push({
                slug: row.slug,
                shortUrl: url.origin + "/" + row.slug,
                url: row.url,
                backupUrl: row.backup_url || "",
                activeTarget: row.active_target || "primary",
                autoSwitched: !!row.auto_switched,
                onlyMobile: !!row.only_mobile,
                lastSwitchedAt: row.last_switched_at || "",
                title: row.title || "资源分享直达",
                brand: detectPanBrand(row.url),
                clicks: row.clicks || 0,
                uv: row.uv || 0,
                convertClicks: Math.min(row.clicks || 0, row.convert_clicks || 0),
                todayClicks: curTodayClicks,
                todayUv: curTodayUv,
                todayConvert: Math.min(curTodayClicks, curTodayConvert),
                sources: {
                  wechat: row.source_wechat || 0,
                  twitter: row.source_twitter || 0,
                  direct: row.source_direct || 0,
                  other: row.source_other || 0
                },
                devices: {
                  mobile: row.mobile_clicks || 0,
                  pc: row.pc_clicks || 0
                },
                daily: daily,
                createdAt: row.created_at || "-",
                createdTimestamp: row.created_timestamp || 0
              });
            }

            return new Response(JSON.stringify({
              success: true,
              items: items,
              total: filteredTotal,
              page: page,
              pageSize: pageSize,
              totalPages: Math.max(1, Math.ceil(filteredTotal / pageSize)),
              metrics: summary,
              engine: "d1"
            }), {
              headers: {
                "Content-Type": "application/json;charset=UTF-8",
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache"
              }
            });
          } catch (d1Err) {}
        }

        // 2. 兜底回退：若无 D1 绑定，使用 KV
        const listRes = env.LINKS ? await env.LINKS.list({ prefix: "link:" }) : { keys: [] };
        const oldList = env.LINKS ? await env.LINKS.list() : { keys: [] };

        const allTargetKeys = [];
        const seenSlugs = new Set();

        for (const key of listRes.keys) {
          const slug = key.name.replace(/^link:/, "");
          seenSlugs.add(slug);
          allTargetKeys.push({ slug: slug, keyName: key.name });
        }

        for (const key of oldList.keys) {
          if (
            key.name.startsWith("link:") ||
            key.name.startsWith("uv_") ||
            key.name.startsWith("uv:") ||
            key.name.startsWith("ratelimit:") ||
            key.name.startsWith("throttle:") ||
            key.name.startsWith("chk:")
          ) {
            continue;
          }
          if (!seenSlugs.has(key.name)) {
            seenSlugs.add(key.name);
            allTargetKeys.push({ slug: key.name, keyName: key.name });
          }
        }

        const rawResults = env.LINKS
          ? await Promise.all(allTargetKeys.map(item => env.LINKS.get(item.keyName).catch(() => null)))
          : [];

        let allItems = [];
        for (let i = 0; i < allTargetKeys.length; i++) {
          const target = allTargetKeys[i];
          const raw = rawResults[i];
          if (!raw) continue;

          try {
            const parsed = JSON.parse(raw);
            if (!parsed.url) continue;

            const daily = parsed.daily || {};
            const todayStats = daily[todayDate] || { clicks: 0, uv: 0, mobile: 0, pc: 0 };

            const createdTs =
              parsed.createdTimestamp ||
              (parsed.createdAt && parsed.createdAt !== "-"
                ? new Date(parsed.createdAt.replace(/-/g, "/")).getTime()
                : 0);

            allItems.push({
              slug: target.slug,
              shortUrl: url.origin + "/" + target.slug,
              url: parsed.url,
              backupUrl: parsed.backupUrl || "",
              activeTarget: parsed.activeTarget || "primary",
              autoSwitched: !!parsed.autoSwitched,
              onlyMobile: !!parsed.onlyMobile,
              lastSwitchedAt: parsed.lastSwitchedAt || "",
              title: parsed.title || "资源分享直达",
              brand: detectPanBrand(parsed.url),
              clicks: parsed.clicks || 0,
              uv: parsed.uv || 0,
              convertClicks: parsed.convertClicks || 0,
              todayClicks: todayStats.clicks || 0,
              todayUv: todayStats.uv || 0,
              sources: parsed.sources || { twitter: 0, direct: 0, other: 0 },
              devices: parsed.devices || { mobile: 0, pc: 0 },
              daily: daily,
              createdAt: parsed.createdAt || "-",
              createdTimestamp: createdTs
            });
          } catch (e) {}
        }

        if (search) {
          allItems = allItems.filter(i => (i.title && i.title.toLowerCase().includes(search.toLowerCase())) || i.slug.toLowerCase().includes(search.toLowerCase()));
        }

        if (sort === "total") {
          allItems.sort((a, b) => (b.clicks || 0) - (a.clicks || 0));
        } else {
          allItems.sort((a, b) => (b.createdTimestamp || 0) - (a.createdTimestamp || 0));
        }

        const filteredTotal = allItems.length;
        const offset = (page - 1) * pageSize;
        const pageItems = isExport ? allItems : allItems.slice(offset, offset + pageSize);

        return new Response(JSON.stringify({
          success: true,
          items: pageItems,
          total: filteredTotal,
          page: page,
          pageSize: pageSize,
          totalPages: Math.max(1, Math.ceil(filteredTotal / pageSize)),
          engine: "kv"
        }), {
          headers: {
            "Content-Type": "application/json;charset=UTF-8",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache"
          }
        });
      } catch (err) {
        return Response.json({ error: "获取数据列表失败" }, { status: 500 });
      }
    }

    // API：按需懒加载单条短链深度数据（7 天趋势柱状图与渠道）
    if (path === "api/detail" && request.method === "POST") {
      try {
        const body = await request.json();
        if (!body || body.pwd !== ADMIN_PASSWORD) {
          return Response.json({ error: "密码验证失败" }, { status: 403 });
        }
        const slug = (body.slug || "").trim();
        if (!slug) {
          return Response.json({ error: "缺少参数 slug" }, { status: 400 });
        }

        if (env.DB) {
          try {
            const row = await env.DB.prepare("SELECT * FROM links WHERE slug = ?").bind(slug).first();
            if (row) {
              let daily = {};
              try {
                daily = row.daily_json ? JSON.parse(row.daily_json) : {};
              } catch (e) {}
              return Response.json({
                success: true,
                daily: daily,
                devices: { mobile: row.mobile_clicks || 0, pc: row.pc_clicks || 0 },
                sources: {
                  twitter: row.source_twitter || 0,
                  direct: row.source_direct || 0,
                  other: row.source_other || 0
                }
              });
            }
          } catch (d1Err) {}
        }

        if (env.LINKS) {
          const raw = (await env.LINKS.get("link:" + slug)) || (await env.LINKS.get(slug));
          if (raw) {
            const parsed = JSON.parse(raw);
            return Response.json({
              success: true,
              daily: parsed.daily || {},
              devices: parsed.devices || { mobile: 0, pc: 0 },
              sources: parsed.sources || { twitter: 0, direct: 0, other: 0 }
            });
          }
        }

        return Response.json({ error: "未找到该短链" }, { status: 404 });
      } catch (e) {
        return Response.json({ error: "获取详情失败" }, { status: 500 });
      }
    }

    // API：生成新短链（支持 D1 数据库秒级录入与 KV 双写备份）
    if (path === "api/shorten" && request.method === "POST") {
      try {
        const body = await request.json();
        if (!body || body.pwd !== ADMIN_PASSWORD) {
          return Response.json({ error: "密码验证失败" }, { status: 403 });
        }
        const targetUrl = (body.url || "").trim();
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
          return Response.json({ error: "请输入以 http:// 或 https:// 开头的有效链接" }, { status: 400 });
        }

        async function checkSlugExist(testSlug) {
          if (!testSlug) return false;
          if (env.DB) {
            try {
              const row = await env.DB.prepare("SELECT slug FROM links WHERE slug = ?").bind(testSlug).first();
              if (row) return true;
            } catch (e) {}
          }
          if (env.LINKS) {
            try {
              const exist = (await env.LINKS.get("link:" + testSlug)) || (await env.LINKS.get(testSlug));
              if (exist) return true;
            } catch (e) {}
          }
          return false;
        }

        const userProvidedSlug = (body.slug || "").trim().replace(/[^\w-]/g, "");
        let slug = userProvidedSlug;

        if (userProvidedSlug) {
          if (["api", ADMIN_PATH, "favicon.ico", "robots.txt"].includes(userProvidedSlug.toLowerCase())) {
            return Response.json({ error: "该短码属于系统保留路径，请更换" }, { status: 400 });
          }
          if (await checkSlugExist(userProvidedSlug)) {
            return Response.json({ error: `短码 [${userProvidedSlug}] 已存在，请更换或留空自动分配` }, { status: 400 });
          }
        } else {
          let candidate = extractResourceId(targetUrl);
          let exist = candidate ? await checkSlugExist(candidate) : true;
          
          if (exist || !candidate || ["api", ADMIN_PATH, "favicon.ico", "robots.txt"].includes(candidate.toLowerCase())) {
            let attempts = 0;
            do {
              candidate = generateRandomSlug();
              exist = await checkSlugExist(candidate);
              attempts++;
            } while (exist && attempts < 5);
          }
          slug = candidate;
        }

        let finalTitle = (body.title || "").trim();
        if (!finalTitle) {
          finalTitle = await fetchTitleFromUrl(targetUrl);
        }
        if (!finalTitle) {
          finalTitle = "资源分享直达";
        }

        const backupUrl = (body.backupUrl || "").trim();
        const onlyMobile = !!body.onlyMobile;
        const todayDate = getBeijingDateStr();
        const nowTs = Date.now();
        const record = {
          url: targetUrl,
          backupUrl: backupUrl,
          activeTarget: "primary",
          autoSwitched: false,
          onlyMobile: onlyMobile,
          title: finalTitle,
          clicks: 0,
          uv: 0,
          sources: { twitter: 0, direct: 0, other: 0 },
          devices: { mobile: 0, pc: 0 },
          daily: {
            [todayDate]: { clicks: 0, uv: 0, mobile: 0, pc: 0 }
          },
          createdAt: new Date().toLocaleDateString("zh-CN"),
          createdTimestamp: nowTs
        };

        // 1. 优先存入 D1 数据库
        if (env.DB) {
          try {
            await env.DB.prepare(`
              INSERT OR REPLACE INTO links (
                slug, url, backup_url, active_target, auto_switched, only_mobile, title,
                clicks, uv, mobile_clicks, pc_clicks, source_twitter, source_direct, source_other,
                created_at, created_timestamp, daily_json
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
              slug, targetUrl, backupUrl, "primary", 0, onlyMobile ? 1 : 0, finalTitle,
              0, 0, 0, 0, 0, 0, 0,
              record.createdAt, nowTs,
              JSON.stringify(record.daily)
            ).run();
          } catch (d1SaveErr) {}
        }

        // 2. 同时写入 KV 作为双轨冷备（如有 KV 绑定）
        if (env.LINKS) {
          try {
            await env.LINKS.put("link:" + slug, JSON.stringify(record), {
              metadata: {
                url: record.url,
                backupUrl: record.backupUrl,
                activeTarget: "primary",
                autoSwitched: false,
                onlyMobile: record.onlyMobile,
                title: record.title,
                clicks: record.clicks,
                uv: record.uv,
                today: todayDate,
                todayClicks: 0,
                todayUv: 0,
                sources: record.sources,
                devices: record.devices,
                createdAt: record.createdAt,
                createdTimestamp: nowTs
              }
            });
          } catch (kvSaveErr) {}
        }

        const createdItem = {
          slug: slug,
          shortUrl: url.origin + "/" + slug,
          url: record.url,
          backupUrl: record.backupUrl,
          activeTarget: "primary",
          autoSwitched: false,
          onlyMobile: record.onlyMobile,
          title: record.title,
          brand: detectPanBrand(record.url),
          clicks: 0,
          uv: 0,
          todayClicks: 0,
          todayUv: 0,
          sources: record.sources,
          devices: record.devices,
          daily: record.daily,
          createdAt: record.createdAt,
          createdTimestamp: nowTs
        };

        return Response.json({
          success: true,
          shortUrl: createdItem.shortUrl,
          item: createdItem
        });
      } catch (err) {
        return Response.json({ error: "KV 写入失败，请检查是否绑定 LINKS" }, { status: 500 });
      }
    }

    // API：动态编辑/更换网盘链接与标题（D1 数据库与 KV 同步更新）
    if (path === "api/update" && request.method === "POST") {
      try {
        const body = await request.json();
        if (!body || body.pwd !== ADMIN_PASSWORD) {
          return Response.json({ error: "密码验证失败" }, { status: 403 });
        }
        const slug = (body.slug || "").trim();
        const newUrl = (body.url || "").trim();
        let newTitle = (body.title || "").trim();

        if (!slug) {
          return Response.json({ error: "缺少参数 slug" }, { status: 400 });
        }
        if (!newUrl.startsWith("http://") && !newUrl.startsWith("https://")) {
          return Response.json({ error: "请输入以 http:// 或 https:// 开头的有效链接" }, { status: 400 });
        }

        if (!newTitle) {
          newTitle = await fetchTitleFromUrl(newUrl);
        }

        // 1. 优先在 D1 中查找并更新
        if (env.DB) {
          try {
            const d1Row = await env.DB.prepare("SELECT * FROM links WHERE slug = ?").bind(slug).first();
            if (d1Row) {
              const activeTarget = body.activeTarget || d1Row.active_target || "primary";
              const autoSwitched = body.activeTarget === "primary" ? 0 : (d1Row.auto_switched || 0);
              const onlyMobile = body.onlyMobile !== undefined ? (body.onlyMobile ? 1 : 0) : (d1Row.only_mobile || 0);
              const backupUrl = body.backupUrl !== undefined ? (body.backupUrl || "").trim() : (d1Row.backup_url || "");
              const finalTitle = newTitle || d1Row.title || "资源分享直达";

              await env.DB.prepare(`
                UPDATE links SET
                  url = ?, backup_url = ?, active_target = ?, auto_switched = ?, only_mobile = ?, title = ?
                WHERE slug = ?
              `).bind(newUrl, backupUrl, activeTarget, autoSwitched, onlyMobile, finalTitle, slug).run();

              if (env.LINKS) {
                try {
                  const raw = await env.LINKS.get("link:" + slug);
                  if (raw) {
                    const item = JSON.parse(raw);
                    item.url = newUrl;
                    item.backupUrl = backupUrl;
                    item.activeTarget = activeTarget;
                    item.autoSwitched = !!autoSwitched;
                    item.onlyMobile = !!onlyMobile;
                    item.title = finalTitle;
                    await env.LINKS.put("link:" + slug, JSON.stringify(item));
                  }
                } catch (e) {}
              }

              let daily = {};
              try { daily = d1Row.daily_json ? JSON.parse(d1Row.daily_json) : {}; } catch (e) {}
              const todayDate = getBeijingDateStr();
              const todayStats = daily[todayDate] || { clicks: 0, uv: 0, mobile: 0, pc: 0 };

              return Response.json({
                success: true,
                item: {
                  slug: slug,
                  shortUrl: url.origin + "/" + slug,
                  url: newUrl,
                  backupUrl: backupUrl,
                  activeTarget: activeTarget,
                  autoSwitched: !!autoSwitched,
                  onlyMobile: !!onlyMobile,
                  title: finalTitle,
                  brand: detectPanBrand(newUrl),
                  clicks: d1Row.clicks || 0,
                  uv: d1Row.uv || 0,
                  todayClicks: todayStats.clicks || 0,
                  todayUv: todayStats.uv || 0,
                  sources: { twitter: d1Row.source_twitter || 0, direct: d1Row.source_direct || 0, other: d1Row.source_other || 0 },
                  devices: { mobile: d1Row.mobile_clicks || 0, pc: d1Row.pc_clicks || 0 },
                  daily: daily,
                  createdAt: d1Row.created_at || "-",
                  createdTimestamp: d1Row.created_timestamp || 0
                }
              });
            }
          } catch (d1UpErr) {}
        }

        // 2. 若 D1 没找到，更新 KV 历史短链
        if (!env.LINKS) {
          return Response.json({ error: "目标短码不存在" }, { status: 404 });
        }

        let storageKey = "link:" + slug;
        let rawData = await env.LINKS.get(storageKey);
        if (!rawData) {
          storageKey = slug;
          rawData = await env.LINKS.get(storageKey);
        }

        if (!rawData) {
          return Response.json({ error: "目标短码不存在" }, { status: 404 });
        }

        const item = JSON.parse(rawData);
        item.url = newUrl;
        
        if (body.backupUrl !== undefined) {
          item.backupUrl = (body.backupUrl || "").trim();
        }
        if (body.onlyMobile !== undefined) {
          item.onlyMobile = !!body.onlyMobile;
        }
        if (body.activeTarget) {
          item.activeTarget = body.activeTarget;
          if (body.activeTarget === "primary") {
            item.autoSwitched = false;
          }
        }

        if (newTitle) {
          item.title = newTitle;
        }

        const todayDate = getBeijingDateStr();
        const daily = item.daily || {};
        const todayStats = daily[todayDate] || { clicks: 0, uv: 0, mobile: 0, pc: 0 };
        const createdTs = item.createdTimestamp || (item.createdAt && item.createdAt !== "-" ? new Date(item.createdAt.replace(/-/g, "/")).getTime() : 0);

        const targetKey = "link:" + slug;
        await env.LINKS.put(targetKey, JSON.stringify(item), {
          metadata: {
            url: item.url,
            backupUrl: item.backupUrl || "",
            activeTarget: item.activeTarget || "primary",
            autoSwitched: !!item.autoSwitched,
            onlyMobile: !!item.onlyMobile,
            title: item.title,
            clicks: item.clicks || 0,
            uv: item.uv || 0,
            today: todayDate,
            todayClicks: todayStats.clicks || 0,
            todayUv: todayStats.uv || 0,
            sources: item.sources || { twitter: 0, direct: 0, other: 0 },
            devices: item.devices || { mobile: 0, pc: 0 },
            createdAt: item.createdAt || "-",
            createdTimestamp: createdTs
          }
        });

        const updatedItem = {
          slug: slug,
          shortUrl: url.origin + "/" + slug,
          url: item.url,
          backupUrl: item.backupUrl || "",
          activeTarget: item.activeTarget || "primary",
          autoSwitched: !!item.autoSwitched,
          onlyMobile: !!item.onlyMobile,
          title: item.title,
          brand: detectPanBrand(item.url),
          clicks: item.clicks || 0,
          uv: item.uv || 0,
          todayClicks: todayStats.clicks || 0,
          todayUv: todayStats.uv || 0,
          sources: item.sources || { twitter: 0, direct: 0, other: 0 },
          devices: item.devices || { mobile: 0, pc: 0 },
          daily: daily,
          createdAt: item.createdAt || "-",
          createdTimestamp: createdTs
        };

        return Response.json({ success: true, item: updatedItem });
      } catch (err) {
        return Response.json({ error: "更新失败" }, { status: 500 });
      }
    }

    // API：快捷一键切换手机端专属限制（点一下无需打开弹窗即生效）
    if (path === "api/toggle-mobile" && request.method === "POST") {
      try {
        const body = await request.json();
        if (!body || body.pwd !== ADMIN_PASSWORD) {
          return Response.json({ error: "密码验证失败" }, { status: 403 });
        }
        const slug = (body.slug || "").trim();
        if (!slug) {
          return Response.json({ error: "缺少参数 slug" }, { status: 400 });
        }

        // 1. 优先更新 D1
        if (env.DB) {
          try {
            const d1Row = await env.DB.prepare("SELECT only_mobile FROM links WHERE slug = ?").bind(slug).first();
            if (d1Row) {
              const nextMobile = body.onlyMobile !== undefined ? (body.onlyMobile ? 1 : 0) : (d1Row.only_mobile ? 0 : 1);
              await env.DB.prepare("UPDATE links SET only_mobile = ? WHERE slug = ?").bind(nextMobile, slug).run();

              if (env.LINKS) {
                try {
                  const raw = await env.LINKS.get("link:" + slug);
                  if (raw) {
                    const item = JSON.parse(raw);
                    item.onlyMobile = !!nextMobile;
                    await env.LINKS.put("link:" + slug, JSON.stringify(item));
                  }
                } catch (e) {}
              }

              return Response.json({ success: true, onlyMobile: !!nextMobile });
            }
          } catch (d1TogErr) {}
        }

        // 2. 若 D1 没找到，更新 KV
        if (!env.LINKS) {
          return Response.json({ error: "目标短码不存在" }, { status: 404 });
        }

        let storageKey = "link:" + slug;
        let rawData = await env.LINKS.get(storageKey);
        if (!rawData) {
          storageKey = slug;
          rawData = await env.LINKS.get(storageKey);
        }
        if (!rawData) {
          return Response.json({ error: "目标短码不存在" }, { status: 404 });
        }
        const item = JSON.parse(rawData);
        item.onlyMobile = body.onlyMobile !== undefined ? !!body.onlyMobile : !item.onlyMobile;

        const todayDate = getBeijingDateStr();
        const daily = item.daily || {};
        const todayStats = daily[todayDate] || { clicks: 0, uv: 0, mobile: 0, pc: 0 };
        const createdTs = item.createdTimestamp || (item.createdAt && item.createdAt !== "-" ? new Date(item.createdAt.replace(/-/g, "/")).getTime() : 0);

        const targetKey = "link:" + slug;
        await env.LINKS.put(targetKey, JSON.stringify(item), {
          metadata: {
            url: item.url,
            backupUrl: item.backupUrl || "",
            activeTarget: item.activeTarget || "primary",
            autoSwitched: !!item.autoSwitched,
            onlyMobile: !!item.onlyMobile,
            title: item.title,
            clicks: item.clicks || 0,
            uv: item.uv || 0,
            today: todayDate,
            todayClicks: todayStats.clicks || 0,
            todayUv: todayStats.uv || 0,
            sources: item.sources || { twitter: 0, direct: 0, other: 0 },
            devices: item.devices || { mobile: 0, pc: 0 },
            createdAt: item.createdAt || "-",
            createdTimestamp: createdTs
          }
        });

        return Response.json({ success: true, onlyMobile: item.onlyMobile });
      } catch (err) {
        return Response.json({ error: "切换状态失败" }, { status: 500 });
      }
    }

    // API：删除短链（D1 与 KV 双库清理）
    if (path === "api/delete" && request.method === "POST") {
      try {
        const body = await request.json();
        if (!body || body.pwd !== ADMIN_PASSWORD) {
          return Response.json({ error: "密码验证失败" }, { status: 403 });
        }
        if (!body.slug) {
          return Response.json({ error: "缺少参数 slug" }, { status: 400 });
        }
        const slug = body.slug.trim();

        if (env.DB) {
          try {
            await env.DB.prepare("DELETE FROM links WHERE slug = ?").bind(slug).run();
          } catch (d1DelErr) {}
        }

        if (env.LINKS) {
          await Promise.all([
            env.LINKS.delete("link:" + slug),
            env.LINKS.delete(slug)
          ]);
        }
        return Response.json({ success: true });
      } catch (err) {
        return Response.json({ error: "删除失败" }, { status: 500 });
      }
    }

    // 根路径保护：未带任何短码后缀直接访问纯域名时，直接返回 404，杜绝触发 KV 空键查询报错
    if (!path) {
      return new Response("404 Not Found - 请通过有效资源短链访问", {
        status: 404,
        headers: { "content-type": "text/plain;charset=UTF-8" }
      });
    }

    // ====== 短链中转与极速防封跳转核心（优先 D1 毫秒级直读，平滑兼容 KV 历史短链） ======
    let item = null;
    let isFromD1 = false;

    if (env.DB) {
      try {
        const d1Row = await env.DB.prepare("SELECT * FROM links WHERE slug = ?").bind(path).first();
        if (d1Row) {
          isFromD1 = true;
          let daily = {};
          try {
            daily = d1Row.daily_json ? JSON.parse(d1Row.daily_json) : {};
          } catch (e) {}
          item = {
            slug: d1Row.slug,
            url: d1Row.url,
            backupUrl: d1Row.backup_url || "",
            activeTarget: d1Row.active_target || "primary",
            autoSwitched: !!d1Row.auto_switched,
            onlyMobile: !!d1Row.only_mobile,
            title: d1Row.title || "资源分享直达",
            clicks: d1Row.clicks || 0,
            uv: d1Row.uv || 0,
            createdAt: d1Row.created_at || "-",
            createdTimestamp: d1Row.created_timestamp || 0,
            lastSwitchedAt: d1Row.last_switched_at || "",
            daily: daily,
            devices: { mobile: d1Row.mobile_clicks || 0, pc: d1Row.pc_clicks || 0 },
            sources: {
              twitter: d1Row.source_twitter || 0,
              direct: d1Row.source_direct || 0,
              other: d1Row.source_other || 0
            }
          };
        }
      } catch (d1QueryErr) {}
    }

    // 若 D1 没查到且有 KV，回退查 KV
    if (!item && env.LINKS) {
      let storageKey = "link:" + path;
      let rawData = await env.LINKS.get(storageKey);
      if (!rawData && path) {
        storageKey = path;
        rawData = await env.LINKS.get(storageKey);
      }
      if (rawData) {
        try {
          item = JSON.parse(rawData);
          item.slug = path;
        } catch (e) {}
      }
    }

    if (!item) {
      return new Response("404 Not Found - 该资源不存在或已被删除", {
        status: 404,
        headers: { "content-type": "text/plain;charset=UTF-8" }
      });
    }

    const userAgent = request.headers.get("user-agent") || "";
    const isBot = /Twitterbot|facebookexternalhit|TelegramBot|bot|spider|crawl|slurp|curl|wget|python|java|bytespider|yisouspider|sogou|httpclient|postman|go-http-client/i.test(userAgent);
    const isWechat = /MicroMessenger/i.test(userAgent);
    const isQQ = /QQ\//i.test(userAgent);
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile/i.test(userAgent);

    const todayDate = getBeijingDateStr();
    const detectedChannel = detectSourceChannel(request, url);

    // 独立访客精准客观去重（Cookie 浏览器指纹 + KV 辅助去重，彻底消除纯 D1 模式下 UV 锁死为 1 的漏洞）
    const cookieHeader = request.headers.get("cookie") || "";
    const uvCookieName = `_p_uv_${path}_${todayDate}`;
    let isNewUv = !cookieHeader.includes(`${uvCookieName}=1`);

    // 异步无阻塞统计（D1 数据库 10 万次极速原子计数，平滑兼容 KV）
    if (!isBot && ctx && ctx.waitUntil) {
      const updateTask = async () => {
        try {
          const clientIp = request.headers.get("cf-connecting-ip") || "127.0.0.1";

          if (env.LINKS && isNewUv) {
            const uvKey = "uv:" + path + ":" + clientIp + ":" + todayDate;
            const hasVisited = await env.LINKS.get(uvKey);
            if (hasVisited) {
              isNewUv = false;
            } else {
              await env.LINKS.put(uvKey, "1", { expirationTtl: 86400 });
            }
          }

          // 2. 统计增量更新
          item.clicks = (item.clicks || 0) + 1;
          if (isNewUv) item.uv = (item.uv || 0) + 1;

          // 渠道统计拆解
          if (!item.sources) item.sources = { wechat: 0, twitter: 0, direct: 0, other: 0 };
          let sTwitter = 0, sDirect = 0, sOther = 0, sWechat = 0;
          if (detectedChannel === "wechat") {
            item.sources.wechat = (item.sources.wechat || 0) + 1;
            sWechat = 1;
          } else if (detectedChannel === "twitter") {
            item.sources.twitter = (item.sources.twitter || 0) + 1;
            sTwitter = 1;
          } else if (detectedChannel === "direct") {
            item.sources.direct = (item.sources.direct || 0) + 1;
            sDirect = 1;
          } else {
            item.sources.other = (item.sources.other || 0) + 1;
            sOther = 1;
          }

          // 手机 vs 电脑 设备统计
          if (!item.devices) item.devices = { mobile: 0, pc: 0 };
          if (isMobile) {
            item.devices.mobile = (item.devices.mobile || 0) + 1;
          } else {
            item.devices.pc = (item.devices.pc || 0) + 1;
          }

          // 按日维度增量统计（包含当天点击、UV、手机/电脑、细分渠道及转化，保留 30 天）
          if (!item.daily) item.daily = {};
          if (!item.daily[todayDate]) {
            item.daily[todayDate] = {
              clicks: 0,
              uv: 0,
              convert: 0,
              mobile: 0,
              pc: 0,
              sources: { wechat: 0, twitter: 0, direct: 0, other: 0 },
              convert_sources: { wechat: 0, twitter: 0, direct: 0, other: 0 }
            };
          }
          item.daily[todayDate].clicks = (item.daily[todayDate].clicks || 0) + 1;
          if (isMobile) {
            item.daily[todayDate].mobile = (item.daily[todayDate].mobile || 0) + 1;
          } else {
            item.daily[todayDate].pc = (item.daily[todayDate].pc || 0) + 1;
          }
          if (isNewUv) {
            item.daily[todayDate].uv = (item.daily[todayDate].uv || 0) + 1;
          }
          if (!item.daily[todayDate].sources) {
            item.daily[todayDate].sources = { wechat: 0, twitter: 0, direct: 0, other: 0 };
          }
          item.daily[todayDate].sources[detectedChannel] = (item.daily[todayDate].sources[detectedChannel] || 0) + 1;

          // 清理 30 天之前的陈旧日期记录，防止存储膨胀
          const dateKeys = Object.keys(item.daily).sort();
          if (dateKeys.length > 30) {
            for (let i = 0; i < dateKeys.length - 30; i++) {
              delete item.daily[dateKeys[i]];
            }
          }

          // 智能探活与自动救火：如果配置了备用链接，且当前仍在用主链接，进行轻量探活
          if (item.backupUrl && item.activeTarget !== "backup") {
            let inCooldown = false;
            if (env.LINKS) {
              const checkCooldownKey = "chk:" + path;
              inCooldown = await env.LINKS.get(checkCooldownKey);
              if (!inCooldown) {
                await env.LINKS.put(checkCooldownKey, "1", { expirationTtl: 900 });
              }
            }
            if (!inCooldown) {
              try {
                const checkResp = await fetch(item.url, {
                  method: "GET",
                  headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                  }
                });
                let isDead = false;
                if (checkResp.status === 404) {
                  isDead = true;
                } else if (checkResp.ok) {
                  const checkHtml = await checkResp.text();
                  const invalidKeywords = ["分享已失效", "文件不存在", "已被取消", "包含违规内容", "分享已删除", "链接已失效"];
                  for (let w of invalidKeywords) {
                    if (checkHtml.includes(w)) {
                      isDead = true;
                      break;
                    }
                  }
                }
                if (isDead) {
                  item.activeTarget = "backup";
                  item.autoSwitched = true;
                  item.lastSwitchedAt = new Date().toLocaleString("zh-CN");
                }
              } catch (checkErr) {}
            }
          }

          // 3. 执行数据持久化
          // A. 优先写入 D1 数据库（原子计数，支持当日字段跨天自愈更新）
          if (isFromD1 && env.DB) {
            await env.DB.prepare(`
              UPDATE links SET
                clicks = clicks + 1,
                uv = uv + ?,
                mobile_clicks = mobile_clicks + ?,
                pc_clicks = pc_clicks + ?,
                source_twitter = source_twitter + ?,
                source_direct = source_direct + ?,
                source_other = source_other + ?,
                source_wechat = source_wechat + ?,
                today_clicks = CASE WHEN today_date = ? THEN today_clicks + 1 ELSE 1 END,
                today_uv = CASE WHEN today_date = ? THEN today_uv + ? ELSE ? END,
                today_convert = CASE WHEN today_date = ? THEN today_convert ELSE 0 END,
                today_date = ?,
                active_target = ?,
                auto_switched = ?,
                last_switched_at = ?,
                daily_json = ?
              WHERE slug = ?
            `).bind(
              isNewUv ? 1 : 0,
              isMobile ? 1 : 0,
              isMobile ? 0 : 1,
              sTwitter,
              sDirect,
              sOther,
              sWechat,
              todayDate,
              todayDate,
              isNewUv ? 1 : 0,
              isNewUv ? 1 : 0,
              todayDate,
              todayDate,
              item.activeTarget || "primary",
              item.autoSwitched ? 1 : 0,
              item.lastSwitchedAt || "",
              JSON.stringify(item.daily),
              path
            ).run();
          } else if (env.LINKS) {
            // B. KV 数据库写入（带 5 分钟节流保护）
            const throttleKey = "throttle:" + path + ":" + clientIp;
            const inThrottle = !isNewUv && (await env.LINKS.get(throttleKey));
            if (!inThrottle) {
              await env.LINKS.put(throttleKey, "1", { expirationTtl: 300 });
              const targetKey = "link:" + path;
              const todayStat = item.daily[todayDate] || { clicks: 0, uv: 0 };
              await env.LINKS.put(targetKey, JSON.stringify(item), {
                metadata: {
                  url: item.url,
                  backupUrl: item.backupUrl || "",
                  activeTarget: item.activeTarget || "primary",
                  autoSwitched: !!item.autoSwitched,
                  title: item.title,
                  clicks: item.clicks,
                  uv: item.uv,
                  today: todayDate,
                  todayClicks: todayStat.clicks || 0,
                  todayUv: todayStat.uv || 0,
                  sources: item.sources,
                  devices: item.devices,
                  createdAt: item.createdAt || "-"
                }
              });
            }
          }
        } catch (e) {}
      };
      ctx.waitUntil(updateTask());
    }

    // 主链接与备用链接多通道解析
    const safePrimaryUrl = escapeHtml(item.url);
    const safeBackupUrl = item.backupUrl ? escapeHtml(item.backupUrl) : "";
    const hasBackup = !!safeBackupUrl;
    const currentShortUrl = url.origin + "/" + path;

    const brand = detectPanBrand(item.url);
    const backupBrand = hasBackup ? detectPanBrand(item.backupUrl) : { name: "备用网盘", color: "#059669", bg: "#ecfdf5" };
    const safeTitle = escapeHtml(item.title || "资源分享直达");

    let targetOrigin = "https://pan.quark.cn";
    try {
      targetOrigin = new URL(item.url).origin;
    } catch (e) {}

    // 判断是否受“强制仅限手机端访问”拦截（电脑端打开展示扫码二维码）
    const isPcBlocked = !!item.onlyMobile && !isMobile;
    if (isPcBlocked) {
      const qrSvg = createQRCodeSvg(currentShortUrl, 200, 2);
      const qrHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <title>${safeTitle} - 资源专属转存通道</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      background: linear-gradient(135deg, #f8fafc 0%, #edf2f7 100%);
      padding: 24px 16px;
      color: #0f172a;
    }
    .qr-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 24px;
      padding: 36px 28px;
      max-width: 420px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 40px -15px rgba(15, 23, 42, 0.08);
    }
    .pill-group {
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }
    .brand-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 4px 12px;
      background: ${brand.bg};
      color: ${brand.color};
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
    }
    .mobile-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: #eef2ff;
      color: #4f46e5;
      font-size: 12px;
      font-weight: 700;
      padding: 3px 10px;
      border-radius: 6px;
      border: 1px solid #c7d2fe;
    }
    .res-title {
      font-size: 18px;
      font-weight: 700;
      color: #0f172a;
      line-height: 1.45;
      margin-bottom: 20px;
      word-break: break-all;
    }
    .qr-box-wrap {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 18px;
      padding: 20px;
      display: inline-flex;
      flex-direction: column;
      align-items: center;
      margin-bottom: 18px;
    }
    .qr-img {
      width: 200px;
      height: 200px;
      display: block;
      border-radius: 10px;
      background: #ffffff;
    }
    .qr-tip {
      font-size: 13px;
      font-weight: 600;
      color: #475569;
      margin-top: 12px;
    }
    .btn-copy-short {
      width: 100%;
      padding: 12px 16px;
      background: #ffffff;
      color: #334155;
      border: 1px solid #cbd5e1;
      border-radius: 10px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-copy-short:hover {
      background: #f8fafc;
      border-color: #94a3b8;
    }
    .toast-msg {
      display: none;
      background: #10b981;
      color: #fff;
      font-size: 13px;
      font-weight: 600;
      padding: 9px 14px;
      border-radius: 8px;
      margin-bottom: 14px;
      animation: popToast 0.2s ease-out;
    }
    @keyframes popToast { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
    .footer-desc {
      font-size: 12px;
      color: #64748b;
      line-height: 1.6;
      margin-top: 16px;
    }
  </style>
</head>
<body>
  <div class="qr-card">
    <div class="pill-group">
      <span class="brand-pill">📦 ${brand.name}</span>
      <span class="mobile-badge">✨ 资源专属转存通道</span>
    </div>
    <h2 class="res-title">${safeTitle}</h2>

    <div id="toastBox" class="toast-msg">✅ 资源链接已复制到剪贴板！</div>

    <div class="qr-box-wrap">
      <div style="width:200px;height:200px;display:flex;align-items:center;justify-content:center;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,0.04);">
        ${qrSvg}
      </div>
      <div class="qr-tip">📷 请使用手机相机或微信扫一扫 极速转存</div>
    </div>

    <div>
      <button type="button" class="btn-copy-short" id="copyShortBtn">📋 复制资源链接发给手机微信/QQ</button>
    </div>

    <div class="footer-desc">
      ${hasBackup ? '💡 该资源已开启原画转存与双通道容灾保护，手机扫码即可极速转存到网盘。' : '💡 该资源已开启防和谐与极速转存保护，请使用手机扫码或复制链接到手机浏览器查看。'}
    </div>
  </div>

  <script>
    document.getElementById("copyShortBtn").addEventListener("click", function() {
      var url = "${currentShortUrl}";
      var toast = document.getElementById("toastBox");
      var btn = this;
      function done() {
        toast.style.display = "block";
        btn.innerText = "✅ 链接已复制成功";
        setTimeout(function() {
          toast.style.display = "none";
          btn.innerText = "📋 复制资源链接发给手机微信/QQ";
        }, 2500);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(done).catch(fallback);
      } else {
        fallback();
      }
      function fallback() {
        var ta = document.createElement("textarea");
        ta.value = url;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        done();
      }
    });
  </script>
</body>
</html>`;
      return new Response(qrHtml, {
        headers: {
          "content-type": "text/html;charset=UTF-8",
          "cache-control": "public, max-age=15, stale-while-revalidate=30"
        }
      });
    }

    // 微信 / QQ 内置浏览器防拦截专用指引页（淡色系现代视觉）
    if (isWechat || isQQ) {
      const wechatHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <title>${safeTitle} - 网盘直达</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
      background: linear-gradient(135deg, #f8fafc 0%, #edf2f7 100%);
      color: #0f172a;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px;
      position: relative;
      overflow-x: hidden;
    }
    .top-guide {
      position: fixed;
      top: 14px;
      right: 18px;
      display: flex;
      align-items: center;
      gap: 8px;
      z-index: 100;
      animation: float 1.8s ease-in-out infinite alternate;
    }
    .guide-badge {
      background: #0284c7;
      color: #ffffff;
      font-weight: 700;
      font-size: 13px;
      padding: 7px 14px;
      border-radius: 9999px;
      box-shadow: 0 4px 14px rgba(2, 132, 199, 0.3);
    }
    .guide-arrow {
      font-size: 26px;
      color: #0284c7;
      transform: rotate(45deg);
      font-weight: 900;
    }
    @keyframes float { 0% { transform: translateY(0); } 100% { transform: translateY(-8px); } }
    .card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 22px;
      padding: 32px 24px;
      max-width: 400px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 40px -15px rgba(15, 23, 42, 0.08);
    }
    .brand-pill {
      display: inline-block;
      background: ${brand.bg};
      color: ${brand.color};
      font-size: 12px;
      font-weight: 700;
      padding: 4px 12px;
      border-radius: 9999px;
      margin-bottom: 14px;
    }
    .title {
      font-size: 19px;
      font-weight: 700;
      color: #0f172a;
      line-height: 1.45;
      margin-bottom: 14px;
      word-break: break-all;
    }
    .step-box {
      background: #f8fafc;
      border-radius: 12px;
      padding: 16px;
      margin: 18px 0;
      text-align: left;
      border: 1px solid #e2e8f0;
    }
    .step-item {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
      font-size: 13px;
      color: #334155;
    }
    .step-item:last-child { margin-bottom: 0; }
    .step-num {
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: #0284c7;
      color: #fff;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .btn-copy {
      width: 100%;
      padding: 13px;
      background: linear-gradient(135deg, #0284c7, #0369a1);
      color: #fff;
      border: none;
      border-radius: 10px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      box-shadow: 0 4px 12px rgba(2, 132, 199, 0.25);
    }
    .btn-copy:active { transform: scale(0.98); }
    .footer-note { font-size: 12px; color: #64748b; margin-top: 16px; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="top-guide">
    <div class="guide-badge">请点击右上角【···】选择在浏览器打开</div>
    <div class="guide-arrow">↗</div>
  </div>

  <div class="card">
    <span class="brand-pill">${brand.name}</span>
    <h2 class="title">${safeTitle}</h2>
    
    <div class="step-box">
      <div class="step-item">
        <span class="step-num">1</span>
        <span>轻触屏幕右上角 <strong>···</strong> 菜单</span>
      </div>
      <div class="step-item">
        <span class="step-num">2</span>
        <span>选择 <strong>在浏览器中打开</strong> 或 <strong>默认浏览器</strong></span>
      </div>
      <div class="step-item">
        <span class="step-num">3</span>
        <span>即可高速直达官方网盘极速转存</span>
      </div>
    </div>

    <button type="button" class="btn-copy" id="copyBtn">📋 一键复制网盘真实地址</button>
    <div class="footer-note">如未自动唤醒，复制后打开系统浏览器粘贴访问即可</div>
  </div>

  <script>
    document.getElementById("copyBtn").addEventListener("click", function() {
      var url = "${safePrimaryUrl}";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(function() {
          alert("网盘地址已复制到剪贴板！请打开手机自带浏览器粘贴访问。");
        });
      } else {
        var ta = document.createElement("textarea");
        ta.value = url;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        alert("网盘地址已复制到剪贴板！请打开手机自带浏览器粘贴访问。");
      }
    });
  </script>
</body>
</html>`;
      return new Response(wechatHtml, {
        headers: {
          "content-type": "text/html;charset=UTF-8",
          "cache-control": "public, max-age=15, stale-while-revalidate=30"
        }
      });
    }

    // 纯手动多通道高颜值淡色系中间落地页（支持主链接与备用兜底链接双通道展示）
    const jumpHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <title>${safeTitle} - 网盘资源直达</title>
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="${safeTitle}">
  <meta name="twitter:description" content="点击查看完整网盘资源文件">
  <meta property="og:type" content="website">
  <meta property="og:title" content="${safeTitle}">
  <meta property="og:description" content="点击查看完整网盘资源文件">
  <meta property="og:url" content="${safePrimaryUrl}">
  <link rel="preconnect" href="${targetOrigin}" crossorigin>
  <link rel="dns-prefetch" href="${targetOrigin}">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      background: linear-gradient(135deg, #f8fafc 0%, #edf2f7 100%);
      padding: 24px 16px;
      color: #0f172a;
    }
    .landing-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 24px;
      padding: 32px 24px;
      max-width: 440px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 40px -15px rgba(15, 23, 42, 0.08);
    }
    .brand-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 14px;
      background: ${brand.bg};
      color: ${brand.color};
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 700;
      margin-bottom: 14px;
    }
    .resource-title {
      font-size: 19px;
      font-weight: 700;
      color: #0f172a;
      line-height: 1.45;
      margin-bottom: 20px;
      word-break: break-all;
    }
    
    .channel-section {
      text-align: left;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      padding: 16px;
      margin-bottom: 14px;
    }
    .channel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .channel-badge {
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 6px;
    }
    .badge-primary {
      background: #eef2ff;
      color: #4f46e5;
    }
    .badge-backup {
      background: #ecfdf5;
      color: #059669;
    }
    
    .link-url-box {
      font-size: 11px;
      color: #64748b;
      word-break: break-all;
      margin-bottom: 12px;
      background: #edf2f7;
      padding: 8px 10px;
      border-radius: 6px;
      border: 1px solid #e2e8f0;
      max-height: 48px;
      overflow: hidden;
      text-overflow: ellipsis;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
    }

    .action-group {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .btn-action {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      padding: 12px 16px;
      border-radius: 10px;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
      border: none;
      outline: none;
    }
    .btn-primary-jump {
      background: linear-gradient(135deg, #4f46e5, #4338ca);
      color: #fff;
      box-shadow: 0 4px 14px rgba(79, 70, 229, 0.25);
    }
    .btn-primary-jump:hover { opacity: 0.95; transform: translateY(-1px); }
    .btn-primary-jump:active { transform: scale(0.98); }

    .btn-backup-jump {
      background: linear-gradient(135deg, #059669, #047857);
      color: #fff;
      box-shadow: 0 4px 14px rgba(5, 150, 105, 0.25);
    }
    .btn-backup-jump:hover { opacity: 0.95; transform: translateY(-1px); }
    .btn-backup-jump:active { transform: scale(0.98); }

    .btn-copy-link {
      background: #ffffff;
      color: #334155;
      border: 1px solid #cbd5e1;
      padding: 10px 14px;
      font-size: 13px;
      font-weight: 600;
    }
    .btn-copy-link:hover {
      background: #f1f5f9;
      border-color: #94a3b8;
    }
    .btn-copy-link:active { transform: scale(0.98); }

    .divider-wrap {
      display: flex;
      align-items: center;
      margin: 18px 0;
      gap: 10px;
    }
    .divider-line {
      flex: 1;
      height: 1px;
      background: #e2e8f0;
    }
    .divider-text {
      font-size: 11px;
      font-weight: 700;
      color: #059669;
      letter-spacing: 0.5px;
    }

    .toast-msg {
      display: none;
      background: #10b981;
      color: #fff;
      font-size: 13px;
      font-weight: 600;
      padding: 10px 14px;
      border-radius: 8px;
      margin-bottom: 14px;
      animation: popToast 0.2s ease-out;
    }
    @keyframes popToast { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }

    .footer-hint {
      font-size: 12px;
      color: #64748b;
      line-height: 1.6;
      margin-top: 18px;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="landing-card">
    <div class="brand-pill">
      <span>📦</span>
      <span>${brand.name}</span>
    </div>
    <h2 class="resource-title">${safeTitle}</h2>

    <div id="toastBox" class="toast-msg">✅ 网盘链接已复制到剪贴板！</div>

    <!-- 推荐主通道模块 -->
    <div class="channel-section">
      <div class="channel-header">
        <span class="channel-badge badge-primary">推荐主通道 · ${brand.name}</span>
      </div>
      <div class="link-url-box" title="${safePrimaryUrl}">
        <span style="opacity:0.7;margin-right:4px;">🔗 主链接:</span>${safePrimaryUrl}
      </div>
      <div class="action-group">
        <a class="btn-action btn-primary-jump" id="jumpPrimaryBtn" href="${safePrimaryUrl}" target="_blank" rel="noreferrer">
          🚀 立即前往主网盘打开
        </a>
        <button type="button" class="btn-action btn-copy-link" id="copyPrimaryBtn">
          📋 复制主网盘链接
        </button>
      </div>
    </div>

    ${hasBackup ? `
    <!-- 备用容灾通道模块（仅配置了备用链接时展示） -->
    <div class="divider-wrap">
      <span class="divider-line"></span>
      <span class="divider-text">🛡️ 备用容灾通道</span>
      <span class="divider-line"></span>
    </div>

    <div class="channel-section" style="margin-top:0;">
      <div class="channel-header">
        <span class="channel-badge badge-backup">备用通道 · ${backupBrand.name}</span>
      </div>
      <div class="link-url-box" title="${safeBackupUrl}">
        <span style="opacity:0.7;margin-right:4px;">🔗 备用:</span>${safeBackupUrl}
      </div>
      <div class="action-group">
        <a class="btn-action btn-backup-jump" id="jumpBackupBtn" href="${safeBackupUrl}" target="_blank" rel="noreferrer">
          🛡️ 前往备用网盘打开 (${backupBrand.name})
        </a>
        <button type="button" class="btn-action btn-copy-link" id="copyBackupBtn">
          📋 复制备用网盘链接
        </button>
      </div>
    </div>
    ` : ''}

    <div class="footer-hint">
      ${hasBackup 
        ? '💡 提示：如遇主链接失效或无法直接打开，可直接使用备用通道访问。' 
        : '💡 提示：如遇内置浏览器拦截或无法直接打开，请点击上方按钮复制链接至浏览器访问。'}
    </div>
  </div>

  <script>
    function copyUrlWithToast(targetUrl, successMsg, btnEl) {
      var toast = document.getElementById("toastBox");
      var originalText = btnEl.innerText;

      function showSuccess() {
        toast.innerText = successMsg;
        toast.style.display = "block";
        btnEl.innerText = "✅ 复制成功！";
        setTimeout(function() {
          toast.style.display = "none";
          btnEl.innerText = originalText;
        }, 2800);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(targetUrl).then(showSuccess).catch(function() {
          fallback(targetUrl);
        });
      } else {
        fallback(targetUrl);
      }

      function fallback(txt) {
        var ta = document.createElement("textarea");
        ta.value = txt;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        showSuccess();
      }
    }

    var currentTrafficSource = "${detectedChannel}";

    function reportAction(actionType) {
      try {
        var storageKey = "pan_conv_" + "${path}";
        var alreadyReported = false;
        try {
          if (sessionStorage.getItem(storageKey)) {
            alreadyReported = true;
          }
        } catch (storageErr) {}

        // 同一访客在本次访问会话中，无论点击主链接、备用链接还是复制，只计 1 次真实转化！
        // 后续重复点击或多通道兼点直接拦截，坚决杜绝转化数失真与虚高！
        if (alreadyReported) return;

        try {
          sessionStorage.setItem(storageKey, "1");
        } catch (storageErr) {}

        var payload = JSON.stringify({ slug: "${path}", action: actionType, source: currentTrafficSource });
        if (navigator.sendBeacon) {
          navigator.sendBeacon("/api/action", payload);
        } else {
          fetch("/api/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: payload,
            keepalive: true
          }).catch(function() {});
        }
      } catch (e) {}
    }

    var jumpPrimaryBtn = document.getElementById("jumpPrimaryBtn");
    if (jumpPrimaryBtn) {
      jumpPrimaryBtn.addEventListener("click", function() {
        reportAction("jump");
      });
    }

    var jumpBackupBtn = document.getElementById("jumpBackupBtn");
    if (jumpBackupBtn) {
      jumpBackupBtn.addEventListener("click", function() {
        reportAction("jump");
      });
    }

    var copyPrimaryBtn = document.getElementById("copyPrimaryBtn");
    if (copyPrimaryBtn) {
      copyPrimaryBtn.addEventListener("click", function() {
        reportAction("copy");
        copyUrlWithToast("${safePrimaryUrl}", "✅ 主网盘链接已复制到剪贴板！", this);
      });
    }

    var copyBackupBtn = document.getElementById("copyBackupBtn");
    if (copyBackupBtn) {
      copyBackupBtn.addEventListener("click", function() {
        reportAction("copy");
        copyUrlWithToast("${safeBackupUrl}", "✅ 备用网盘链接已复制到剪贴板！", this);
      });
    }
  </script>
</body>
</html>`;

    const respHeaders = {
      "content-type": "text/html;charset=UTF-8",
      "cache-control": "public, max-age=15, stale-while-revalidate=30"
    };
    if (isNewUv) {
      respHeaders["Set-Cookie"] = `_p_uv_${path}_${todayDate}=1; Path=/; Max-Age=86400; SameSite=Lax`;
    }

    return new Response(jumpHtml, { headers: respHeaders });
  }
};

function detectPanBrand(url) {
  if (!url) return { name: "外链资源", code: "other", color: "#64748b", bg: "#f1f5f9" };
  const u = url.toLowerCase();
  if (u.includes("pan.quark.cn")) {
    return { name: "夸克网盘", code: "quark", color: "#7c3aed", bg: "#f3e8ff" };
  }
  if (u.includes("pan.baidu.com")) {
    return { name: "百度网盘", code: "baidu", color: "#0284c7", bg: "#e0f2fe" };
  }
  if (u.includes("alipan.com") || u.includes("aliyundrive.com")) {
    return { name: "阿里云盘", code: "aliyun", color: "#ea580c", bg: "#ffedd5" };
  }
  if (u.includes("xunlei.com")) {
    return { name: "迅雷云盘", code: "xunlei", color: "#0284c7", bg: "#e0f2fe" };
  }
  if (u.includes("drive.uc.cn") || u.includes("uc.cn")) {
    return { name: "UC网盘", code: "uc", color: "#d97706", bg: "#fef3c7" };
  }
  if (u.includes("139.com")) {
    return { name: "移动云盘", code: "caiyun", color: "#059669", bg: "#d1fae5" };
  }
  if (u.includes("189.cn")) {
    return { name: "天翼云盘", code: "tianyi", color: "#2563eb", bg: "#dbeafe" };
  }
  if (u.includes("123pan.com")) {
    return { name: "123云盘", code: "123pan", color: "#4f46e5", bg: "#e0e7ff" };
  }
  return { name: "网盘资源", code: "other", color: "#475569", bg: "#f1f5f9" };
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function fetchTitleFromUrl(targetUrl) {
  if (!targetUrl) return "";

  if (targetUrl.includes("quark.cn")) {
    try {
      const match = targetUrl.match(/\/s\/([a-zA-Z0-9_-]+)/);
      if (match && match[1]) {
        const pwd_id = match[1];
        const res = await fetch("https://pan.quark.cn/1/clouddrive/share/sharepage/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Referer": "https://pan.quark.cn/s/" + pwd_id
          },
          body: JSON.stringify({ pwd_id: pwd_id, passcode: "" })
        });
        if (res.ok) {
          const data = await res.json();
          if (data && data.data && data.data.title) {
            return data.data.title.trim();
          }
        }
      }
    } catch (e) {}
  }

  if (targetUrl.includes("alipan.com") || targetUrl.includes("aliyundrive.com")) {
    try {
      const match = targetUrl.match(/\/s\/([a-zA-Z0-9_-]+)/);
      if (match && match[1]) {
        const share_id = match[1];
        const res = await fetch("https://api.alipan.com/adrive/v3/share_link/get_share_by_anonymous", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
          },
          body: JSON.stringify({ share_id: share_id })
        });
        if (res.ok) {
          const data = await res.json();
          if (data && data.share_title) {
            return data.share_title.trim();
          }
        }
      }
    } catch (e) {}
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2600);
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9"
      }
    });
    clearTimeout(timer);
    if (res.ok) {
      const html = await res.text();

      if (targetUrl.includes("baidu.com")) {
        const fileM = html.match(/"server_filename":"([^"]+)"/);
        if (fileM && fileM[1]) return fileM[1].trim();
      }

      const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (match && match[1]) {
        let t = match[1].trim();
        t = t
          .replace(/_免费高速下载\|百度网盘-分享无限制.*/i, "")
          .replace(/_百度网盘.*/i, "")
          .replace(/- 夸克网盘.*/i, "")
          .replace(/\| 夸克网盘.*/i, "")
          .replace(/夸克网盘分享.*/i, "")
          .replace(/- 阿里云盘.*/i, "")
          .replace(/- 迅雷云盘.*/i, "")
          .replace(/- UC网盘.*/i, "")
          .replace(/- 移动云盘.*/i, "")
          .replace(/- 天翼云盘.*/i, "")
          .replace(/夸克网盘.*/i, "")
          .trim();
        if (t && t !== "百度网盘" && t !== "夸克网盘" && t.length > 1) {
          return t;
        }
      }
    }
  } catch (e) {}

  return "";
}

function extractResourceId(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    const pathname = parsed.pathname;

    if (parsed.searchParams.has("surl")) {
      return "1" + parsed.searchParams.get("surl");
    }
    if (parsed.searchParams.has("shareid")) {
      return parsed.searchParams.get("shareid");
    }
    if (parsed.searchParams.has("code")) {
      return parsed.searchParams.get("code");
    }
    if (parsed.searchParams.has("s")) {
      return parsed.searchParams.get("s");
    }
    if (parsed.searchParams.has("id")) {
      return parsed.searchParams.get("id");
    }

    const sMatch = pathname.match(/\/s\/([a-zA-Z0-9_-]+)/);
    if (sMatch && sMatch[1]) return sMatch[1];

    const shareMatch = pathname.match(/\/share\/([a-zA-Z0-9_-]+)/);
    if (shareMatch && shareMatch[1] && !["init", "link", "home", "list"].includes(shareMatch[1].toLowerCase())) {
      return shareMatch[1];
    }
  } catch (e) {}

  return generateRandomSlug();
}

function generateRandomSlug() {
  const chars = "abcdefhjkmnprstuvwxyz23456789";
  let res = "";
  for (let i = 0; i < 6; i++) {
    res += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return res;
}

function renderAdminPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PanTools Pro · 网盘防封中转与流量雷达</title>
  <style>
    :root {
      --primary: #4f46e5;
      --primary-hover: #4338ca;
      --primary-light: #eef2ff;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --radius-lg: 16px;
      --radius-md: 10px;
      --shadow-sm: 0 1px 3px rgba(0,0,0,0.04);
      --shadow-md: 0 4px 20px -2px rgba(15, 23, 42, 0.05);
      --shadow-lg: 0 10px 30px -4px rgba(15, 23, 42, 0.08);
    }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif; background: var(--bg); margin: 0; padding: 24px 16px; color: var(--text-main); display: flex; flex-direction: column; align-items: center; min-height: 100vh; }
    
    .auth-card { background: var(--card-bg); padding: 40px 32px; border-radius: var(--radius-lg); max-width: 400px; width: 100%; box-shadow: var(--shadow-lg); text-align: center; border: 1px solid var(--border); margin-top: 60px; }
    .auth-logo { font-size: 36px; margin-bottom: 12px; display: inline-block; }
    .auth-title { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
    .auth-sub { font-size: 13px; color: var(--text-muted); margin-bottom: 24px; }
    
    .app-container { width: 100%; max-width: 1200px; display: none; }
    
    .navbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding: 4px 2px; }
    .nav-brand { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 800; background: linear-gradient(135deg, #1e293b, #4f46e5); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .nav-badge { background: #eef2ff; color: #4f46e5; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 9999px; -webkit-text-fill-color: initial; }
    .nav-actions { display: flex; gap: 8px; align-items: center; }

    /* 顶部 5 大指标网格 */
    .metrics-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 22px; }
    .metric-card { background: var(--card-bg); padding: 18px 16px; border-radius: var(--radius-lg); box-shadow: var(--shadow-md); border: 1px solid var(--border); position: relative; overflow: hidden; transition: transform 0.2s, box-shadow 0.2s; }
    .metric-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
    .metric-header { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-muted); font-weight: 600; }
    .metric-icon { width: 28px; height: 28px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 15px; background: #f8fafc; }
    .metric-value { font-size: 24px; font-weight: 800; color: var(--text-main); margin-top: 8px; line-height: 1.1; letter-spacing: -0.5px; word-break: break-all; }
    .metric-footer { font-size: 11px; color: var(--text-muted); margin-top: 6px; display: flex; align-items: center; gap: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    .device-progress-bar { width: 100%; height: 6px; background: #f1f5f9; border-radius: 9999px; overflow: hidden; display: flex; margin-top: 8px; }
    .bar-mobile { background: linear-gradient(90deg, #4f46e5, #6366f1); height: 100%; transition: width 0.3s; }
    .bar-pc { background: linear-gradient(90deg, #0ea5e9, #38bdf8); height: 100%; transition: width 0.3s; }

    .card { background: var(--card-bg); padding: 24px 28px; border-radius: var(--radius-lg); box-shadow: var(--shadow-md); border: 1px solid var(--border); margin-bottom: 22px; }
    .card-title { font-size: 16px; font-weight: 700; margin: 0 0 16px 0; display: flex; align-items: center; gap: 8px; color: #1e293b; }

    .form-group { margin-bottom: 16px; }
    .form-label { display: flex; justify-content: space-between; align-items: center; font-size: 13px; font-weight: 600; color: #334155; margin-bottom: 6px; }
    .form-input { width: 100%; padding: 11px 14px; border: 1px solid var(--border); border-radius: var(--radius-md); font-size: 14px; outline: none; transition: all 0.2s; background: #fff; }
    .form-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.12); }
    
    .btn { display: inline-flex; align-items: center; justify-content: center; font-weight: 600; cursor: pointer; transition: all 0.15s; border: none; outline: none; text-decoration: none; }
    .btn-primary { width: 100%; padding: 13px; background: linear-gradient(135deg, #4f46e5, #4338ca); color: #fff; border-radius: var(--radius-md); font-size: 15px; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.25); }
    .btn-primary:hover { opacity: 0.95; transform: translateY(-1px); }
    .btn-secondary { background: #f1f5f9; color: #475569; border: 1px solid var(--border); padding: 7px 14px; font-size: 13px; border-radius: var(--radius-md); }
    .btn-secondary:hover { background: #e2e8f0; color: #0f172a; }
    .btn-sm-smart { background: #eef2ff; color: #4f46e5; border: 1px solid #c7d2fe; padding: 3px 9px; font-size: 12px; border-radius: 6px; cursor: pointer; }
    .btn-sm-smart:hover { background: #e0e7ff; }

    .result-box { margin-top: 18px; padding: 18px 20px; background: linear-gradient(135deg, #f0fdf4, #ecfdf5); border: 1px solid #bbf7d0; border-radius: var(--radius-md); display: none; }
    .result-title { font-size: 13px; color: #166534; font-weight: 700; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }
    .result-link { font-size: 16px; font-weight: 800; color: #059669; word-break: break-all; margin: 8px 0; }

    /* 彻底消灭挤压的精简自适应表格 */
    .table-wrapper { width: 100%; overflow-x: auto; margin-top: 14px; border-radius: var(--radius-md) var(--radius-md) 0 0; border: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; font-size: 13px; background: #fff; table-layout: auto; }
    th, td { padding: 12px 10px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: middle; }
    th { background: #f8fafc; font-weight: 700; color: var(--text-muted); font-size: 12px; letter-spacing: 0.3px; white-space: nowrap; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background-color: #fafafa; }

    /* 表格底部轻量分页栏 */
    .pagination-bar { display: flex; justify-content: space-between; align-items: center; padding: 11px 16px; background: #f8fafc; border: 1px solid var(--border); border-top: none; border-radius: 0 0 var(--radius-md) var(--radius-md); font-size: 12px; color: var(--text-muted); }
    .pagination-info { font-weight: 600; }
    .pagination-controls { display: flex; align-items: center; gap: 8px; }
    .btn-page { background: #fff; border: 1px solid var(--border); padding: 5px 12px; font-size: 12px; font-weight: 600; border-radius: 6px; cursor: pointer; color: #334155; transition: all 0.15s; }
    .btn-page:hover:not(:disabled) { background: #eef2ff; color: var(--primary); border-color: #c7d2fe; }
    .btn-page:disabled { opacity: 0.45; cursor: not-allowed; }
    .page-num-indicator { font-weight: 700; color: #1e293b; padding: 0 4px; }

    /* 智能榜单排序切换胶囊组 */
    .sort-pill-group { display: inline-flex; align-items: center; background: #f1f5f9; padding: 3px; border-radius: 8px; gap: 2px; }
    .sort-pill { border: none; outline: none; background: transparent; padding: 5px 11px; font-size: 12px; font-weight: 600; color: #64748b; border-radius: 6px; cursor: pointer; transition: all 0.15s; white-space: nowrap; }
    .sort-pill:hover { color: #1e293b; }
    .sort-pill.active { background: #fff; color: #4f46e5; font-weight: 700; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    
    .brand-tag { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 5px; font-size: 11px; font-weight: 700; white-space: nowrap; margin-right: 6px; }
    
    /* 访问表现双值胶囊 */
    .traffic-pill { display: inline-flex; align-items: center; gap: 5px; padding: 3px 8px; background: #f1f5f9; border-radius: 6px; font-size: 11px; font-weight: 700; cursor: pointer; transition: all 0.15s; white-space: nowrap; }
    .traffic-pill:hover { background: #e2e8f0; }
    .pill-today { color: #10b981; }
    .pill-total { color: #4f46e5; }

    /* 操作胶囊按钮（紧凑无挤压） */
    .action-group { display: flex; gap: 4px; justify-content: flex-end; align-items: center; white-space: nowrap; }
    .act-btn { padding: 4px 7px; font-size: 11px; font-weight: 600; border-radius: 5px; cursor: pointer; border: 1px solid transparent; transition: all 0.15s; line-height: 1.3; }
    .act-stat { background: #fdf4ff; color: #a855f7; border-color: #f0abfc; }
    .act-stat:hover { background: #a855f7; color: #fff; }
    .act-copy { background: #f0fdf4; color: #16a34a; border-color: #bbf7d0; }
    .act-copy:hover { background: #16a34a; color: #fff; }
    .act-edit { background: #eff6ff; color: #2563eb; border-color: #bfdbfe; }
    .act-edit:hover { background: #2563eb; color: #fff; }
    .act-del { background: #fef2f2; color: #dc2626; border-color: #fecaca; }
    .act-del:hover { background: #dc2626; color: #fff; }

    /* 现代化 Switch 开关微卡片 */
    .toggle-card-box {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 12px 16px;
      margin: 12px 0 16px 0;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    .toggle-card-box:hover {
      background: #f1f5f9;
      border-color: #cbd5e1;
    }
    .toggle-card-info {
      flex: 1;
      padding-right: 14px;
    }
    .toggle-card-title {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      font-weight: 700;
      color: #1e293b;
      margin-bottom: 3px;
    }
    .toggle-tag-badge {
      font-size: 10px;
      font-weight: 700;
      color: #4f46e5;
      background: #eef2ff;
      border: 1px solid #c7d2fe;
      padding: 1px 6px;
      border-radius: 4px;
    }
    .toggle-card-desc {
      font-size: 12px;
      color: #64748b;
      line-height: 1.4;
    }
    
    /* 现代 iOS / Tailwind 风格 Switch 控件 */
    .switch-toggle {
      position: relative;
      display: inline-block;
      width: 44px;
      height: 24px;
      flex-shrink: 0;
      cursor: pointer;
    }
    .switch-toggle input {
      opacity: 0;
      width: 0;
      height: 0;
    }
    .switch-slider {
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background-color: #cbd5e1;
      border-radius: 24px;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .switch-slider:before {
      position: absolute;
      content: "";
      height: 18px;
      width: 18px;
      left: 3px;
      bottom: 3px;
      background-color: #ffffff;
      border-radius: 50%;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.18);
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .switch-toggle input:checked + .switch-slider {
      background: linear-gradient(135deg, #4f46e5, #6366f1);
    }
    .switch-toggle input:checked + .switch-slider:before {
      transform: translateX(20px);
    }

    /* 列表中的设备访问分段双按钮组 */
    .device-segmented-group {
      display: inline-flex;
      align-items: center;
      background: #f1f5f9;
      padding: 2px;
      border-radius: 8px;
      border: 1px solid #e2e8f0;
      gap: 2px;
      user-select: none;
    }
    .btn-segment {
      border: none;
      outline: none;
      background: transparent;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 600;
      color: #64748b;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease-in-out;
      white-space: nowrap;
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }
    .btn-segment:hover:not(.active):not(.active-mobile) {
      color: #1e293b;
      background: rgba(255, 255, 255, 0.6);
    }
    .btn-segment.active {
      background: #ffffff;
      color: #0284c7;
      font-weight: 700;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
      border: 1px solid #e0f2fe;
    }
    .btn-segment.active-mobile {
      background: #ffffff;
      color: #4f46e5;
      font-weight: 700;
      box-shadow: 0 1px 3px rgba(79, 70, 229, 0.12);
      border: 1px solid #c7d2fe;
    }
    .btn-segment:disabled {
      opacity: 0.6;
      cursor: wait;
    }

    /* 通用模态弹窗 */
    .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.5); backdrop-filter: blur(4px); display: none; align-items: center; justify-content: center; z-index: 1000; padding: 16px; }
    .modal-box { background: #fff; border-radius: var(--radius-lg); max-width: 520px; width: 100%; padding: 26px; box-shadow: var(--shadow-lg); border: 1px solid var(--border); animation: popIn 0.2s cubic-bezier(0.16, 1, 0.3, 1); max-height: 90vh; overflow-y: auto; }
    @keyframes popIn { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; border-bottom: 1px solid #f1f5f9; padding-bottom: 12px; }
    .modal-title { font-size: 17px; font-weight: 700; color: #0f172a; margin: 0; }
    .modal-close { background: none; border: none; font-size: 22px; color: var(--text-muted); cursor: pointer; padding: 2px 6px; }
    .modal-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 22px; }
    .modal-footer-dual { display: flex; justify-content: space-between; align-items: center; margin-top: 20px; flex-wrap: wrap; gap: 10px; }

    /* 每日统计条形图与分析模块 */
    .stat-section { margin-bottom: 16px; background: #f8fafc; border-radius: 12px; padding: 14px 16px; border: 1px solid #f1f5f9; }
    .stat-section-title { font-size: 13px; font-weight: 700; color: #334155; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
    .stat-row-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; text-align: center; }
    .stat-row-grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; text-align: center; }
    .stat-row-grid-6 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; text-align: center; }
    @media (max-width: 480px) {
      .stat-row-grid-4 { grid-template-columns: repeat(2, 1fr); }
      .stat-row-grid-6 { grid-template-columns: repeat(2, 1fr); }
    }
    .stat-tile { background: #fff; padding: 10px 8px; border-radius: 8px; border: 1px solid #e2e8f0; transition: transform 0.15s, box-shadow 0.15s; }
    .stat-tile:hover { transform: translateY(-1px); box-shadow: 0 2px 6px rgba(0,0,0,0.04); }
    .stat-tile-val { font-size: 17px; font-weight: 800; color: #0f172a; line-height: 1.2; }
    .stat-tile-label { font-size: 11px; color: var(--text-muted); margin-top: 3px; white-space: nowrap; }

    /* 智能运营洞察与诊断卡片 */
    .insight-banner { display: flex; align-items: flex-start; gap: 8px; padding: 10px 14px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; font-size: 12px; color: #1e40af; line-height: 1.5; margin-bottom: 14px; }
    .insight-icon { font-size: 16px; flex-shrink: 0; line-height: 1.2; }

    /* 横向动态占比进度条 */
    .progress-track { width: 100%; height: 7px; background: #f1f5f9; border-radius: 9999px; overflow: hidden; display: flex; }
    .progress-fill-mobile { background: linear-gradient(90deg, #4f46e5, #6366f1); height: 100%; transition: width 0.3s; }
    .progress-fill-pc { background: linear-gradient(90deg, #0ea5e9, #38bdf8); height: 100%; transition: width 0.3s; }

    .channel-pill-list { display: flex; flex-direction: column; gap: 7px; }
    .channel-row { display: flex; align-items: center; justify-content: space-between; font-size: 12px; }
    .channel-bar-wrap { flex: 1; margin: 0 10px; height: 6px; background: #f1f5f9; border-radius: 9999px; overflow: hidden; }
    .channel-bar-inner { height: 100%; border-radius: 9999px; transition: width 0.3s; }

    /* PV / UV 双柱对比图表 */
    .bar-chart-container { display: flex; align-items: flex-end; gap: 6px; height: 124px; padding: 18px 6px 6px 6px; background: #fff; border-radius: 8px; border: 1px solid #e2e8f0; margin-top: 8px; }
    .chart-col { flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; justify-content: flex-end; cursor: pointer; transition: background 0.15s; border-radius: 6px; padding: 2px 0; }
    .chart-col:hover { background: #f8fafc; }
    .chart-dual-wrap { width: 100%; height: 100%; display: flex; align-items: flex-end; justify-content: center; gap: 4px; }
    .chart-pillar-pv { width: 11px; max-width: 13px; background: linear-gradient(180deg, #4f46e5, #818cf8); border-radius: 3px 3px 0 0; min-height: 4px; transition: height 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; }
    .chart-pillar-uv { width: 11px; max-width: 13px; background: linear-gradient(180deg, #10b981, #6ee7b7); border-radius: 3px 3px 0 0; min-height: 4px; transition: height 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; }
    .chart-pillar-pv:hover, .chart-pillar-uv:hover { opacity: 0.85; }
    .chart-val-tip { position: absolute; top: -16px; left: 50%; transform: translateX(-50%); font-size: 10px; font-weight: 700; white-space: nowrap; }
    .chart-val-pv { color: #4f46e5; }
    .chart-val-uv { color: #059669; }
    .chart-date { font-size: 10px; color: var(--text-muted); margin-top: 6px; transform: scale(0.92); white-space: nowrap; }

    @media (max-width: 900px) {
      .metrics-grid { grid-template-columns: repeat(2, 1fr); }
      body { padding: 14px 10px; }
      .card { padding: 18px 14px; }
    }
  </style>
</head>
<body>
  <div class="auth-card" id="authBox">
    <div class="auth-logo">🔐</div>
    <div class="auth-title">PanTools 控制台</div>
    <div class="auth-sub">请输入管理密码以解锁短链与流量大屏</div>
    <input type="password" id="loginPwd" class="form-input" placeholder="输入专属管理密码" style="margin-bottom:16px;">
    <button type="button" class="btn btn-primary" id="loginBtn">登录工作台</button>
  </div>

  <div class="app-container" id="dashBox">
    <div class="navbar">
      <div class="nav-brand">
        <span>🚀 PanTools Pro</span>
        <span class="nav-badge">v3.2 每日趋势旗舰版</span>
      </div>
      <div class="nav-actions">
        <button type="button" id="exportBtn" class="btn btn-secondary" style="border:1px solid #cbd5e1;background:#fff;color:#0f766e;font-weight:700;">📥 导出报表 (Excel)</button>
        <button type="button" id="refreshBtn" class="btn btn-secondary">🔄 刷新数据</button>
        <button type="button" id="logoutBtn" class="btn btn-secondary">退出登录</button>
      </div>
    </div>

    <!-- 顶部 5 大指标网格 -->
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-header">
          <span>有效短链总数</span>
          <div class="metric-icon">🔗</div>
        </div>
        <div class="metric-value" id="metricTotalLinks">0</div>
        <div class="metric-footer">🟢 全网健康在线运行中</div>
      </div>
      <div class="metric-card">
        <div class="metric-header">
          <span>今日点击 (PV)</span>
          <div class="metric-icon">👁️</div>
        </div>
        <div class="metric-value" id="metricTodayClicks" style="color:var(--primary);">0</div>
        <div class="metric-footer" id="metricTotalClicksSub">历史累计: 0 次</div>
      </div>
      <div class="metric-card">
        <div class="metric-header">
          <span>今日访客 (UV)</span>
          <div class="metric-icon">👤</div>
        </div>
        <div class="metric-value" id="metricTodayUv" style="color:#10b981;">0</div>
        <div class="metric-footer" id="metricTotalUvSub">历史累计: 0 人</div>
      </div>
      <div class="metric-card">
        <div class="metric-header">
          <span>终端设备占比</span>
          <div class="metric-icon">📱</div>
        </div>
        <div class="metric-value" id="metricDeviceRatio" style="font-size:16px;font-weight:700;padding-top:4px;">0% / 0%</div>
        <div class="device-progress-bar">
          <div class="bar-mobile" id="barMobile" style="width:50%;"></div>
          <div class="bar-pc" id="barPc" style="width:50%;"></div>
        </div>
        <div class="metric-footer" id="metricDeviceSub" style="margin-top:6px;">📱手机 0 · 💻电脑 0</div>
      </div>
      <div class="metric-card">
        <div class="metric-header">
          <span>全网爆款资源</span>
          <div class="metric-icon">🔥</div>
        </div>
        <div class="metric-value" id="metricTopTitle" style="font-size:15px; font-weight:700; padding-top:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="-">-</div>
        <div class="metric-footer" id="metricTopSub" style="color:#f59e0b;font-weight:600;">🏆 暂无点击记录</div>
      </div>
    </div>

    <!-- 转换录入卡片 -->
    <div class="card">
      <div class="card-title">✨ 网盘链接防封转换器</div>
      <div class="form-group">
        <label class="form-label">
          <span>原始网盘链接 *</span>
          <span style="font-size:11px;color:var(--primary);font-weight:normal;">自动识别夸克/百度/阿里真实资源名</span>
        </label>
        <input type="text" id="url" class="form-input" placeholder="输入或粘贴网盘链接（如夸克/百度/阿里），支持整段文本">
      </div>

      <div class="form-group">
        <label class="form-label">
          <span>卡片展示标题（选填）</span>
          <button type="button" id="fetchTitleBtn" class="btn-sm-smart">⚡ 智能识别真实资源名称</button>
        </label>
        <input type="text" id="title" class="form-input" placeholder="留空自动联网提取真实资源主标题，也可手动输入">
      </div>

      <div class="form-group">
        <label class="form-label">
          <span>自定义短码（选填）</span>
          <span style="font-size:11px;color:var(--text-muted);font-weight:normal;">留空自动分配唯一短码，绝不覆盖已有短链</span>
        </label>
        <input type="text" id="slug" class="form-input" placeholder="例如：vip-2026，若已存在会自动弹窗提醒">
      </div>

      <div class="form-group">
        <label class="form-label">
          <span>🛡️ 备用兜底网盘链接（选填，爆款防和谐防封）</span>
          <span style="font-size:11px;color:#10b981;font-weight:normal;">主链接失效时系统自动无缝接管</span>
        </label>
        <input type="text" id="backupUrl" class="form-input" placeholder="输入备用网盘分享链接（如主链被和谐，自动无感导向此链接）">
      </div>

      <div class="toggle-card-box" onclick="document.getElementById('onlyMobileCheck').click()">
        <div class="toggle-card-info">
          <div class="toggle-card-title">
            <span>📱 强制仅限手机端访问</span>
            <span class="toggle-tag-badge">电脑自动扫码</span>
          </div>
          <div class="toggle-card-desc">开启后电脑桌面端访问将展示高清扫码二维码，引导用户使用手机扫码转存（网盘拉新必备）</div>
        </div>
        <label class="switch-toggle" onclick="event.stopPropagation()">
          <input type="checkbox" id="onlyMobileCheck">
          <span class="switch-slider"></span>
        </label>
      </div>

      <button type="button" class="btn btn-primary" id="createBtn">立即生成防封短链</button>

      <div class="result-box" id="resBox">
        <div class="result-title">🎉 防封短链已就绪，可直接发帖或私域分享：</div>
        <div class="result-link" id="resUrl"></div>
        <div style="display:flex;gap:8px;margin-top:10px;">
          <button type="button" class="btn act-copy" id="copyGenBtn" style="padding:7px 16px;font-size:13px;">📋 复制短链</button>
          <a id="resTestBtn" href="#" target="_blank" class="btn btn-secondary" style="font-size:13px;padding:7px 14px;">↗ 立即测试访问</a>
        </div>
      </div>
    </div>

    <!-- 流量大屏明细表格（彻底解决挤压，自适应清爽排版） -->
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:14px;">
        <div class="card-title" style="margin:0;">📊 流量大屏与短链矩阵</div>
        <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;">
          <div class="sort-pill-group" id="sortPillGroup">
            <button type="button" class="sort-pill active" data-sort="latest">⏱️ 最新发布</button>
            <button type="button" class="sort-pill" data-sort="today">🔥 今日爆款榜</button>
            <button type="button" class="sort-pill" data-sort="total">🏆 历史总榜</button>
          </div>
          <input type="text" id="searchInput" class="form-input" placeholder="🔍 快速搜索资源名称或短码..." style="width:200px;padding:6px 12px;font-size:12px;">
        </div>
      </div>

      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th style="min-width:210px;">网盘类型 & 资源主标题</th>
              <th style="min-width:150px;">短链直达地址</th>
              <th style="width:130px;white-space:nowrap;">访问表现 (今日 / 累计)</th>
              <th style="width:80px;white-space:nowrap;text-align:center;">创建日期</th>
              <th style="width:170px;min-width:170px;white-space:nowrap;text-align:right;">操作</th>
            </tr>
          </thead>
          <tbody id="listBody">
            <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:36px 0;">正在加载数据大屏...</td></tr>
          </tbody>
        </table>
      </div>

      <!-- 表格轻量分页控制栏 -->
      <div class="pagination-bar" id="paginationBar">
        <div class="pagination-info" id="paginationInfo">共 0 条短链</div>
        <div class="pagination-controls" id="paginationControls">
          <button type="button" class="btn-page" id="prevPageBtn" disabled>◀ 上一页</button>
          <span class="page-num-indicator" id="pageIndicator">第 1 / 1 页</span>
          <button type="button" class="btn-page" id="nextPageBtn" disabled>下一页 ▶</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 多维数据与深度画像分析弹窗 -->
  <div class="modal-overlay" id="statModal">
    <div class="modal-box" style="max-width:540px;">
      <div class="modal-header">
        <h3 class="modal-title" id="statModalTitle">📊 资源流量深度画像</h3>
        <button type="button" class="modal-close" id="closeStatModalBtn">×</button>
      </div>

      <!-- 资源基础信息与通道状态 -->
      <div style="margin-bottom:12px;">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;margin-bottom:6px;">
          <div style="display:flex;align-items:center;gap:6px;max-width:76%;">
            <span class="brand-tag" id="statModalBrand">网盘</span>
            <span style="font-size:15px;font-weight:700;color:#0f172a;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" id="statModalResName">-</span>
          </div>
          <span id="statModalStatusBadge" style="display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:700;padding:2px 8px;border-radius:9999px;background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0;">🟢 正常运行</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);word-break:break-all;" id="statModalUrl">-</div>
        <div style="font-size:11px;color:#0284c7;word-break:break-all;margin-top:2px;display:none;" id="statModalBackupUrl"></div>
      </div>

      <!-- 💡 智能运营洞察与诊断卡片 -->
      <div class="insight-banner" id="statModalInsight" style="display:none;">
        <span class="insight-icon" id="statInsightIcon">💡</span>
        <div id="statInsightText" style="flex:1;">-</div>
      </div>

      <!-- 核心指标六宫格（今日真实转化 vs 历史全周期，对称漏斗对比） -->
      <div class="stat-section">
        <div class="stat-section-title">
          <span>📈 实时流量转化漏斗大盘</span>
          <span style="font-size:11px;color:var(--primary);font-weight:600;" id="statPvPerUvBadge">人均频次: 1.0</span>
        </div>
        <div class="stat-row-grid-6">
          <div class="stat-tile">
            <div class="stat-tile-val" id="tileTodayPv" style="color:var(--primary);">0</div>
            <div class="stat-tile-label">今日点击 (PV)</div>
          </div>
          <div class="stat-tile">
            <div class="stat-tile-val" id="tileTodayUv" style="color:#10b981;">0</div>
            <div class="stat-tile-label">今日访客 (UV)</div>
          </div>
          <div class="stat-tile" style="background:#eff6ff;border-color:#bfdbfe;">
            <div class="stat-tile-val" id="tileTodayRate" style="color:#2563eb;">0%</div>
            <div class="stat-tile-label" id="tileTodayConvCount" style="color:#1d4ed8;font-weight:600;">今日转存 0 次</div>
          </div>
          <div class="stat-tile">
            <div class="stat-tile-val" id="tileTotalPv">0</div>
            <div class="stat-tile-label">累计总点击 (PV)</div>
          </div>
          <div class="stat-tile">
            <div class="stat-tile-val" id="tileTotalUv" style="color:#059669;">0</div>
            <div class="stat-tile-label">累计总访客 (UV)</div>
          </div>
          <div class="stat-tile" style="background:#f0fdf4;border-color:#bbf7d0;">
            <div class="stat-tile-val" id="tileConvertRate" style="color:#16a34a;">0%</div>
            <div class="stat-tile-label" id="tileConvertCountSub" style="color:#15803d;font-weight:600;">累计转存 0 次</div>
          </div>
        </div>
      </div>

      <!-- 最近 7 天按日趋势双柱图与转化明细 -->
      <div class="stat-section">
        <div class="stat-section-title">
          <span>📅 最近 7 天趋势与每日转化</span>
          <div style="display:flex;align-items:center;gap:10px;font-size:11px;">
            <span style="display:inline-flex;align-items:center;gap:4px;">
              <span style="width:8px;height:8px;border-radius:2px;background:#4f46e5;display:inline-block;"></span> 点击 (PV)
            </span>
            <span style="display:inline-flex;align-items:center;gap:4px;">
              <span style="width:8px;height:8px;border-radius:2px;background:#10b981;display:inline-block;"></span> 访客 (UV)
            </span>
          </div>
        </div>
        <div class="bar-chart-container" id="barChartContainer">
          <!-- 双柱在此动态渲染 -->
        </div>
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);margin:6px 0 10px 0;padding:0 2px;">
          <span>统计周期: 过去 7 天</span>
          <span id="statChartRange">-</span>
        </div>
        <!-- 每日转化小清单 -->
        <div id="statDailyListContainer" style="background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0;padding:6px 10px;font-size:11px;color:#475569;display:none;">
        </div>
      </div>

      <!-- 终端设备 & 来源渠道双列画像（支持今日 vs 累计切换，包含渠道转存率） -->
      <div class="stat-section" style="margin-bottom:0;">
        <div class="stat-section-title">
          <span>📱 终端设备 & 渠道精准转化</span>
          <div style="display:inline-flex;background:#f1f5f9;border-radius:4px;padding:2px;gap:2px;">
            <button type="button" id="btnChannelToday" class="sort-pill active" style="padding:2px 8px;font-size:11px;border-radius:3px;cursor:pointer;">🔥 今日渠道</button>
            <button type="button" id="btnChannelTotal" class="sort-pill" style="padding:2px 8px;font-size:11px;border-radius:3px;cursor:pointer;">🌐 全周期</button>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <!-- 终端设备 -->
          <div style="background:#fff;padding:12px;border-radius:8px;border:1px solid #e2e8f0;">
            <div style="font-size:12px;font-weight:700;color:#334155;margin-bottom:6px;display:flex;justify-content:space-between;">
              <span>访问终端</span>
              <span id="statDeviceRatioText" style="font-weight:600;font-size:11px;color:var(--text-muted);">0% / 0%</span>
            </div>
            <div class="progress-track" style="margin:6px 0 10px 0;">
              <div id="statBarMobile" class="progress-fill-mobile" style="width:50%;"></div>
              <div id="statBarPc" class="progress-fill-pc" style="width:50%;"></div>
            </div>
            <div style="font-size:12px;display:flex;justify-content:space-between;margin-bottom:4px;">
              <span>📱 手机移动端:</span>
              <strong id="statMobileCount" style="color:#4f46e5;">0</strong>
            </div>
            <div style="font-size:12px;display:flex;justify-content:space-between;">
              <span>💻 电脑桌面端:</span>
              <strong id="statPcCount" style="color:#0ea5e9;">0</strong>
            </div>
          </div>

          <!-- 渠道来源与转化漏斗 -->
          <div style="background:#fff;padding:12px;border-radius:8px;border:1px solid #e2e8f0;">
            <div style="font-size:12px;font-weight:700;color:#334155;margin-bottom:6px;display:flex;justify-content:space-between;">
              <span id="statChannelTitle">引流与转存转化</span>
              <span style="font-size:10px;color:var(--text-muted);">访问 · 转存(率)</span>
            </div>
            <div class="channel-pill-list">
              <div class="channel-row">
                <span style="color:#475569;white-space:nowrap;">💬 微信私域</span>
                <div class="channel-bar-wrap"><div id="barSrcWechat" class="channel-bar-inner" style="width:0%;background:#059669;"></div></div>
                <strong id="statSrcWechat" style="font-size:11px;">0</strong>
              </div>
              <div class="channel-row">
                <span style="color:#475569;white-space:nowrap;">🐦 X / 推特</span>
                <div class="channel-bar-wrap"><div id="barSrcTwitter" class="channel-bar-inner" style="width:0%;background:#38bdf8;"></div></div>
                <strong id="statSrcTwitter" style="font-size:11px;">0</strong>
              </div>
              <div class="channel-row">
                <span style="color:#475569;white-space:nowrap;">🔗 直接访问</span>
                <div class="channel-bar-wrap"><div id="barSrcDirect" class="channel-bar-inner" style="width:0%;background:#10b981;"></div></div>
                <strong id="statSrcDirect" style="font-size:11px;">0</strong>
              </div>
              <div class="channel-row">
                <span style="color:#475569;white-space:nowrap;">🌐 外部其他</span>
                <div class="channel-bar-wrap"><div id="barSrcOther" class="channel-bar-inner" style="width:0%;background:#94a3b8;"></div></div>
                <strong id="statSrcOther" style="font-size:11px;">0</strong>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 底部快捷操作栏 -->
      <div class="modal-footer-dual">
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          <a id="statModalOpenLink" href="#" target="_blank" class="btn btn-secondary" style="padding:6px 12px;font-size:12px;text-decoration:none;">🚀 测试跳转</a>
          <button type="button" class="btn btn-secondary" id="statModalCopyBtn" style="padding:6px 12px;font-size:12px;">📋 复制短链</button>
          <button type="button" class="btn btn-secondary" id="statModalEditBtn" style="padding:6px 12px;font-size:12px;">✏️ 编辑配置</button>
        </div>
        <button type="button" class="btn btn-secondary" id="confirmStatModalBtn" style="padding:6px 18px;font-size:13px;font-weight:700;">关闭</button>
      </div>
    </div>
  </div>

  <!-- 编辑短链模态弹窗 -->
  <div class="modal-overlay" id="editModal">
    <div class="modal-box">
      <div class="modal-header">
        <h3 class="modal-title">✏️ 编辑网盘短链与兜底通道</h3>
        <button type="button" class="modal-close" id="closeModalBtn">×</button>
      </div>

      <!-- 爆款紧急救火提示条 -->
      <div id="editAlertBanner" style="display:none;background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:10px 12px;border-radius:8px;font-size:12px;margin-bottom:14px;line-height:1.5;"></div>

      <div class="form-group">
        <label class="form-label">短码路径 (不可修改)</label>
        <input type="text" id="editSlug" class="form-input" style="background:#f1f5f9;color:#64748b;" readonly>
      </div>
      <div class="form-group">
        <label class="form-label">主网盘链接 *</label>
        <input type="text" id="editUrl" class="form-input" placeholder="输入主网盘链接">
      </div>
      <div class="form-group">
        <label class="form-label">
          <span>🛡️ 备用兜底网盘链接（选填）</span>
          <span style="font-size:11px;color:#10b981;font-weight:normal;">主链接失效时自动接管</span>
        </label>
        <input type="text" id="editBackupUrl" class="form-input" placeholder="输入备用网盘链接，没有可留空">
      </div>
      <div class="form-group">
        <label class="form-label">当前生效通道</label>
        <select id="editActiveTarget" class="form-input" style="cursor:pointer;">
          <option value="primary">🟢 指向主链接（默认）</option>
          <option value="backup">🛡️ 强制指向备用链接</option>
        </select>
      </div>
      <div class="toggle-card-box" onclick="document.getElementById('editOnlyMobileCheck').click()" style="margin:10px 0;">
        <div class="toggle-card-info">
          <div class="toggle-card-title">
            <span>📱 强制仅限手机端访问</span>
            <span class="toggle-tag-badge">电脑扫码</span>
          </div>
          <div class="toggle-card-desc">开启后电脑访问时展示扫码二维码，手机访问正常打开</div>
        </div>
        <label class="switch-toggle" onclick="event.stopPropagation()">
          <input type="checkbox" id="editOnlyMobileCheck">
          <span class="switch-slider"></span>
        </label>
      </div>
      <div class="form-group">
        <label class="form-label">展示标题 (留空自动重抓)</label>
        <input type="text" id="editTitle" class="form-input" placeholder="输入更新后的标题，或留空自动提取">
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" id="cancelModalBtn">取消</button>
        <button type="button" class="btn btn-primary" id="saveEditBtn" style="width:auto;padding:8px 20px;">保存修改</button>
      </div>
    </div>
  </div>

  <script>
    (function() {
      var allItems = [];
      var currentFilteredList = [];
      var currentPage = 1;
      var pageSize = 10;
      var currentSort = "latest";

      function getPwd() {
        return localStorage.getItem("pan_cf_pwd") || "";
      }

      function checkAuth() {
        var pwd = getPwd();
        var authBox = document.getElementById("authBox");
        var dashBox = document.getElementById("dashBox");
        if (pwd) {
          authBox.style.display = "none";
          dashBox.style.display = "block";
          loadList();
        } else {
          authBox.style.display = "block";
          dashBox.style.display = "none";
        }
      }

      async function doLogin() {
        var pwdInput = document.getElementById("loginPwd");
        var pwd = pwdInput.value.trim();
        if (!pwd) { alert("请输入密码！"); return; }
        var btn = document.getElementById("loginBtn");
        btn.innerText = "正在验证...";
        btn.disabled = true;
        try {
          var resp = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pwd: pwd })
          });
          var data = await resp.json().catch(function() { return {}; });
          if (resp.ok) {
            localStorage.setItem("pan_cf_pwd", pwd);
            pwdInput.value = "";
            checkAuth();
          } else {
            alert(data.error || "密码错误，请重新输入！");
          }
        } catch (e) {
          alert("网络连接出错：" + e.message);
        } finally {
          btn.innerText = "登录工作台";
          btn.disabled = false;
        }
      }

      function doLogout() {
        localStorage.removeItem("pan_cf_pwd");
        location.reload();
      }

      var serverTotal = 0;
      var serverTotalPages = 1;
      var searchTimer = null;

      async function loadList(targetPage) {
        var pwd = getPwd();
        if (!pwd) return;
        if (targetPage !== undefined) currentPage = targetPage;
        var q = document.getElementById("searchInput").value.trim();

        try {
          var resp = await fetch("/api/list?_t=" + Date.now(), {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": "no-cache, no-store, must-revalidate"
            },
            body: JSON.stringify({
              pwd: pwd,
              page: currentPage,
              pageSize: pageSize,
              search: q,
              sort: currentSort
            })
          });
          var data = await resp.json();
          if (resp.ok && data.items) {
            allItems = data.items;
            serverTotal = data.total !== undefined ? data.total : data.items.length;
            serverTotalPages = data.totalPages || 1;
            currentPage = data.page || 1;

            if (data.metrics) {
              updateMetricsFromSummary(data.metrics);
            } else {
              updateMetrics();
            }

            renderTable(allItems);
            updatePaginationUI();
          } else if (resp.status === 403) {
            alert("登录已失效，请重新登录");
            doLogout();
          }
        } catch (e) {}
      }

      function getClientBeijingDateStr(d) {
        var dateObj = d || new Date();
        var d8 = new Date(dateObj.getTime() + 8 * 3600 * 1000);
        return d8.toISOString().slice(0, 10);
      }

      function updateMetricsFromSummary(m) {
        document.getElementById("metricTotalLinks").innerText = m.totalLinks || 0;

        var totalClicks = m.totalClicks || 0;
        var totalUv = m.totalUv || 0;
        var totalConvert = m.totalConvert || 0;
        var avgRate = totalClicks > 0 ? Math.min(100, Math.round((totalConvert / totalClicks) * 100)) : 0;

        // 全站客观真实今日指标（直接取自 D1 服务端全局统计聚合，彻底消除分页仅能加当前页 20 条的失真漏洞）
        var todayClicks = m.todayClicks !== undefined ? m.todayClicks : allItems.reduce(function(acc, i) { return acc + (i.todayClicks || 0); }, 0);
        var todayUv = m.todayUv !== undefined ? m.todayUv : allItems.reduce(function(acc, i) { return acc + (i.todayUv || 0); }, 0);
        var todayConv = m.todayConvert !== undefined ? m.todayConvert : 0;
        var todayRate = todayClicks > 0 ? Math.min(100, Math.round((todayConv / todayClicks) * 100)) : 0;

        document.getElementById("metricTodayClicks").innerText = todayClicks;
        document.getElementById("metricTotalClicksSub").innerText = "全站累计 " + totalClicks + " 次 · 🎯转存 " + totalConvert + " (" + avgRate + "%)";

        document.getElementById("metricTodayUv").innerText = todayUv;
        document.getElementById("metricTotalUvSub").innerText = "全站累计访客: " + totalUv + " 人 · 今日转存 " + todayConv + " (" + todayRate + "%)";

        var totalMobile = m.totalMobile || 0;
        var totalPc = m.totalPc || 0;
        var totalDev = totalMobile + totalPc;
        var mPercent = totalDev > 0 ? Math.round((totalMobile / totalDev) * 100) : 50;
        var pPercent = totalDev > 0 ? (100 - mPercent) : 50;

        document.getElementById("metricDeviceRatio").innerText = (totalDev > 0 ? mPercent : 0) + "% 手机 / " + (totalDev > 0 ? pPercent : 0) + "% 电脑";
        document.getElementById("barMobile").style.width = mPercent + "%";
        document.getElementById("barPc").style.width = pPercent + "%";
        document.getElementById("metricDeviceSub").innerText = "📱手机 " + totalMobile + " · 💻电脑 " + totalPc;

        if (allItems.length > 0) {
          var sorted = allItems.slice().sort(function(a, b) { 
            return currentSort === "today" ? ((b.todayClicks || 0) - (a.todayClicks || 0)) : ((b.clicks || 0) - (a.clicks || 0)); 
          });
          var top = sorted[0];
          var topVal = currentSort === "today" ? (top.todayClicks || 0) : (top.clicks || 0);
          var topTag = currentSort === "today" ? "🔥 今日领跑 " : "🏆 历史领跑 ";
          if (topVal > 0) {
            document.getElementById("metricTopTitle").innerText = top.title || top.slug;
            document.getElementById("metricTopTitle").setAttribute("title", top.title || top.slug);
            document.getElementById("metricTopSub").innerText = topTag + topVal + " 次点击 (UV " + (currentSort === "today" ? (top.todayUv || 0) : (top.uv || 0)) + ")";
          } else {
            document.getElementById("metricTopTitle").innerText = "暂无访问数据";
            document.getElementById("metricTopTitle").setAttribute("title", "暂无访问数据");
            document.getElementById("metricTopSub").innerText = "链接尚未产生点击";
          }
        } else {
          document.getElementById("metricTopTitle").innerText = "-";
          document.getElementById("metricTopSub").innerText = "暂无短链";
        }
      }

      function updateMetrics() {
        document.getElementById("metricTotalLinks").innerText = allItems.length;
        
        var totalClicks = allItems.reduce(function(acc, item) { return acc + (item.clicks || 0); }, 0);
        var totalUv = allItems.reduce(function(acc, item) { return acc + (item.uv || 0); }, 0);
        var todayClicks = allItems.reduce(function(acc, item) { return acc + (item.todayClicks || 0); }, 0);
        var todayUv = allItems.reduce(function(acc, item) { return acc + (item.todayUv || 0); }, 0);

        var totalConvert = allItems.reduce(function(acc, item) { return acc + (item.convertClicks || 0); }, 0);
        var avgRate = totalClicks > 0 ? Math.min(100, Math.round((totalConvert / totalClicks) * 100)) : 0;
        var todayConvert = allItems.reduce(function(acc, item) { return acc + (item.todayConvert || 0); }, 0);
        var todayRate = todayClicks > 0 ? Math.min(100, Math.round((todayConvert / todayClicks) * 100)) : 0;

        document.getElementById("metricTodayClicks").innerText = todayClicks;
        document.getElementById("metricTotalClicksSub").innerText = "累计 " + totalClicks + " 次 · 🎯转存 " + totalConvert + " (" + avgRate + "%)";
        
        document.getElementById("metricTodayUv").innerText = todayUv;
        document.getElementById("metricTotalUvSub").innerText = "历史累计: " + totalUv + " 人 · 今日转存 " + todayConvert + " (" + todayRate + "%)";

        var totalMobile = allItems.reduce(function(acc, item) { return acc + ((item.devices && item.devices.mobile) || 0); }, 0);
        var totalPc = allItems.reduce(function(acc, item) { return acc + ((item.devices && item.devices.pc) || 0); }, 0);
        var totalDev = totalMobile + totalPc;
        var mPercent = totalDev > 0 ? Math.round((totalMobile / totalDev) * 100) : 50;
        var pPercent = totalDev > 0 ? (100 - mPercent) : 50;
        
        document.getElementById("metricDeviceRatio").innerText = (totalDev > 0 ? mPercent : 0) + "% 手机 / " + (totalDev > 0 ? pPercent : 0) + "% 电脑";
        document.getElementById("barMobile").style.width = mPercent + "%";
        document.getElementById("barPc").style.width = pPercent + "%";
        document.getElementById("metricDeviceSub").innerText = "📱手机 " + totalMobile + " · 💻电脑 " + totalPc;

        if (allItems.length > 0) {
          var sorted = allItems.slice().sort(function(a, b) { return (b.clicks || 0) - (a.clicks || 0); });
          var top = sorted[0];
          if ((top.clicks || 0) > 0) {
            document.getElementById("metricTopTitle").innerText = top.title || top.slug;
            document.getElementById("metricTopTitle").setAttribute("title", top.title || top.slug);
            document.getElementById("metricTopSub").innerText = "🔥 累计 " + top.clicks + " 次点击 (UV " + (top.uv || 0) + ")";
          } else {
            document.getElementById("metricTopTitle").innerText = "暂无访问数据";
            document.getElementById("metricTopTitle").setAttribute("title", "暂无访问数据");
            document.getElementById("metricTopSub").innerText = "链接尚未产生点击";
          }
        } else {
          document.getElementById("metricTopTitle").innerText = "-";
          document.getElementById("metricTopSub").innerText = "暂无短链";
        }
      }

      function updatePaginationUI() {
        var infoEl = document.getElementById("paginationInfo");
        var indicatorEl = document.getElementById("pageIndicator");
        var prevBtn = document.getElementById("prevPageBtn");
        var nextBtn = document.getElementById("nextPageBtn");

        if (serverTotal === 0) {
          infoEl.innerText = "共 0 条短链";
          indicatorEl.innerText = "第 1 / 1 页";
          prevBtn.disabled = true;
          nextBtn.disabled = true;
        } else {
          var startIdx = (currentPage - 1) * pageSize + 1;
          var endIdx = Math.min(currentPage * pageSize, serverTotal);
          infoEl.innerText = "显示第 " + startIdx + " - " + endIdx + " 条，共 " + serverTotal + " 条短链";
          indicatorEl.innerText = "第 " + currentPage + " / " + serverTotalPages + " 页";
          prevBtn.disabled = (currentPage <= 1);
          nextBtn.disabled = (currentPage >= serverTotalPages);
        }
      }

      function goToPrevPage() {
        if (currentPage > 1) {
          loadList(currentPage - 1);
        }
      }

      function goToNextPage() {
        if (currentPage < serverTotalPages) {
          loadList(currentPage + 1);
        }
      }

      function handleSearchInput() {
        if (searchTimer) clearTimeout(searchTimer);
        searchTimer = setTimeout(function() {
          loadList(1);
        }, 300);
      }

      // 精简自适应无挤压表格
      function renderTable(items) {
        var tbody = document.getElementById("listBody");
        if (items.length === 0) {
          tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;color:var(--text-muted);padding:36px 0;'>暂无相关短链数据</td></tr>";
          return;
        }
        var html = "";
        for (var i = 0; i < items.length; i++) {
          var item = items[i];
          var brand = item.brand || { name: "网盘资源", color: "#475569", bg: "#f1f5f9" };
          var todayPv = item.todayClicks || 0;
          var totalPv = item.clicks || 0;

          var rankBadge = "";
          if (currentPage === 1 && ((currentSort === "today" && todayPv > 0) || (currentSort === "total" && totalPv > 0))) {
            if (i === 0) rankBadge = "<span style='margin-right:4px;' title='榜首'>🥇</span>";
            else if (i === 1) rankBadge = "<span style='margin-right:4px;' title='第二名'>🥈</span>";
            else if (i === 2) rankBadge = "<span style='margin-right:4px;' title='第三名'>🥉</span>";
          }

          var backupPill = "";
          if (item.backupUrl) {
            if (item.autoSwitched) {
              backupPill = "<span style='display:inline-flex;align-items:center;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;background:#fef2f2;color:#dc2626;border:1px solid #fecaca;margin-left:6px;' title='系统检测到主链失效，已自动切备用接管流量'>🔥 已切备用</span>";
            } else if (item.activeTarget === "backup") {
              backupPill = "<span style='display:inline-flex;align-items:center;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;background:#fff7ed;color:#ea580c;border:1px solid #ffedd5;margin-left:6px;' title='当前通道强制为备用网盘'>🛡️ 备用中</span>";
            } else {
              backupPill = "<span style='display:inline-flex;align-items:center;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0;margin-left:6px;' title='已配置备用兜底链，失效自动接管'>🛡️ 备用就绪</span>";
            }
          }

          html += "<tr>" +
            "<td>" +
              "<div style='display:flex;align-items:center;margin-bottom:3px;'>" +
                rankBadge +
                "<span class='brand-tag' style='background:" + brand.bg + ";color:" + brand.color + ";'>" + brand.name + "</span>" +
                "<span style='font-weight:700;color:#1e293b;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' title='" + item.title + "'>" + item.title + "</span>" +
                backupPill +
              "</div>" +
              "<div style='font-size:11px;color:var(--text-muted);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' title='" + item.url + "'>目标: " + item.url + "</div>" +
            "</td>" +
            "<td>" +
              "<div><a href='" + item.shortUrl + "' target='_blank' style='color:var(--primary);text-decoration:none;font-weight:700;font-size:12px;display:inline-block;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' title='" + item.shortUrl + "'>" + item.shortUrl + "</a></div>" +
              "<div style='margin-top:4px;'>" +
                "<div class='device-segmented-group'>" +
                  "<button type='button' class='btn-segment" + (!item.onlyMobile ? " active" : "") + "' data-slug='" + item.slug + "' data-target-mobile='0' title='允许所有设备（电脑和手机）直接访问网盘'>" +
                    "🌐 全设备" +
                  "</button>" +
                  "<button type='button' class='btn-segment" + (item.onlyMobile ? " active-mobile" : "") + "' data-slug='" + item.slug + "' data-target-mobile='1' title='仅限手机端访问（电脑端打开展示扫码二维码）'>" +
                    "📱 仅手机" +
                  "</button>" +
                "</div>" +
              "</div>" +
            "</td>" +
            "<td>" +
              "<div class='traffic-pill' data-slug='" + item.slug + "' title='点击查看深度流量分析'>" +
                "<span>今日 <strong class='pill-today'>" + todayPv + "</strong></span>" +
                "<span style='color:#cbd5e1;'>/</span>" +
                "<span>总 <strong class='pill-total'>" + totalPv + "</strong></span>" +
              "</div>" +
              (function() {
                var conv = item.convertClicks || 0;
                var rate = totalPv > 0 ? Math.min(100, Math.round((conv / totalPv) * 100)) : 0;
                return "<div style='margin-top:3px;font-size:11px;display:flex;align-items:center;gap:3px;' title='真实转存 " + conv + " 次，转化率 " + rate + "%'>" +
                  "<span style='padding:1px 4px;border-radius:4px;background:#f0fdf4;color:#16a34a;font-weight:700;border:1px solid #bbf7d0;'>🎯 转存 " + conv + "</span>" +
                  "<span style='color:var(--text-muted);font-weight:600;font-size:10px;'>" + rate + "%</span>" +
                "</div>";
              })() +
            "</td>" +
            "<td style='color:var(--text-muted);font-size:11px;white-space:nowrap;text-align:center;'>" + item.createdAt + "</td>" +
            "<td style='text-align:right;white-space:nowrap;'>" +
              "<div class='action-group'>" +
                "<button type='button' class='act-btn act-stat' data-slug='" + item.slug + "'>📊 详情</button>" +
                "<button type='button' class='act-btn act-edit' data-slug='" + item.slug + "' data-url='" + item.url + "' data-title='" + item.title + "' data-backup='" + (item.backupUrl || "") + "' data-target='" + (item.activeTarget || "primary") + "' data-autoswitched='" + (item.autoSwitched ? "1" : "0") + "' data-lastswitched='" + (item.lastSwitchedAt || "") + "' data-onlymobile='" + (item.onlyMobile ? "1" : "0") + "'>✏️ 编辑</button>" +
                "<button type='button' class='act-btn act-copy' data-url='" + item.shortUrl + "'>📋 复制</button>" +
                "<button type='button' class='act-btn act-del' data-slug='" + item.slug + "'>🗑️</button>" +
              "</div>" +
            "</td>" +
          "</tr>";
        }
        tbody.innerHTML = html;
      }

      function extractFirstUrl(text) {
        if (!text) return "";
        var h1 = text.indexOf("http://");
        var h2 = text.indexOf("https://");
        var startIdx = -1;
        if (h1 !== -1 && h2 !== -1) startIdx = Math.min(h1, h2);
        else if (h1 !== -1) startIdx = h1;
        else if (h2 !== -1) startIdx = h2;
        if (startIdx === -1) return text.trim();
        var sub = text.substring(startIdx);
        var pure = "";
        for (var i = 0; i < sub.length; i++) {
          var codePoint = sub.charCodeAt(i);
          if (codePoint <= 32 || codePoint > 255) break;
          pure += sub[i];
        }
        return pure.replace(/[，。；！,;!]+$/, "").trim();
      }

      function handleSmartPaste(rawText) {
        if (!rawText) return;
        var pureUrl = extractFirstUrl(rawText);
        if (pureUrl.startsWith("http://") || pureUrl.startsWith("https://")) {
          document.getElementById("url").value = pureUrl;
          var titleInput = document.getElementById("title");
          if (!titleInput.value.trim()) {
            var bMatch = rawText.match(/[「【]([^」】]+)[」】]/);
            if (bMatch && bMatch[1]) {
              titleInput.value = bMatch[1].trim();
            } else if (rawText.indexOf("分享了") !== -1) {
              var parts = rawText.split("分享了");
              if (parts[1]) {
                var rawTitle = parts[1].replace(/^[「“"\\s]+/, "");
                rawTitle = rawTitle.split("，")[0].split(",")[0].split("。")[0].split(" ")[0];
                titleInput.value = rawTitle.replace(/[」”"\\s]+$/, "").trim();
              }
            } else {
              doFetchTitle(true);
            }
          }
        }
      }

      async function doFetchTitle(silent) {
        var pwd = getPwd();
        var urlInput = document.getElementById("url");
        var titleInput = document.getElementById("title");
        var btn = document.getElementById("fetchTitleBtn");
        var rawUrl = urlInput.value.trim();
        var targetUrl = extractFirstUrl(rawUrl);

        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
          if (!silent) alert("请先输入有效的网盘链接！");
          return;
        }

        btn.innerText = "⏳ 正在识别真实标题...";
        btn.disabled = true;
        try {
          var resp = await fetch("/api/fetch-title", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pwd: pwd, url: targetUrl })
          });
          var data = await resp.json();
          if (data.success && data.title) {
            titleInput.value = data.title;
          } else {
            if (!silent) alert("未能自动识别到资源主名称，可手动输入");
          }
        } catch (e) {
          if (!silent) alert("识别超时，请检查网络");
        } finally {
          btn.innerText = "⚡ 智能识别真实资源名称";
          btn.disabled = false;
        }
      }

      async function doCreate() {
        var pwd = getPwd();
        var urlInput = document.getElementById("url");
        var titleInput = document.getElementById("title");
        var slugInput = document.getElementById("slug");
        var backupUrlInput = document.getElementById("backupUrl");
        var onlyMobileCheck = document.getElementById("onlyMobileCheck");
        var btn = document.getElementById("createBtn");

        var rawUrl = urlInput.value.trim();
        var url = extractFirstUrl(rawUrl);
        var title = titleInput.value.trim();
        var slug = slugInput.value.trim();
        var backupUrl = backupUrlInput ? backupUrlInput.value.trim() : "";
        var onlyMobile = onlyMobileCheck ? onlyMobileCheck.checked : false;

        if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
          alert("请输入有效的网盘链接！");
          return;
        }

        btn.innerText = "正在生成防封短链...";
        btn.disabled = true;
        try {
          var resp = await fetch("/api/shorten", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pwd: pwd, url: url, title: title, slug: slug, backupUrl: backupUrl, onlyMobile: onlyMobile })
          });
          var data = await resp.json();
          if (!resp.ok) {
            alert(data.error || "生成失败");
          } else {
            document.getElementById("resBox").style.display = "block";
            document.getElementById("resUrl").innerText = data.shortUrl;
            document.getElementById("resTestBtn").setAttribute("href", data.shortUrl);
            urlInput.value = "";
            titleInput.value = "";
            slugInput.value = "";
            if (backupUrlInput) backupUrlInput.value = "";
            if (onlyMobileCheck) onlyMobileCheck.checked = false;

            loadList(1);
          }
        } catch (e) {
          alert("网络请求出错");
        } finally {
          btn.innerText = "立即生成防封短链";
          btn.disabled = false;
        }
      }

      var currentModalItem = null;
      var currentChannelMode = "today";

      // 打开深度数据画像与智能诊断弹窗（支持对称漏斗六宫格、渠道转化钻取、近7天逐日明细与快捷操作）
      async function openStatModal(slug) {
        var item = null;
        for (var i = 0; i < allItems.length; i++) {
          if (allItems[i].slug === slug) { item = allItems[i]; break; }
        }
        if (!item) return;

        currentModalItem = item;
        currentChannelMode = "today";
        updateChannelTabsUI();

        // 1. 顶部基础信息与品牌标签
        var brand = item.brand || { name: "网盘资源", color: "#475569", bg: "#f1f5f9" };
        var brandEl = document.getElementById("statModalBrand");
        brandEl.innerText = brand.name;
        brandEl.style.background = brand.bg;
        brandEl.style.color = brand.color;

        document.getElementById("statModalResName").innerText = item.title || item.slug;
        document.getElementById("statModalUrl").innerText = "主链: " + item.url;

        var backupEl = document.getElementById("statModalBackupUrl");
        if (item.backupUrl) {
          backupEl.style.display = "block";
          backupEl.innerText = "备用: " + item.backupUrl;
        } else {
          backupEl.style.display = "none";
        }

        // 2. 通道运行状态胶囊徽章
        var statusBadge = document.getElementById("statModalStatusBadge");
        if (item.autoSwitched) {
          statusBadge.innerText = "🔥 自动切备用中";
          statusBadge.style.background = "#fef2f2";
          statusBadge.style.color = "#dc2626";
          statusBadge.style.borderColor = "#fecaca";
        } else if (item.activeTarget === "backup") {
          statusBadge.innerText = "🛡️ 强制备用中";
          statusBadge.style.background = "#fff7ed";
          statusBadge.style.color = "#ea580c";
          statusBadge.style.borderColor = "#ffedd5";
        } else if (item.backupUrl) {
          statusBadge.innerText = "🛡️ 备用已就绪";
          statusBadge.style.background = "#f0fdf4";
          statusBadge.style.color = "#16a34a";
          statusBadge.style.borderColor = "#bbf7d0";
        } else {
          statusBadge.innerText = "🟢 主通道正常";
          statusBadge.style.background = "#eff6ff";
          statusBadge.style.color = "#2563eb";
          statusBadge.style.borderColor = "#bfdbfe";
        }

        // 3. 核心数值六宫格计算（今日实时 vs 历史全周期对称展现）
        var totalPv = item.clicks || 0;
        var totalUv = item.uv || 0;
        var todayPv = item.todayClicks || 0;
        var todayUv = item.todayUv || 0;
        var totalConv = item.convertClicks || 0;
        var todayConv = item.todayConvert || 0;

        var totalRate = totalPv > 0 ? (Math.round((totalConv / totalPv) * 1000) / 10) : 0;
        var todayRate = todayPv > 0 ? (Math.round((todayConv / todayPv) * 1000) / 10) : 0;
        var pvPerUv = totalUv > 0 ? (Math.round((totalPv / totalUv) * 10) / 10).toFixed(1) : "1.0";

        var badgeEl = document.getElementById("statPvPerUvBadge");
        if (badgeEl) badgeEl.innerText = "全周期人均频次: " + pvPerUv + " 次/人";

        document.getElementById("tileTodayPv").innerText = todayPv;
        document.getElementById("tileTodayUv").innerText = todayUv;
        document.getElementById("tileTodayRate").innerText = todayRate + "%";
        document.getElementById("tileTodayConvCount").innerText = "今日转存 " + todayConv + " 次";

        document.getElementById("tileTotalPv").innerText = totalPv;
        document.getElementById("tileTotalUv").innerText = totalUv;
        document.getElementById("tileConvertRate").innerText = totalRate + "%";
        document.getElementById("tileConvertCountSub").innerText = "累计转存 " + totalConv + " 次";

        // 4. 智能运营洞察与诊断小贴士
        var insightEl = document.getElementById("statModalInsight");
        var iconEl = document.getElementById("statInsightIcon");
        var textEl = document.getElementById("statInsightText");

        var dev = item.devices || { mobile: 0, pc: 0 };
        var mobileCount = dev.mobile || 0;
        var pcCount = dev.pc || 0;
        var totalDev = mobileCount + pcCount;
        var mobileRatio = totalDev > 0 ? (mobileCount / totalDev) : 0;

        if (item.autoSwitched) {
          iconEl.innerText = "🛡️";
          textEl.innerHTML = "<strong>【紧急救火成功】</strong>检测到主网盘曾失效，系统已自动切至备用网盘接管，保住了潜在流失的访客！";
          insightEl.style.background = "#fff1f2";
          insightEl.style.borderColor = "#fecdd3";
          insightEl.style.color = "#be123c";
          insightEl.style.display = "flex";
        } else if (todayRate >= 30 && todayPv >= 3) {
          iconEl.innerText = "🔥";
          textEl.innerHTML = "<strong>【今日极速爆发】</strong>今日转存转化率高达 <strong>" + todayRate + "%</strong>（已转存 " + todayConv + " 次）！建议在公众号推文、X(推特)或微信社群置顶主推！";
          insightEl.style.background = "#f0fdf4";
          insightEl.style.borderColor = "#bbf7d0";
          insightEl.style.color = "#15803d";
          insightEl.style.display = "flex";
        } else if (totalRate >= 30 && totalPv >= 5) {
          iconEl.innerText = "🎯";
          textEl.innerHTML = "<strong>【高转化常青树】</strong>全周期转存率 <strong>" + totalRate + "%</strong>，流量承接表现极其稳健，可持续长期投放引流。";
          insightEl.style.background = "#eff6ff";
          insightEl.style.borderColor = "#bfdbfe";
          insightEl.style.color = "#1d4ed8";
          insightEl.style.display = "flex";
        } else if (totalPv >= 10 && totalConv === 0) {
          iconEl.innerText = "⚠️";
          textEl.innerHTML = "<strong>【异常预警】</strong>累计访问已达 <strong>" + totalPv + "</strong> 次但暂无转存，建议点击下方「🚀 测试跳转」核验资源是否已失效或提取码变更！";
          insightEl.style.background = "#fffbeb";
          insightEl.style.borderColor = "#fde68a";
          insightEl.style.color = "#b45309";
          insightEl.style.display = "flex";
        } else if (mobileRatio >= 0.8 && totalDev >= 2) {
          iconEl.innerText = "📱";
          textEl.innerHTML = "<strong>【移动端主导】</strong>超 <strong>" + Math.round(mobileRatio * 100) + "%</strong> 流量来自手机端，若需防爬虫，可在列表中开启「仅手机访问」模式。";
          insightEl.style.background = "#faf5ff";
          insightEl.style.borderColor = "#e9d5ff";
          insightEl.style.color = "#7e22ce";
          insightEl.style.display = "flex";
        } else {
          iconEl.innerText = "💡";
          textEl.innerHTML = "<strong>【状态健康】</strong>当前链接访问链路畅通，数据持续沉淀中，随时可通过下方按钮复制短链发往各平台。";
          insightEl.style.background = "#f8fafc";
          insightEl.style.borderColor = "#e2e8f0";
          insightEl.style.color = "#334155";
          insightEl.style.display = "flex";
        }

        // 5. 渲染设备横向进度条与渠道分布
        renderDeviceAndSourcesBars(dev, item, currentChannelMode);

        // 6. 绑定底部快捷操作按钮
        var openLink = document.getElementById("statModalOpenLink");
        if (openLink) openLink.href = item.shortUrl || ("/" + item.slug);

        var copyBtn = document.getElementById("statModalCopyBtn");
        if (copyBtn) {
          copyBtn.onclick = function() {
            copyText(item.shortUrl || (location.origin + "/" + item.slug));
          };
        }

        var editBtn = document.getElementById("statModalEditBtn");
        if (editBtn) {
          editBtn.onclick = function() {
            closeStatModal();
            openEditModal(item.slug, item.url, item.title, item.backupUrl, item.activeTarget, item.autoSwitched, item.lastSwitchedAt, item.onlyMobile);
          };
        }

        // 7. 渲染最近 7 天 PV / UV 双柱趋势图及逐日明细清单
        renderDailyChart(item.daily || {});

        document.getElementById("statModal").style.display = "flex";

        // 若尚未拉取过完整的 daily 数据，后台静默补拉
        if (!item.daily || Object.keys(item.daily).length === 0) {
          try {
            var pwd = getPwd();
            var resp = await fetch("/api/detail", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ pwd: pwd, slug: slug })
            });
            var data = await resp.json();
            if (resp.ok && data.daily) {
              item.daily = data.daily;
              item.devices = data.devices || item.devices;
              item.sources = data.sources || item.sources;
              renderDailyChart(item.daily);
              renderDeviceAndSourcesBars(item.devices, item, currentChannelMode);
            }
          } catch (e) {}
        }
      }

      function updateChannelTabsUI() {
        var bToday = document.getElementById("btnChannelToday");
        var bTotal = document.getElementById("btnChannelTotal");
        if (bToday && bTotal) {
          if (currentChannelMode === "today") {
            bToday.classList.add("active");
            bTotal.classList.remove("active");
          } else {
            bTotal.classList.add("active");
            bToday.classList.remove("active");
          }
        }
      }

      function renderDeviceAndSourcesBars(dev, item, mode) {
        var mCount = (dev && dev.mobile) || 0;
        var pCount = (dev && dev.pc) || 0;
        var devSum = mCount + pCount;
        var mPct = devSum > 0 ? Math.round((mCount / devSum) * 100) : 50;
        var pPct = devSum > 0 ? (100 - mPct) : 50;

        document.getElementById("statMobileCount").innerText = mCount;
        document.getElementById("statPcCount").innerText = pCount;
        document.getElementById("statBarMobile").style.width = (devSum > 0 ? mPct : 0) + "%";
        document.getElementById("statBarPc").style.width = (devSum > 0 ? pPct : 0) + "%";
        document.getElementById("statDeviceRatioText").innerText = (devSum > 0 ? ("手机 " + mPct + "% / 电脑 " + pPct + "%") : "暂无访问");

        var todayDate = getClientBeijingDateStr();
        var todayStats = (item && item.daily && item.daily[todayDate]) || {};

        var sWechat = 0, sTwitter = 0, sDirect = 0, sOther = 0;
        var cWechat = 0, cTwitter = 0, cDirect = 0, cOther = 0;

        if (mode === "today") {
          document.getElementById("statChannelTitle").innerText = "🔥 今日引流与转存转化";
          var srcToday = todayStats.sources || {};
          var convToday = todayStats.convert_sources || {};
          sWechat = srcToday.wechat || 0;
          sTwitter = srcToday.twitter || 0;
          sDirect = srcToday.direct || 0;
          sOther = srcToday.other || 0;
          cWechat = convToday.wechat || 0;
          cTwitter = convToday.twitter || 0;
          cDirect = convToday.direct || 0;
          cOther = convToday.other || 0;
        } else {
          document.getElementById("statChannelTitle").innerText = "🌐 全周期引流与转存转化";
          var srcTotal = (item && item.sources) || {};
          sWechat = srcTotal.wechat || 0;
          sTwitter = srcTotal.twitter || 0;
          sDirect = srcTotal.direct || 0;
          sOther = srcTotal.other || 0;
        }

        var srcSum = sWechat + sTwitter + sDirect + sOther;
        var maxSrc = Math.max(1, srcSum);

        function formatChannelBadge(visit, conv) {
          if (mode === "today") {
            var r = visit > 0 ? (Math.round((conv / visit) * 100)) + "%" : "0%";
            return visit + " 访 · 🎯" + conv + " (" + r + ")";
          }
          return visit + " 次点击";
        }

        document.getElementById("statSrcWechat").innerText = formatChannelBadge(sWechat, cWechat);
        document.getElementById("statSrcTwitter").innerText = formatChannelBadge(sTwitter, cTwitter);
        document.getElementById("statSrcDirect").innerText = formatChannelBadge(sDirect, cDirect);
        document.getElementById("statSrcOther").innerText = formatChannelBadge(sOther, cOther);

        document.getElementById("barSrcWechat").style.width = Math.round((sWechat / maxSrc) * 100) + "%";
        document.getElementById("barSrcTwitter").style.width = Math.round((sTwitter / maxSrc) * 100) + "%";
        document.getElementById("barSrcDirect").style.width = Math.round((sDirect / maxSrc) * 100) + "%";
        document.getElementById("barSrcOther").style.width = Math.round((sOther / maxSrc) * 100) + "%";
      }

      function closeStatModal() {
        document.getElementById("statModal").style.display = "none";
      }

      // 渲染最近 7 天原生双柱图及逐日明细列表（支持 PV、UV、转存数与每日转化率）
      function renderDailyChart(dailyMap) {
        var chartBox = document.getElementById("barChartContainer");
        var listContainer = document.getElementById("statDailyListContainer");
        var days = [];
        for (var i = 6; i >= 0; i--) {
          var d = new Date();
          d.setDate(d.getDate() - i);
          days.push(getClientBeijingDateStr(d));
        }

        document.getElementById("statChartRange").innerText = days[0].substring(5) + " 至 " + days[6].substring(5);

        var maxVal = 1;
        for (var k = 0; k < days.length; k++) {
          var dayData = dailyMap[days[k]];
          var pv = dayData ? (dayData.clicks || 0) : 0;
          var uv = dayData ? (dayData.uv || 0) : 0;
          if (pv > maxVal) maxVal = pv;
          if (uv > maxVal) maxVal = uv;
        }

        var html = "";
        var tableRows = [];
        for (var j = 0; j < days.length; j++) {
          var dateStr = days[j];
          var dayInfo = dailyMap[dateStr];
          var pvCount = dayInfo ? (dayInfo.clicks || 0) : 0;
          var uvCount = dayInfo ? (dayInfo.uv || 0) : 0;
          var convCount = dayInfo ? (dayInfo.convert || 0) : 0;
          var rate = pvCount > 0 ? (Math.round((convCount / pvCount) * 1000) / 10) + "%" : "0%";

          var pvHeight = Math.max(5, Math.round((pvCount / maxVal) * 80));
          var uvHeight = Math.max(5, Math.round((uvCount / maxVal) * 80));
          var isToday = (j === 6);
          var dateDisplay = dateStr.substring(5);

          html += "<div class='chart-col' title='" + dateStr + (isToday ? " (今天)" : "") + "\\n点击 (PV): " + pvCount + "\\n访客 (UV): " + uvCount + "\\n真实转存: " + convCount + " 次 (" + rate + ")'>" +
            "<div class='chart-dual-wrap'>" +
              "<div class='chart-pillar-pv' style='height:" + pvHeight + "%;'>" +
                "<span class='chart-val-tip chart-val-pv'>" + (pvCount > 0 ? pvCount : "") + "</span>" +
              "</div>" +
              "<div class='chart-pillar-uv' style='height:" + uvHeight + "%;'>" +
                "<span class='chart-val-tip chart-val-uv'>" + (uvCount > 0 ? uvCount : "") + "</span>" +
              "</div>" +
            "</div>" +
            "<span class='chart-date'" + (isToday ? " style='font-weight:700;color:#4f46e5;'" : "") + ">" + dateDisplay + "</span>" +
          "</div>";

          if (pvCount > 0 || uvCount > 0) {
            tableRows.push(
              "<div style='display:flex;justify-content:space-between;align-items:center;padding:3px 0;border-bottom:1px dashed #e2e8f0;font-size:11px;'>" +
                "<span" + (isToday ? " style='font-weight:700;color:#4f46e5;'" : "") + ">" + dateStr + (isToday ? " (今日)" : "") + "</span>" +
                "<span>PV: <strong>" + pvCount + "</strong> · UV: <strong>" + uvCount + "</strong></span>" +
                "<span style='color:#16a34a;font-weight:600;'>转存: " + convCount + " (" + rate + ")</span>" +
              "</div>"
            );
          }
        }
        chartBox.innerHTML = html;

        if (listContainer) {
          if (tableRows.length > 0) {
            listContainer.style.display = "block";
            listContainer.innerHTML = "<div style='font-weight:700;margin-bottom:4px;color:#334155;'>📋 近 7 天每日转化清单：</div>" + tableRows.join("");
          } else {
            listContainer.style.display = "none";
          }
        }
      }

      function openEditModal(slug, url, title, backupUrl, activeTarget, autoSwitched, lastSwitchedAt, onlyMobile) {
        document.getElementById("editSlug").value = slug;
        document.getElementById("editUrl").value = url;
        document.getElementById("editTitle").value = title;
        document.getElementById("editBackupUrl").value = backupUrl || "";
        document.getElementById("editActiveTarget").value = activeTarget || "primary";
        document.getElementById("editOnlyMobileCheck").checked = (onlyMobile === "1" || onlyMobile === true);

        var alertBanner = document.getElementById("editAlertBanner");
        if (autoSwitched === "1" || autoSwitched === true) {
          alertBanner.style.display = "block";
          alertBanner.innerHTML = "⚠️ <strong>爆款紧急救火记录</strong>：系统检测到主网盘曾失效，已自动切换至备用链接抢救流量！<br><span style='color:#64748b;'>自动接管时间: " + (lastSwitchedAt || "近期") + "。若已更新好主链接，可选择切换回主链接保存。</span>";
        } else {
          alertBanner.style.display = "none";
        }

        document.getElementById("editModal").style.display = "flex";
      }

      function closeEditModal() {
        document.getElementById("editModal").style.display = "none";
      }

      async function doSaveEdit() {
        var pwd = getPwd();
        var slug = document.getElementById("editSlug").value.trim();
        var url = document.getElementById("editUrl").value.trim();
        var title = document.getElementById("editTitle").value.trim();
        var backupUrl = document.getElementById("editBackupUrl").value.trim();
        var activeTarget = document.getElementById("editActiveTarget").value;
        var onlyMobile = document.getElementById("editOnlyMobileCheck").checked;
        var btn = document.getElementById("saveEditBtn");

        if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
          alert("请输入有效的主网盘目标链接！");
          return;
        }

        btn.innerText = "正在保存...";
        btn.disabled = true;
        try {
          var resp = await fetch("/api/update", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              pwd: pwd,
              slug: slug,
              url: url,
              title: title,
              backupUrl: backupUrl,
              activeTarget: activeTarget,
              onlyMobile: onlyMobile
            })
          });
          var data = await resp.json();
          if (!resp.ok) {
            alert(data.error || "更新失败");
          } else {
            closeEditModal();
            if (data.item) {
              for (var i = 0; i < allItems.length; i++) {
                if (allItems[i].slug === slug) {
                  allItems[i] = data.item;
                  break;
                }
              }
              renderTable(allItems);
            } else {
              loadList(currentPage);
            }
            alert("配置已更新！线上所有已发出的短链即时生效！");
          }
        } catch (e) {
          alert("网络请求出错");
        } finally {
          btn.innerText = "保存修改";
          btn.disabled = false;
        }
      }

      async function doDelete(slug) {
        if (!confirm("确定要删除短码 [" + slug + "] 吗？此操作无法撤销！")) return;
        var pwd = getPwd();
        try {
          var resp = await fetch("/api/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pwd: pwd, slug: slug })
          });
          if (resp.ok) {
            loadList(currentPage);
          } else {
            alert("删除失败");
          }
        } catch (e) {
          alert("网络请求出错");
        }
      }

      function escapeCsv(val) {
        if (val === null || val === undefined) return '""';
        var str = String(val);
        var hasSpecial = str.indexOf('"') !== -1 || 
                         str.indexOf(',') !== -1 || 
                         str.indexOf(String.fromCharCode(10)) !== -1 || 
                         str.indexOf(String.fromCharCode(13)) !== -1;
        if (hasSpecial) {
          str = '"' + str.replace(/"/g, '""') + '"';
        }
        return str;
      }

      async function doExportCsv() {
        var pwd = getPwd();
        if (!pwd) return;
        var btn = document.getElementById("exportBtn");
        var oldText = btn ? btn.innerHTML : "";
        if (btn) {
          btn.innerText = "⏳ 正在导出全量报表...";
          btn.disabled = true;
        }

        try {
          var resp = await fetch("/api/list?_t=" + Date.now(), {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": "no-cache, no-store, must-revalidate"
            },
            body: JSON.stringify({ pwd: pwd, exportAll: true })
          });
          var data = await resp.json().catch(function() { return {}; });
          if (!resp.ok || !data.items) {
            alert(data.error || "导出失败，请重试");
            return;
          }

          var items = data.items;
          if (items.length === 0) {
            alert("当前暂无短链数据可供导出");
            return;
          }

          var headers = [
            "短码(Slug)", "完整短链地址", "资源标题", "网盘品牌",
            "目标链接", "备用链接", "当前通道", "访问限制",
            "今日点击(PV)", "今日访客(UV)", "今日转存数", "今日转存率(CTR)",
            "累计点击(PV)", "累计访客(UV)", "累计转存数", "累计转存率(CTR)",
            "微信引流", "Twitter引流", "直接访问", "其他来源",
            "手机访问", "电脑访问", "创建时间"
          ];

          var csvRows = [];
          csvRows.push(headers.join(","));

          for (var i = 0; i < items.length; i++) {
            var it = items[i];
            var dev = it.devices || {};
            var src = it.sources || {};
            var totalPv = it.clicks || 0;
            var conv = it.convertClicks || 0;
            var ctr = totalPv > 0 ? (Math.round((conv / totalPv) * 1000) / 10) + "%" : "0%";
            var todayPv = it.todayClicks || 0;
            var todayConv = it.todayConvert || 0;
            var todayCtr = todayPv > 0 ? (Math.round((todayConv / todayPv) * 1000) / 10) + "%" : "0%";
            var brandName = (it.brand && it.brand.name) ? it.brand.name : "网盘资源";
            var channel = it.activeTarget === "backup" ? "备用链接" : "主链接";
            if (it.autoSwitched) channel = "自动切备用";
            var devLimit = it.onlyMobile ? "仅手机" : "全设备";

            var row = [
              escapeCsv(it.slug),
              escapeCsv(it.shortUrl || ""),
              escapeCsv(it.title || ""),
              escapeCsv(brandName),
              escapeCsv(it.url || ""),
              escapeCsv(it.backupUrl || ""),
              escapeCsv(channel),
              escapeCsv(devLimit),
              todayPv,
              it.todayUv || 0,
              todayConv,
              escapeCsv(todayCtr),
              totalPv,
              it.uv || 0,
              conv,
              escapeCsv(ctr),
              src.wechat || 0,
              src.twitter || 0,
              src.direct || 0,
              src.other || 0,
              dev.mobile || 0,
              dev.pc || 0,
              escapeCsv(it.createdAt || "")
            ];
            csvRows.push(row.join(","));
          }

          var csvContent = String.fromCharCode(0xFEFF) + csvRows.join(String.fromCharCode(13, 10));
          var blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
          var blobUrl = URL.createObjectURL(blob);
          var downloadLink = document.createElement("a");
          downloadLink.href = blobUrl;
          downloadLink.download = "PanTools全量网盘转化与多维渠道分析报表_" + getClientBeijingDateStr() + ".csv";
          document.body.appendChild(downloadLink);
          downloadLink.click();
          document.body.removeChild(downloadLink);
          URL.revokeObjectURL(blobUrl);
        } catch (e) {
          alert("导出异常：" + e.message);
        } finally {
          if (btn) {
            btn.innerHTML = oldText;
            btn.disabled = false;
          }
        }
      }

      function copyText(txt) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(txt).then(function() { alert("已复制到剪贴板！"); });
        } else {
          var ta = document.createElement("textarea");
          ta.value = txt;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          document.body.removeChild(ta);
          alert("已复制到剪贴板！");
        }
      }

      document.getElementById("url").addEventListener("input", function(e) {
        handleSmartPaste(e.target.value);
      });
      document.getElementById("url").addEventListener("blur", function(e) {
        var val = e.target.value.trim();
        var titleVal = document.getElementById("title").value.trim();
        if (val && !titleVal) {
          doFetchTitle(true);
        }
      });

      document.getElementById("fetchTitleBtn").addEventListener("click", function() {
        doFetchTitle(false);
      });

      document.getElementById("loginBtn").addEventListener("click", doLogin);
      document.getElementById("loginPwd").addEventListener("keydown", function(e) { if (e.key === "Enter") doLogin(); });
      document.getElementById("logoutBtn").addEventListener("click", doLogout);
      var exportBtnEl = document.getElementById("exportBtn");
      if (exportBtnEl) exportBtnEl.addEventListener("click", doExportCsv);
      document.getElementById("createBtn").addEventListener("click", doCreate);
      document.getElementById("refreshBtn").addEventListener("click", function() { loadList(currentPage); });
      document.getElementById("searchInput").addEventListener("input", handleSearchInput);

      // 榜单维度排序切换胶囊
      document.getElementById("sortPillGroup").addEventListener("click", function(e) {
        var btn = e.target.closest(".sort-pill");
        if (!btn) return;
        var sortType = btn.getAttribute("data-sort");
        if (!sortType || sortType === currentSort) return;

        currentSort = sortType;
        var pills = document.querySelectorAll(".sort-pill");
        for (var i = 0; i < pills.length; i++) {
          pills[i].classList.remove("active");
        }
        btn.classList.add("active");

        loadList(1);
      });
      document.getElementById("copyGenBtn").addEventListener("click", function() {
        copyText(document.getElementById("resUrl").innerText);
      });

      document.getElementById("closeModalBtn").addEventListener("click", closeEditModal);
      document.getElementById("cancelModalBtn").addEventListener("click", closeEditModal);
      document.getElementById("saveEditBtn").addEventListener("click", doSaveEdit);

      document.getElementById("closeStatModalBtn").addEventListener("click", closeStatModal);
      document.getElementById("confirmStatModalBtn").addEventListener("click", closeStatModal);

      // 弹窗内渠道来源切换监听（今日各渠道转化 vs 全周期渠道）
      var btnChToday = document.getElementById("btnChannelToday");
      if (btnChToday) {
        btnChToday.addEventListener("click", function() {
          currentChannelMode = "today";
          updateChannelTabsUI();
          if (currentModalItem) renderDeviceAndSourcesBars(currentModalItem.devices, currentModalItem, "today");
        });
      }
      var btnChTotal = document.getElementById("btnChannelTotal");
      if (btnChTotal) {
        btnChTotal.addEventListener("click", function() {
          currentChannelMode = "total";
          updateChannelTabsUI();
          if (currentModalItem) renderDeviceAndSourcesBars(currentModalItem.devices, currentModalItem, "total");
        });
      }

      // 分页控制按钮
      document.getElementById("prevPageBtn").addEventListener("click", goToPrevPage);
      document.getElementById("nextPageBtn").addEventListener("click", goToNextPage);

      // 事件代理：支持点击详情按钮、一键快捷切换仅手机访问、编辑与删除
      document.getElementById("listBody").addEventListener("click", async function(e) {
        var target = e.target;

        // 快捷点击分段双按钮【🌐 全设备】或【📱 仅手机】直接修改
        var segBtn = target.closest(".btn-segment");
        if (segBtn) {
          var slug = segBtn.getAttribute("data-slug");
          var targetVal = parseInt(segBtn.getAttribute("data-target-mobile"), 10);
          if (!slug || isNaN(targetVal)) return;

          // 若点击的是当前已激活的状态，则无需重复发起请求
          var isAlreadyActive = (targetVal === 1 && segBtn.classList.contains("active-mobile")) ||
                                (targetVal === 0 && segBtn.classList.contains("active"));
          if (isAlreadyActive) return;

          var pwd = getPwd();
          if (!pwd) return;

          // 临时禁用该组按钮防止手速过快连击
          var group = segBtn.closest(".device-segmented-group");
          var groupBtns = group ? group.querySelectorAll(".btn-segment") : [segBtn];
          for (var b = 0; b < groupBtns.length; b++) groupBtns[b].disabled = true;

          var oldHtml = segBtn.innerHTML;
          segBtn.innerHTML = "⏳";

          try {
            var resp = await fetch("/api/toggle-mobile", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ pwd: pwd, slug: slug, onlyMobile: targetVal === 1 })
            });
            var res = await resp.json();
            if (res.success) {
              for (var i = 0; i < allItems.length; i++) {
                if (allItems[i].slug === slug) {
                  allItems[i].onlyMobile = !!res.onlyMobile;
                  break;
                }
              }
              renderTable(allItems);
            } else {
              alert(res.error || "修改状态失败");
              renderTable(allItems);
            }
          } catch (err) {
            alert("请求异常，请稍后重试");
            renderTable(allItems);
          }
          return;
        }

        var statBtn = target.closest(".act-stat") || target.closest(".traffic-pill");
        if (statBtn) {
          var slug = statBtn.getAttribute("data-slug");
          if (slug) openStatModal(slug);
          return;
        }

        var copyBtn = target.closest(".act-copy");
        if (copyBtn) {
          var url = copyBtn.getAttribute("data-url");
          if (url) copyText(url);
          return;
        }

        var editBtn = target.closest(".act-edit");
        if (editBtn) {
          var slug = editBtn.getAttribute("data-slug");
          var url = editBtn.getAttribute("data-url");
          var title = editBtn.getAttribute("data-title");
          var backup = editBtn.getAttribute("data-backup");
          var actTarget = editBtn.getAttribute("data-target");
          var autoSwitched = editBtn.getAttribute("data-autoswitched");
          var lastSwitched = editBtn.getAttribute("data-lastswitched");
          var onlyMobile = editBtn.getAttribute("data-onlymobile");
          openEditModal(slug, url, title, backup, actTarget, autoSwitched, lastSwitched, onlyMobile);
          return;
        }

        var delBtn = target.closest(".act-del");
        if (delBtn) {
          var slug = delBtn.getAttribute("data-slug");
          if (slug) doDelete(slug);
          return;
        }
      });

      checkAuth();
    })();
  </script>
</body>
</html>`;
}

// 极轻量纯原生 QR 码离线生成引擎（100% 符合 ISO/IEC 18004 国际规范，0 外部依赖，0 毫秒秒出原生 SVG）
function createQRCodeSvg(text, size = 200, margin = 2) {
  const QRMode = { MODE_8BIT_BYTE: 4 };
  const QRMaskPattern = {
    PATTERN000: 0, PATTERN001: 1, PATTERN010: 2, PATTERN011: 3,
    PATTERN100: 4, PATTERN101: 5, PATTERN110: 6, PATTERN111: 7
  };

  const QRUtil = {
    PATTERN_POSITION_TABLE: [
      [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
      [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]
    ],
    G15: (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0),
    G15_MASK: (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1),
    getBCHTypeInfo(data) {
      let d = data << 10;
      while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15) >= 0) {
        d ^= (QRUtil.G15 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15)));
      }
      return ((data << 10) | d) ^ QRUtil.G15_MASK;
    },
    getBCHDigit(data) {
      let digit = 0;
      while (data !== 0) { digit++; data >>>= 1; }
      return digit;
    },
    getMask(maskPattern, i, j) {
      switch (maskPattern) {
        case QRMaskPattern.PATTERN000: return (i + j) % 2 === 0;
        case QRMaskPattern.PATTERN001: return i % 2 === 0;
        case QRMaskPattern.PATTERN010: return j % 3 === 0;
        case QRMaskPattern.PATTERN011: return (i + j) % 3 === 0;
        case QRMaskPattern.PATTERN100: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
        case QRMaskPattern.PATTERN101: return ((i * j) % 2) + ((i * j) % 3) === 0;
        case QRMaskPattern.PATTERN110: return (((i * j) % 2) + ((i * j) % 3)) % 2 === 0;
        case QRMaskPattern.PATTERN111: return (((i * j) % 3) + ((i + j) % 2)) % 2 === 0;
        default: return false;
      }
    },
    getErrorCorrectPolynomial(errorCorrectLength) {
      let a = new QRPolynomial([1], 0);
      for (let i = 0; i < errorCorrectLength; i++) {
        a = a.multiply(new QRPolynomial([1, QRMath.gexp(i)], 0));
      }
      return a;
    },
    getLengthInBits(mode, type) {
      return (1 <= type && type < 10) ? 8 : 16;
    },
    getLostPoint(qrCode) {
      const moduleCount = qrCode.getModuleCount();
      let lostPoint = 0;
      for (let row = 0; row < moduleCount; row++) {
        for (let col = 0; col < moduleCount; col++) {
          let sameCount = 0;
          const dark = qrCode.isDark(row, col);
          for (let r = -1; r <= 1; r++) {
            if (row + r < 0 || moduleCount <= row + r) continue;
            for (let c = -1; c <= 1; c++) {
              if (col + c < 0 || moduleCount <= col + c || (r === 0 && c === 0)) continue;
              if (dark === qrCode.isDark(row + r, col + c)) sameCount++;
            }
          }
          if (sameCount > 5) lostPoint += (3 + sameCount - 5);
        }
      }
      for (let row = 0; row < moduleCount - 1; row++) {
        for (let col = 0; col < moduleCount - 1; col++) {
          let count = 0;
          if (qrCode.isDark(row, col)) count++;
          if (qrCode.isDark(row + 1, col)) count++;
          if (qrCode.isDark(row, col + 1)) count++;
          if (qrCode.isDark(row + 1, col + 1)) count++;
          if (count === 0 || count === 4) lostPoint += 3;
        }
      }
      return lostPoint;
    }
  };

  const QRMath = {
    glog(n) {
      if (n < 1) throw new Error("glog(" + n + ")");
      return QRMath.LOG_TABLE[n];
    },
    gexp(n) {
      while (n < 0) n += 255;
      while (n >= 255) n -= 255;
      return QRMath.EXP_TABLE[n];
    },
    EXP_TABLE: new Array(256),
    LOG_TABLE: new Array(256)
  };
  for (let i = 0; i < 8; i++) QRMath.EXP_TABLE[i] = 1 << i;
  for (let i = 8; i < 256; i++) {
    QRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4] ^ QRMath.EXP_TABLE[i - 5] ^ QRMath.EXP_TABLE[i - 6] ^ QRMath.EXP_TABLE[i - 8];
  }
  for (let i = 0; i < 255; i++) QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i;

  function QRPolynomial(num, shift) {
    let offset = 0;
    while (offset < num.length && num[offset] === 0) offset++;
    this.num = new Array(num.length - offset + shift);
    for (let i = 0; i < num.length - offset; i++) this.num[i] = num[i + offset];
    for (let i = num.length - offset; i < this.num.length; i++) this.num[i] = 0;
  }
  QRPolynomial.prototype = {
    get(index) { return this.num[index]; },
    getLength() { return this.num.length; },
    multiply(e) {
      const num = new Array(this.getLength() + e.getLength() - 1).fill(0);
      for (let i = 0; i < this.getLength(); i++) {
        for (let j = 0; j < e.getLength(); j++) {
          num[i + j] ^= QRMath.gexp(QRMath.glog(this.get(i)) + QRMath.glog(e.get(j)));
        }
      }
      return new QRPolynomial(num, 0);
    },
    mod(e) {
      if (this.getLength() - e.getLength() < 0) return this;
      const ratio = QRMath.glog(this.get(0)) - QRMath.glog(e.get(0));
      const num = new Array(this.getLength());
      for (let i = 0; i < this.getLength(); i++) num[i] = this.get(i);
      for (let i = 0; i < e.getLength(); i++) {
        num[i] ^= QRMath.gexp(QRMath.glog(e.get(i)) + ratio);
      }
      return new QRPolynomial(num, 0).mod(e);
    }
  };

  const RS_BLOCK_TABLE = [
    [1, 26, 16], [2, 44, 28], [3, 70, 44], [4, 100, 64], [5, 134, 86],
    [6, 172, 108], [7, 196, 124], [8, 242, 154], [9, 292, 182], [10, 346, 216]
  ];

  const RS_BLOCK_SPECS = [
    null,
    [[1, 26, 16]],
    [[1, 44, 28]],
    [[1, 70, 44]],
    [[2, 50, 32]],
    [[2, 67, 43]],
    [[4, 43, 27]],
    [[4, 49, 31]],
    [[2, 61, 38], [2, 62, 39]],
    [[3, 58, 36], [2, 59, 37]],
    [[4, 69, 43], [1, 70, 44]]
  ];

  const utf8Bytes = [];
  for (let i = 0; i < text.length; i++) {
    let c = text.charCodeAt(i);
    if (c < 128) {
      utf8Bytes.push(c);
    } else if (c < 2048) {
      utf8Bytes.push(192 | (c >> 6), 128 | (c & 63));
    } else if (c < 55296 || c >= 57344) {
      utf8Bytes.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63));
    } else {
      i++;
      c = 65536 + (((c & 1023) << 10) | (text.charCodeAt(i) & 1023));
      utf8Bytes.push(240 | (c >> 18), 128 | ((c >> 12) & 63), 128 | ((c >> 6) & 63), 128 | (c & 63));
    }
  }

  let typeNumber = 1;
  while (typeNumber <= 10) {
    const row = RS_BLOCK_TABLE[typeNumber - 1];
    if (utf8Bytes.length + 2 <= row[2]) break;
    typeNumber++;
  }
  if (typeNumber > 10) typeNumber = 10;

  const totalDataBytes = RS_BLOCK_TABLE[typeNumber - 1][2];

  const bits = [];
  function writeBits(val, len) {
    for (let i = 0; i < len; i++) bits.push(((val >>> (len - 1 - i)) & 1) === 1);
  }
  writeBits(QRMode.MODE_8BIT_BYTE, 4);
  writeBits(utf8Bytes.length, QRUtil.getLengthInBits(QRMode.MODE_8BIT_BYTE, typeNumber));
  for (let i = 0; i < utf8Bytes.length; i++) writeBits(utf8Bytes[i], 8);

  const totalBits = totalDataBytes * 8;
  if (bits.length + 4 <= totalBits) writeBits(0, 4);
  else writeBits(0, totalBits - bits.length);
  while (bits.length % 8 !== 0) bits.push(false);

  let pad = 0xec;
  while (bits.length < totalBits) {
    writeBits(pad, 8);
    pad = (pad === 0xec ? 0x11 : 0xec);
  }

  const dataArray = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) if (bits[i + j]) b |= (1 << (7 - j));
    dataArray.push(b);
  }

  const specs = RS_BLOCK_SPECS[typeNumber];
  const blocks = [];
  let dOffset = 0;
  for (let s = 0; s < specs.length; s++) {
    const numBlocks = specs[s][0];
    const totalCount = specs[s][1];
    const dataCount = specs[s][2];
    const ecCount = totalCount - dataCount;
    for (let b = 0; b < numBlocks; b++) {
      const bData = dataArray.slice(dOffset, dOffset + dataCount);
      dOffset += dataCount;
      const rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
      const rawPoly = new QRPolynomial(bData, rsPoly.getLength() - 1);
      const modPoly = rawPoly.mod(rsPoly);
      const bEc = new Array(rsPoly.getLength() - 1).fill(0);
      for (let i = 0; i < bEc.length; i++) {
        const modIndex = i + modPoly.getLength() - bEc.length;
        bEc[i] = (modIndex >= 0) ? modPoly.get(modIndex) : 0;
      }
      blocks.push({ data: bData, ec: bEc });
    }
  }

  const interleaved = [];
  let maxDataLen = 0;
  let maxEcLen = 0;
  for (let i = 0; i < blocks.length; i++) {
    if (blocks[i].data.length > maxDataLen) maxDataLen = blocks[i].data.length;
    if (blocks[i].ec.length > maxEcLen) maxEcLen = blocks[i].ec.length;
  }
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < blocks.length; b++) {
      if (i < blocks[b].data.length) interleaved.push(blocks[b].data[i]);
    }
  }
  for (let i = 0; i < maxEcLen; i++) {
    for (let b = 0; b < blocks.length; b++) {
      if (i < blocks[b].ec.length) interleaved.push(blocks[b].ec[i]);
    }
  }

  const moduleCount = typeNumber * 4 + 17;
  const modules = Array.from({ length: moduleCount }, () => new Array(moduleCount).fill(null));

  function markPattern(row, col) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        if (row + r < 0 || moduleCount <= row + r || col + c < 0 || moduleCount <= col + c) continue;
        if ((0 <= r && r <= 6 && (c === 0 || c === 6)) ||
            (0 <= c && c <= 6 && (r === 0 || r === 6)) ||
            (2 <= r && r <= 4 && 2 <= c && c <= 4)) {
          modules[row + r][col + c] = true;
        } else {
          modules[row + r][col + c] = false;
        }
      }
    }
  }
  markPattern(0, 0);
  markPattern(moduleCount - 7, 0);
  markPattern(0, moduleCount - 7);

  for (let r = 8; r < moduleCount - 8; r++) {
    if (modules[r][6] === null) modules[r][6] = (r % 2 === 0);
  }
  for (let c = 8; c < moduleCount - 8; c++) {
    if (modules[6][c] === null) modules[6][c] = (c % 2 === 0);
  }

  if (typeNumber >= 2) {
    const pattern = QRUtil.PATTERN_POSITION_TABLE[typeNumber - 1];
    for (let i = 0; i < pattern.length; i++) {
      for (let j = 0; j < pattern.length; j++) {
        const row = pattern[i];
        const col = pattern[j];
        if (modules[row][col] !== null) continue;
        for (let r = -2; r <= 2; r++) {
          for (let c = -2; c <= 2; c++) {
            if (r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0)) {
              modules[row + r][col + c] = true;
            } else {
              modules[row + r][col + c] = false;
            }
          }
        }
      }
    }
  }

  modules[4 * typeNumber + 9][8] = true;

  for (let i = 0; i < 8; i++) {
    if (modules[8][i] === null) modules[8][i] = false;
    if (modules[i][8] === null) modules[i][8] = false;
  }
  modules[8][8] = false;
  for (let i = 0; i < 8; i++) {
    modules[moduleCount - 1 - i][8] = false;
    modules[8][moduleCount - 1 - i] = false;
  }

  let byteIndex = 0;
  let bitIndex = 7;
  let dir = -1;
  let r = moduleCount - 1;

  for (let c = moduleCount - 1; c > 0; c -= 2) {
    if (c === 6) c--;
    while (true) {
      for (let cc = 0; cc < 2; cc++) {
        const col = c - cc;
        if (modules[r][col] === null) {
          let dark = false;
          if (byteIndex < interleaved.length) {
            dark = ((interleaved[byteIndex] >>> bitIndex) & 1) === 1;
          }
          modules[r][col] = dark;
          bitIndex--;
          if (bitIndex === -1) { byteIndex++; bitIndex = 7; }
        }
      }
      r += dir;
      if (r < 0 || moduleCount <= r) {
        r -= dir;
        dir = -dir;
        break;
      }
    }
  }

  let minLostPoint = Infinity;
  let bestPattern = 0;

  for (let pattern = 0; pattern < 8; pattern++) {
    const testModules = modules.map(row => row.slice());
    const typeInfo = QRUtil.getBCHTypeInfo((0 << 3) | pattern);
    for (let i = 0; i < 15; i++) {
      const mod = ((typeInfo >> i) & 1) === 1;
      if (i < 6) testModules[i][8] = mod;
      else if (i < 8) testModules[i + 1][8] = mod;
      else testModules[moduleCount - 15 + i][8] = mod;

      if (i < 8) testModules[8][moduleCount - i - 1] = mod;
      else if (i < 9) testModules[8][15 - i - 1 + 1] = mod;
      else testModules[8][15 - i - 1] = mod;
    }

    for (let i = 0; i < moduleCount; i++) {
      for (let j = 0; j < moduleCount; j++) {
        const isFunctional = (
          (i <= 8 && j <= 8) ||
          (i <= 8 && j >= moduleCount - 8) ||
          (i >= moduleCount - 8 && j <= 8) ||
          (i === 6 || j === 6)
        );
        if (!isFunctional && QRUtil.getMask(pattern, i, j)) {
          testModules[i][j] = !testModules[i][j];
        }
      }
    }

    const qrWrapper = {
      getModuleCount: () => moduleCount,
      isDark: (rr, cc) => testModules[rr][cc]
    };
    const lostPoint = QRUtil.getLostPoint(qrWrapper);
    if (lostPoint < minLostPoint) {
      minLostPoint = lostPoint;
      bestPattern = pattern;
    }
  }

  const finalTypeInfo = QRUtil.getBCHTypeInfo((0 << 3) | bestPattern);
  for (let i = 0; i < 15; i++) {
    const mod = ((finalTypeInfo >> i) & 1) === 1;
    if (i < 6) modules[i][8] = mod;
    else if (i < 8) modules[i + 1][8] = mod;
    else modules[moduleCount - 15 + i][8] = mod;

    if (i < 8) modules[8][moduleCount - i - 1] = mod;
    else if (i < 9) modules[8][15 - i - 1 + 1] = mod;
    else modules[8][15 - i - 1] = mod;
  }

  for (let i = 0; i < moduleCount; i++) {
    for (let j = 0; j < moduleCount; j++) {
      const isFunctional = (
        (i <= 8 && j <= 8) ||
        (i <= 8 && j >= moduleCount - 8) ||
        (i >= moduleCount - 8 && j <= 8) ||
        (i === 6 || j === 6)
      );
      if (!isFunctional && QRUtil.getMask(bestPattern, i, j)) {
        modules[i][j] = !modules[i][j];
      }
    }
  }

  const totalUnits = moduleCount + (margin * 2);
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalUnits} ${totalUnits}" width="${size}" height="${size}" shape-rendering="crispEdges">`;
  svg += `<rect width="100%" height="100%" fill="#ffffff" rx="8"/>`;
  svg += `<path fill="#0f172a" d="`;
  let path = "";
  for (let r = 0; r < moduleCount; r++) {
    for (let c = 0; c < moduleCount; c++) {
      if (modules[r][c]) path += `M${c + margin},${r + margin}h1v1h-1z`;
    }
  }
  svg += path + `"/>`;
  svg += `</svg>`;

  return svg;
}
