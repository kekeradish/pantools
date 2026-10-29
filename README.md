# 🚀 PanTools - 终身免费的网盘短链防封中转与流量雷达系统

> **做资源分享和网盘拉新最怕的是什么？**  
> 辛辛苦苦把帖子引爆了，几十万播放涌进来，结果粉丝留言“链接失效了”，或者在微信里直接爆红被安全中心拦截，眼睁睁看着白花花的流量打水漂！  
> 
> **PanTools** 是一个专为网盘资源分享、推文淘金客、私域博主设计的**单文件全栈 Serverless 防封系统**。基于 **Cloudflare Workers + D1 数据库** 深度打造，**0 服务器成本、0 域名备案门槛、0 运维负担**，让你的网盘链接“不怕失联、微信不爆红、看清真实转存率”！

---

## 🌟 核心杀手锏特性

- 🛡️ **双轨备用链接自动救火（不怕失联）**：为每个短链同时配置主网盘与备用网盘。一旦主链接被取消分享或被封，系统自动秒级切换至备用网盘接管流量，老帖子终身有效！
- 📱 **微信生态智能防拦截**：在微信内置浏览器打开时，自动触发优雅的右上角引导遮罩，提示用户“在浏览器中打开”，彻底绕开微信域名拦截机制。
- 🎯 **真实转存率与 CTR 转化漏斗**：不仅记录点击量(PV)与访客数(UV)，更精确统计用户是否真正点击了“打开网盘/转存”，内置会话级防刷排重，转存率真实可靠。
- 📊 **深度流量画像（六宫格数据大屏）**：针对单个短链展示今日PV/UV、累计PV/UV、人均访问频次、真实转存率、最近 7 天柱状趋势图，并由算法自动生成运营诊断小贴士！
- 💻 **电脑端自动扫码二维码**：主做移动端私域时，可一键开启“仅手机访问”。电脑端访问时自动生成原生无损 SVG 矢量二维码，引导扫码，防止同行批量爬取。
- ⚡ **D1 工业级服务端分页与极速搜索**：底层原生 SQL `LIMIT / OFFSET` 与毫秒级 `LIKE` 模糊搜索，全库单条 SQL 聚合大盘，数万条短链依然秒级响应。
- 🚀 **15 秒边缘微缓存 (Edge Cache)**：落地页由 Cloudflare 全球 300+ 边缘机房就近毫秒级吐出，抗击百万级流量洪峰，后台管理界面与 API 保持 0 缓存即时生效。
- 📥 **一键导出全量报表 (Excel / CSV)**：内置 `\uFEFF` UTF-8 BOM 头防乱码规范，一键导出完整资产与转化率数据，兼容 Windows Excel、WPS、Mac Numbers。
- 📦 **纯单文件，一键部署**：整个前端 UI、后台管理控制台、后端 RESTful API、自适应热升级数据库全部浓缩在单个 `work.js` 文件中！

---

## 🛠️ 极速 4 步部署指南（约 5~10 分钟）

### 第一步：准备 Cloudflare 账号
打开 [Cloudflare 官网](https://cloudflare.com/) 免费注册一个账号（每天免费赠送 10 万次 Workers 请求，完全足够日常使用）。

### 第二步：创建 D1 云数据库并建表
1. 登录 Cloudflare 控制台，进入左侧 **存储和数据库 (D1)**；
2. 点击 **创建数据库**，数据库名称填入 `pan_db`，区域推荐选择亚太地区；
3. 进入 `pan_db` 详情页，点击顶部的 **控制台 (Console)**；
4. 复制本项目 [`schema.sql`](./schema.sql) 中的建表代码，粘贴到输入框中并点击 **执行**：

```sql
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
  mobile_clicks INTEGER DEFAULT 0,
  pc_clicks INTEGER DEFAULT 0,
  source_twitter INTEGER DEFAULT 0,
  source_direct INTEGER DEFAULT 0,
  source_other INTEGER DEFAULT 0,
  created_at TEXT DEFAULT '',
  created_timestamp INTEGER DEFAULT 0,
  daily_json TEXT DEFAULT '{}'
);
```

### 第三步：创建 Worker 服务并绑定数据库
1. 在 Cloudflare 左侧导航栏进入 **Workers 和 Pages**，点击 **创建应用程序** ➔ 创建 Worker（名称可自定，如 `pantools`）；
2. 创建完成后进入该 Worker 主页，点击 **设置 (Settings)** ➔ **变量与机密 (Variables and Secrets)**；
3. 找到 **D1 数据库绑定** 区域，点击 **添加绑定**：
   - **变量名称（必须严格大写）**：`DB`
   - **D1 数据库**：下拉选择刚才创建的 `pan_db`
4. 点击右上角 **部署** 保存。

### 第四步：粘贴代码，立即上线！
1. 回到 Worker 主页，点击右上角的 **编辑代码**；
2. 将左侧默认的代码全选删除，直接将本项目的 [`work.js`](./work.js) 代码全文复制并粘贴进去；
3. 点击右上角 **保存并部署 (Save and deploy)**！

🎉 **大功告成！** 打开分配给你的 Worker 域名（例如 `https://你的域名.workers.dev/my-admin-7788`），输入初始密码 `123456`，即可畅享你的专属网盘流量控制大屏！

---

## 🔐 生产环境安全与隐私建议

为了保障您线上系统的绝对安全，强烈建议在 Worker 的 **设置 (Settings) ➔ 变量与机密 (Variables and Secrets)** 中配置两条加密环境变量：

| 变量名 | 说明 | 示例 |
| :--- | :--- | :--- |
| `ADMIN_PASSWORD` | 自定义管理员专属复杂密码 | `MyPass_8899@#!` |
| `ADMIN_PATH` | 自定义后台隐藏管理路径 | `my-secret-pan-666` |

*配置后，系统会自动以您的环境变量为准，代码内默认的 `123456` 与 `my-admin-7788` 将自动失效，任何人即使查看开源代码也绝对无法推测出您的真实后台！*

---

## 📄 开源许可证

本项目基于 [MIT License](./LICENSE) 协议开源，完全免费，允许自由修改与商业使用。

如果 PanTools 对你的资源分享或网盘收益有所帮助，欢迎在右上角点一个 **⭐️ Star** 支持一下！
