// 仅供规则自测的漏洞样例：rules/web-baseline.yml 的 web-base- 规则应命中 >= 3 处
const express = require('express');
const cors = require('cors');
const app = express();

// 场景 1：cors 通配 origin + credentials:true → web-base-cors-wildcard-credentials
app.use(cors({ origin: '*', credentials: true }));

// 场景 2：cors 反射 origin + credentials:true → web-base-cors-reflected-origin-credentials
app.use(cors({ origin: true, credentials: true }));

app.post('/login', (req, res) => {
  // 场景 3：res.cookie options 缺 httpOnly/secure → web-base-cookie-missing-security-flags
  res.cookie('sid', req.sessionID, { maxAge: 3600000, path: '/' });
  res.json({ ok: true });
});

app.post('/track', (req, res) => {
  // 场景 4：显式 httpOnly: false，仍缺 httpOnly 语义 → web-base-cookie-missing-security-flags
  res.cookie('tracker', req.query.t, { httpOnly: false, secure: true });
  res.json({ ok: true });
});

app.post('/logout', (req, res) => {
  // 场景 5：显式 secure: false → web-base-cookie-secure-false
  res.cookie('sid', '', { httpOnly: true, secure: false, maxAge: 0 });
  res.json({ ok: true });
});

app.listen(3000);
