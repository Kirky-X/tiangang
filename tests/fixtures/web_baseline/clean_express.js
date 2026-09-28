// 仅供规则自测的正确样例：rules/web-baseline.yml 的 web-base- 规则应 0 命中
const express = require('express');
const cors = require('cors');
const app = express();

const allowlist = ['https://app.example.com'];

const corsOptions = {
  origin(origin, callback) {
    if (allowlist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));

app.post('/login', (req, res) => {
  res.cookie('sid', req.sessionID, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000,
    path: '/',
  });
  res.json({ ok: true });
});

app.post('/logout', (req, res) => {
  res.clearCookie('sid', { path: '/' });
  res.json({ ok: true });
});

app.listen(3000);
