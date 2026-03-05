const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(cookieParser());

// 環境変数
const sessionSecret = process.env.SESSION_SECRET || 'dev-secret-key';
const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
const adminPassword = process.env.ADMIN_PASSWORD || 'password123';
const gasApiUrl = process.env.GAS_API_URL || '';
const gasApiKey = process.env.GAS_API_KEY || '';

// セッショントークンの署名作成
function createSessionToken(sessionId) {
    const sig = crypto.createHmac('sha256', sessionSecret).update(sessionId).digest('hex');
    return `${sessionId}.${sig}`;
}

// セッショントークンの署名検証
function verifySessionToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 2) return false;
        const [sessionId, signature] = parts;
        const expected = crypto.createHmac('sha256', sessionSecret).update(sessionId).digest('hex');
        return signature === expected;
    } catch {
        return false;
    }
}

// 認証チェックミドルウェア
function requireAuth(req, res, next) {
    const token = req.cookies['session_token'];
    if (token && verifySessionToken(token)) {
        return next();
    }
    res.redirect('/login.html');
}

// ルートパス ("/") → 認証チェック後に index.html を返す
app.get('/', requireAuth, (req, res) => {
    const htmlPath = path.join(__dirname, 'functions', 'views', 'index.html');
    res.sendFile(htmlPath);
});

// public/ 以下を静的配信（login.html など）
app.use(express.static(path.join(__dirname, 'public')));

// POST /api/login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (email === adminEmail && password === adminPassword) {
        const sessionId = crypto.randomUUID();
        const token = createSessionToken(sessionId);
        res.cookie('session_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 1週間
        });
        res.json({ status: 'success' });
    } else {
        res.status(401).json({ status: 'error', message: 'メールアドレスまたはパスワードが間違っています。' });
    }
});

// GET /api/logout
app.get('/api/logout', (req, res) => {
    res.clearCookie('session_token', { path: '/' });
    res.json({ status: 'success' });
});

// GET /api/config (要認証)
app.get('/api/config', requireAuth, (req, res) => {
    res.json({
        gasApiUrl: gasApiUrl.trim(),
        gasApiKey: gasApiKey.trim()
    });
});

app.listen(PORT, () => {
    console.log(`Tenko Server running at http://localhost:${PORT}`);
});
