const { onRequest } = require("firebase-functions/v2/https");
const { setGlobalOptions } = require("firebase-functions/v2");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

setGlobalOptions({ region: "asia-northeast1" }); // Japan region

// セッショントークンの署名作成
function createSessionToken(sessionId, secret) {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(sessionId);
    const signature = hmac.digest('hex');
    return `${sessionId}.${signature}`;
}

// セッショントークンの署名検証
function verifySessionToken(token, secret) {
    try {
        const parts = token.split('.');
        if (parts.length !== 2) return false;
        const [sessionId, signature] = parts;
        const expectedSignature = crypto.createHmac('sha256', secret).update(sessionId).digest('hex');
        return signature === expectedSignature;
    } catch {
        return false;
    }
}

// Cookie文字列のパース
function parseCookies(cookieHeader) {
    if (!cookieHeader) return {};
    return Object.fromEntries(
        cookieHeader.split(';').map(c => c.trim()).map(c => {
            const idx = c.indexOf('=');
            if (idx === -1) return [c, ''];
            return [c.slice(0, idx), c.slice(idx + 1)];
        })
    );
}

exports.api = onRequest(async (req, res) => {
    // リクエストのURLパスを取得
    const url = new URL(req.url, `https://${req.headers.host}`);
    const pathname = url.pathname;

    // 環境変数（存在しない場合はデフォルト値や空文字をセット）
    const sessionSecret = process.env.SESSION_SECRET || 'dev-secret-key';
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'password123';
    const gasApiUrl = process.env.GAS_API_URL || '';
    const gasApiKey = process.env.GAS_API_KEY || '';

    // セッションチェック
    const cookies = parseCookies(req.headers.cookie);
    const sessionToken = cookies['session_token'];
    let isAuthenticated = false;
    if (sessionToken && verifySessionToken(sessionToken, sessionSecret)) {
        isAuthenticated = true;
    }

    // 1. ルートパス ("/")
    if (pathname === '/') {
        if (!isAuthenticated) {
            // 未ログインならHosting側にある login.html へリダイレクト
            res.redirect(302, '/login.html');
            return;
        }

        // ログイン済みの場合は、保護された index.html を読み込んで返す
        const htmlPath = path.join(__dirname, 'views', 'index.html');
        try {
            const html = fs.readFileSync(htmlPath, 'utf-8');
            res.set('Content-Type', 'text/html; charset=utf-8');
            res.send(html);
        } catch (e) {
            console.error(e);
            res.status(500).send('Error loading index.html');
        }
        return;
    }

    // 2. ログインAPI
    if (pathname === '/api/login' && req.method === 'POST') {
        const { email, password } = req.body || {};
        if (email === adminEmail && password === adminPassword) {
            const sessionId = crypto.randomUUID();
            const token = createSessionToken(sessionId, sessionSecret);
            // HttpOnly, SecureでCookieをセット
            res.setHeader('Set-Cookie', `session_token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${60 * 60 * 24 * 7}`);
            res.status(200).json({ status: 'success' });
        } else {
            res.status(401).json({ status: 'error', message: 'メールアドレスまたはパスワードが間違っています。' });
        }
        return;
    }

    // 3. ログアウトAPI
    if (pathname === '/api/logout') {
        // Cookieを無効化
        res.setHeader('Set-Cookie', 'session_token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
        res.status(200).json({ status: 'success' });
        return;
    }

    // 4. GAS設定情報の取得API (要認証)
    if (pathname === '/api/config') {
        if (!isAuthenticated) {
            res.status(401).json({ status: 'error', message: 'Unauthorized' });
            return;
        }
        res.status(200).json({
            gasApiUrl: gasApiUrl.trim(),
            gasApiKey: gasApiKey.trim()
        });
        return;
    }

    // どれにもマッチしないAPIパス
    if (pathname.startsWith('/api/')) {
        res.status(404).json({ error: 'Not found' });
        return;
    }

    // その他想定外のアクセス
    res.status(404).send('Not Found');
});
