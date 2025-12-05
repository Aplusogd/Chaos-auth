// ... (All previous SaaS/Chaos code remains above) ...

// ==========================================
// STATIC FILES & ROUTING (THE FIX)
// ==========================================
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// 1. ROOT -> LOGIN (app.html)
app.get('/', (req, res) => {
    res.sendFile(path.join(publicPath, 'app.html'));
});

// 2. /app -> LOGIN (app.html) - FIXES YOUR ERROR
app.get('/app', (req, res) => {
    res.sendFile(path.join(publicPath, 'app.html'));
});

// 3. /dashboard -> DASHBOARD (dashboard.html)
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(publicPath, 'dashboard.html'));
});

// 4. CATCH-ALL (Redirect unknowns to Login)
app.get('*', (req, res) => {
    res.redirect('/');
});

app.listen(PORT, '0.0.0.0', () => console.log(`>>> A+ CHAOS ONLINE: ${PORT}`));
