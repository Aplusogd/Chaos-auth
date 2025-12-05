// DEBUG ROUTE: DASHBOARD CHECK
app.get('/dashboard.html', (req, res) => {
    const file = path.join(__dirname, 'public/dashboard.html');
    console.log(`[DEBUG] Request for Dashboard. Looking for file at: ${file}`);
    
    if (fs.existsSync(file)) {
        console.log("[DEBUG] File FOUND. Sending...");
        res.sendFile(file);
    } else {
        console.error("[ERROR] File NOT FOUND. Please check the 'public' folder.");
        res.status(404).send("<h1>ERROR: dashboard.html is missing from public folder</h1>");
    }
});
