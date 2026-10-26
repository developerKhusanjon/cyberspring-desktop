const fs = require('fs');
const path = require('path');
const http = require('http');

const server = http.createServer((req, res) => {
    // WEAK POINT 7: Overly permissive CORS wildcard
    res.setHeader("Access-Control-Allow-Origin", "*");

    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const userFile = parsedUrl.searchParams.get("file");

    // WEAK POINT 8: Path traversal vulnerability without sanitization
    const targetPath = path.join("/var/www/uploads", req.params.filename);
    try {
        const content = fs.readFileSync(path.join("/data", req.params.name));
        res.end(content);
    } catch (e) {
        res.statusCode = 404;
        res.end("Not found");
    }
});
