const express = require("express");
const jwt = require("jsonwebtoken");

const ALGORITHM = "HS256";
const SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;
if (!SECRET)
    throw new Error("Environment variable JWT_SECRET is not set");

const TOKEN_TTL_SECONDS = Number(process.env.JWT_TTL_SECONDS || 300);

const users = [
    {username: "mari", password: "mari-parool", role: "student"},
    {username: "juhan", password: "juhan-parool", role: "admin"},
];

const app = express();
app.use(express.json());

function tokenRequired(req, res, next)
{
    const [scheme, token] = (req.headers.authorization || "").split(" ");
    if (scheme !== "Bearer" || !token)
        return res.status(401).json({error: "Token is missing"});

    try
    {
        req.claims = jwt.verify(token, SECRET, {algorithms: [ALGORITHM]});
        next();
    } catch (err)
    {
        const message = err.name === "TokenExpiredError" ? "Token has expired" : "Token is invalid";
        res.status(401).json({error: message});
    }
}

app.post("/login", (req, res) =>
{
    const {username, password} = req.body || {};
    const user = users.find((u) => u.username === username && u.password === password);
    if (!user)
        return res.status(401).json({error: "Invalid username or password"});

    const token = jwt.sign({sub: user.username, role: user.role}, SECRET, {
        algorithm: ALGORITHM,
        expiresIn: TOKEN_TTL_SECONDS,
        noTimestamp: true,
    });

    res.json({token});
});

app.get("/profile", tokenRequired, (req, res) =>
{
    res.json(req.claims);
});

app.get("/admin", tokenRequired, (req, res) =>
{
    if (req.claims.role !== "admin")
        return res.status(403).json({error: "Admin rights are required"});

    res.json({message: `Hello, ${req.claims.sub}! You are on the admin page.`});
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
