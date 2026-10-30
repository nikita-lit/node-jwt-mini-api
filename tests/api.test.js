const {test, before, after} = require("node:test");
const assert = require("node:assert");
const {spawn} = require("node:child_process");
const crypto = require("node:crypto");
const path = require("node:path");
const jwt = require("jsonwebtoken");

const SECRET = crypto.randomBytes(32).toString("hex");
const URL = "http://localhost:5050";
const SHORT_URL = "http://localhost:5051"; // tokens expire after 1 second

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const b64url = (data) => Buffer.from(JSON.stringify(data)).toString("base64url");

const servers = [];
let student, admin, claims;

async function startServer(port, ttl)
{
    const env = {...process.env, JWT_SECRET: SECRET, PORT: port, JWT_TTL_SECONDS: ttl};
    servers.push(spawn(process.execPath, [path.join(__dirname, "..", "app.js")], {env, stdio: "ignore"}));

    for (let i = 0; i < 50; i++)
    {
        try
        {
            return await fetch(`http://localhost:${port}/profile`);
        } catch
        {
            await sleep(100);
        }
    }
    throw new Error(`Server did not start on port ${port}`);
}

function login(username, password, url = URL)
{
    return fetch(`${url}/login`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({username, password}),
    });
}

async function getToken(username, password, url = URL)
{
    const res = await login(username, password, url);
    return (await res.json()).token;
}

function get(endpoint, token, url = URL)
{
    return fetch(`${url}${endpoint}`, {headers: token ? {Authorization: `Bearer ${token}`} : {}});
}

before(async () =>
{
    await startServer(5050, 300);
    await startServer(5051, 1);
    student = await getToken("mari", "mari-parool");
    admin = await getToken("juhan", "juhan-parool");
    claims = jwt.decode(student);
});

after(() => servers.forEach((server) => server.kill()));

test("T01 login as student returns a token with sub, role and exp", async () =>
{
    const res = await login("mari", "mari-parool");
    assert.strictEqual(res.status, 200);

    const decoded = jwt.verify((await res.json()).token, SECRET, {algorithms: ["HS256"]});
    assert.strictEqual(decoded.sub, "mari");
    assert.strictEqual(decoded.role, "student");
    assert.ok(Math.abs(decoded.exp - Date.now() / 1000 - 300) < 5);
});

test("T02 login as admin", async () =>
{
    assert.strictEqual((await login("juhan", "juhan-parool")).status, 200);
});

test("T03 wrong password", async () =>
{
    assert.strictEqual((await login("mari", "wrong")).status, 401);
});

test("T04 valid token on /profile", async () =>
{
    const res = await get("/profile", student);
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(await res.json(), claims);
});

test("T05 missing token", async () =>
{
    assert.strictEqual((await get("/profile")).status, 401);
});

test("T06 changed payload, old signature", async () =>
{
    const [header, , signature] = student.split(".");
    const token = `${header}.${b64url({...claims, role: "admin"})}.${signature}`;
    assert.strictEqual((await get("/profile", token)).status, 401);
});

test("T07 expired token", async () =>
{
    const token = await getToken("mari", "mari-parool", SHORT_URL);
    await sleep(1100);
    assert.strictEqual((await get("/profile", token, SHORT_URL)).status, 401);
});

test("T08 student on /admin", async () =>
{
    assert.strictEqual((await get("/admin", student)).status, 403);
});

test("T09 admin on /admin", async () =>
{
    assert.strictEqual((await get("/admin", admin)).status, 200);
});

test("T10 admin token signed with the wrong key", async () =>
{
    const token = jwt.sign({...claims, role: "admin"}, "x".repeat(32));
    assert.strictEqual((await get("/admin", token)).status, 401);
});

test("T11 alg=none token", async () =>
{
    const token = `${b64url({alg: "none", typ: "JWT"})}.${b64url({...claims, role: "admin"})}.`;
    assert.strictEqual((await get("/admin", token)).status, 401);
});

test("T12 token signed with a disallowed algorithm", async () =>
{
    const token = jwt.sign(claims, SECRET, {algorithm: "HS512"});
    assert.strictEqual((await get("/profile", token)).status, 401);
});
