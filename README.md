# JWT mini-API

A small Express API with JWT authentication.

| Endpoint | Description | Responses |
| --- | --- | --- |
| `POST /login` | Checks username and password, returns a token (`sub`, `role`, `exp`, valid for 5 min) | 200, 401 |
| `GET /profile` | Returns the token data | 200, 401 |
| `GET /admin` | Requires the `admin` role | 200, 401, 403 |

## Run

Requires Node.js. The server does not start without `JWT_SECRET`.

```bash
npm install
export JWT_SECRET="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
npm start
```

## Tests

```bash
npm test
```

The tests start the server with a secret and send HTTP requests to it.
