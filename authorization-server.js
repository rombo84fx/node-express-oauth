const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/authorize', (req, res) => {
	const { client_id, scope } = req.query
	if (clients.hasOwnProperty(client_id) &&
		containsAll(clients[client_id].scopes, scope.split(" "))) {
		const requestId = randomString()
		requests[requestId] = req.query
		res.render("login",
			{
				client: clients[client_id],
				scope,
				requestId
			})
	} else {
		res.status(401).end()
	}
})

app.post("/approve", (req, res) => {
	const { userName, password, requestId } = req.body

	if (users[userName] === password && requests.hasOwnProperty(requestId)) {
		const clientReq = requests[requestId]
		delete requests[requestId]
		const code = randomString()
		authorizationCodes[code] = { clientReq, userName }
		const { redirect_uri, state } = clientReq
		const redirectUrl = new URL(redirect_uri)
		redirectUrl.searchParams.append("code", code)
		redirectUrl.searchParams.append("state", state)
		res.redirect(redirectUrl)
	} else {
		res.status(401).end()
	}
})

app.post('/token', (req, res) => {
	if (req.headers.hasOwnProperty("authorization")) {
		const { clientId, clientSecret } = decodeAuthCredentials(req.headers.authorization)
		if (clients[clientId].clientSecret === clientSecret) {
			const { code } = req.body
			if (authorizationCodes.hasOwnProperty(code)) {
				const authorizationCode = authorizationCodes[code]
				delete authorizationCodes[code]
				const token = jwt.sign(
					{
						userName: authorizationCode.userName,
						scope: authorizationCode.clientReq.scope
					}, config.privateKey, { algorithm: "RS256" })
				res.json(
					{
						"access_token": token,
						"token_type": "Bearer"
					}
				)
			} else {
				res.status(401).end()
			}
		} else {
			res.status(401).end()
		}
	} else {
		res.status(401).end()
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
