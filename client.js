const express = require("express")
const bodyParser = require("body-parser")
const axios = require("axios").default
const { randomString, timeout } = require("./utils")

const config = {
	port: 9000,

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
	tokenEndpoint: "http://localhost:9001/token",
	userInfoEndpoint: "http://localhost:9002/user-info",
}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/client")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/authorize", (res, req) => {
	state = randomString()
	const redirectUrl = new URL(config.authorizationEndpoint)
	redirectUrl.searchParams.append("response_type", "code")
	redirectUrl.searchParams.append("client_id", config.clientId)
	redirectUrl.searchParams.append("redirect_uri", config.redirectUri)
	redirectUrl.searchParams.append("scope", "permission:name permission:date_of_birth")
	redirectUrl.searchParams.append("state", state)

	req.redirect(redirectUrl)
})

app.get("/callback", (req, res) => {
	if (req.query.state !== state) {
		res.status(403).end()
		return
	}

	axios({
		method: "POST",
		url: config.tokenEndpoint,
		auth: { username: config.clientId, password: config.clientSecret },
		data: { code: req.query.code }
	})
		.then(response => {
			return axios({
				method: "GET",
				url: config.userInfoEndpoint,
				headers: { authorization: `bearer ${response.data.access_token}` }
			})
		})
		.then(response => {
			res.render("welcome", { user: response.data })
		})
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = {
	app,
	server,
	getState() {
		return state
	},
	setState(s) {
		state = s
	},
}
