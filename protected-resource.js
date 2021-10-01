const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const { timeout } = require("./utils")
const jwt = require("jsonwebtoken")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/user-info", (req, res) => {
	if (req.headers.hasOwnProperty("authorization")) {
		const token = req.headers.authorization.slice("bearer ".length, -1)
		jwt.verify(token, config.publicKey, { algorithms: ["RS256"] }, (err, decoded) => {
			if (err) {
				res.status(401).end()
			} else {
				const { userName, scope } = decoded
				const fields = {}
				scope.split(" ").array.forEach(permission => {
					const field = permission.slice("permission:".length, -1)
					fields[field] = users[userName][field]
				});
				res.json(fields)
			}
		})
	} else {
		res.status(401).end()
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
