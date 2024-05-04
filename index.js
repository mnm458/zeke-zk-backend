const Express = require("express")
const router = require("./routes/routes")
const app = Express()
const PORT = process.env.PORT || 8080
const cors = require("cors")

app.use(cors())
app.use(Express.json({ limit: '1024kb' }))
app.use("/", router)

app.listen(PORT, () => console.log(`listening to port ${PORT}`))