const Express = require("express")
const router = Express.Router()

const OfframperProve = require("../functions/offramper")
const MDVProve = require("../functions/mdv")
const Pong = require("../functions/pong")
const Preprocess = require("../functions/preprocess")


router.post("/generate/offramper", OfframperProve)
router.post("/generate/mdv", MDVProve)
router.post("/generate/preprocess", Preprocess)


router.get("/ping", Pong)

module.exports = router