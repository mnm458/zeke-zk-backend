const snarkjs = require("snarkjs")
const { nanoid } = require("./utils")
const fs = require("fs")
const shellExec = require("shell-exec")

async function MDVProve(req, res){
    try {
        
        const body = Buffer.from(req.body.contents, "base64")
        const size = req.body.size ?? 1024
    
        // res.json(await snarkjs.groth16.fullProve({
        //     in: Array.from(new Uint8Array(size).map((_item, index, arr) => arr[index] = body[index + req.body.initial] ?? 0)),
        //     length: req.body.contentLength,
        //     pre_hash: req.body.pre_hash
        // }, `./public/mdv/${size}.wasm`, `./public/mdv/${size}.zkey`))

        const id = nanoid()
        fs.writeFileSync(`./tmp/${id}_input.json`, JSON.stringify({
            in: Array.from(new Uint8Array(size).map((_item, index, arr) => arr[index] = body[index + req.body.initial] ?? 0)),
            length: req.body.contentLength,
            pre_hash: req.body.pre_hash
        }))
        await shellExec.default(`./bin/${size} ./tmp/${id}_input.json ./tmp/${id}.wtns`)
        // res.json(await snarkjs.groth16.fullProve(input, "./public/offramper/prover.wasm", "./public/offramper/circuit.zkey"))
        await shellExec.default(`./bin/prover ./public/mdv/${size}.zkey ./tmp/${id}.wtns ./tmp/${id}_proof.json ./tmp/${id}_public.json`)

        res.json({proof: JSON.parse(fs.readFileSync(`./tmp/${id}_proof.json`)), public: JSON.parse(fs.readFileSync(`./tmp/${id}_public.json`)), verifier: size/512 })
        shellExec.default(`rm ./tmp/${id}_proof.json ./tmp/${id}_public.json ./tmp/${id}.wtns ./tmp/${id}_input.json`)

    } catch (error) {
        console.error(error)
        res.json({"message": error.message})
    }
    
}

module.exports = MDVProve