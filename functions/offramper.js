const { verifyDKIMSignature } = require("@zk-email/helpers/dist/dkim");
const {
  bytesToBigInt,
  stringToBytes,
  fromHex,
  toCircomBigIntBytes,
  packBytesIntoNBytes,
  bufferToUint8Array,
  bufferToString,
  bufferToHex,
  Uint8ArrayToString,
  Uint8ArrayToCharArray,
  assert,
  mergeUInt8Arrays,
  int8toBytes,
  int64toBytes,
} = require("@zk-email/helpers/dist/binary-format");
const { nanoid, getPrecomputeIndex, getOnramperEmailRegexIndex, getTimestampIndex, getAmountRegexIndex, getEmailRegexIndex, getOfframperRegexIndex } = require("./utils");
const { sha256Pad, shaHash, partialSha, tryVerifyDKIM } = require("@zk-email/helpers/dist");
const snarkjs = require("snarkjs");
const { wtns } = require("snarkjs");
const shellExec = require("shell-exec")
const fs = require("fs")

// const { shaHash, partialSha, sha256Pad } = require ("@zk-email/helpers/dist/shaHash");

async function OfframperProve(req, res){
    // Generate proof using zk-email

    /* 
        Inputs:
        1. in_padded[768] (header total bytes) (done)
        2. modulus[17] (public key, each element max 2^121)
        3. signature[17] (signature, each element max 2^121)
        4. in_len_padded_bytes (header byte length)

        5. body_hash_idx (prolly the index of hash precompute)
        6. precompute_sha[32]
        7. in_body_padded[7168] (body after the body hash idx)
        8. in_body_len_padded_bytes

        9. email_from_idx (position of FROM email starting in header)
       10. paypal_amount_idx (position of the exact amount starting)
       11. email_timestamp_idx (position of the email timestamp in header)
       12. paypal_offramper_id_idx (in the header)
       13. paypal_onramper_idx (in the body)

       14. pathElementsOfframper[7] (elements)
       15. pathIndicesOfframper[7] (indices, find out a way to figure out left or right)

       16. pathElementsOnramper[7] (elements)
       17. pathIndicesOnramper[7] (indices, find out a way to figure out left or right) 

       18. intent_hash (any random number)

    */
    try {
        
        const data = await verifyDKIMSignature(Buffer.from(req.body.email, "base64"), null, true)

        const paypal_amount_idx = getAmountRegexIndex(data.body.toString())
        const paypal_onramper_id_idx = getOnramperEmailRegexIndex(data.body.toString())
        const precompute_idx = getPrecomputeIndex(paypal_amount_idx, paypal_onramper_id_idx)

        const hash_idx = data.headers.indexOf(data.bodyHash)
        const [header, headerLen] = await sha256Pad(Uint8Array.from(data.headers), 768)

        const [body, bodyLen] = await sha256Pad(Uint8Array.from(data.body), Math.ceil(data.body.length / 512) * 512)
        
        const precomputed_sha = await partialSha(body, precompute_idx)

        const input = {
            in_padded: Array.from(header),
            modulus: toCircomBigIntBytes(data.publicKey),
            signature: toCircomBigIntBytes(data.signature),
            in_len_padded_bytes: headerLen,
            body_hash_idx: hash_idx,
            precomputed_sha: Array.from(precomputed_sha),
            in_body_padded: Array.from(new Uint8Array(6144).map((_item, index, arr) => arr[index] = body[index + precompute_idx] ?? 0)),
            in_body_len_padded_bytes: 6144,
            email_from_idx: getEmailRegexIndex(data.headers.toString()),
            paypal_amount_idx: paypal_amount_idx - precompute_idx - 1,
            email_timestamp_idx: getTimestampIndex(data.headers.toString()),
            paypal_offramper_id_idx: getOfframperRegexIndex(data.headers.toString()),
            paypal_onramper_id_idx: paypal_onramper_id_idx - precompute_idx,
            pathElementsOfframper: [0, 0, 0, 0, 0, 0, 0, 0, 0],
            pathIndicesOfframper: [0, 0, 0, 0, 0, 0, 0, 0, 0],
            pathElementsOnramper: [0, 0, 0, 0, 0, 0, 0, 0, 0],
            pathIndicesOnramper: [0, 0, 0, 0, 0, 0, 0, 0, 0],
            intent_hash: 12345
        }

        const id = nanoid()

        // TODO: implement rapidsnark here
        fs.writeFileSync(`./tmp/${id}_input.json`, JSON.stringify(input))

        await shellExec.default(`./bin/offramper ./tmp/${id}_input.json ./tmp/${id}.wtns`)
        // res.json(await snarkjs.groth16.fullProve(input, "./public/offramper/prover.wasm", "./public/offramper/circuit.zkey"))
        await shellExec.default(`./bin/prover ./public/offramper/circuit.zkey ./tmp/${id}.wtns ./tmp/${id}_proof.json ./tmp/${id}_public.json`)

        res.json({proof: JSON.parse(fs.readFileSync(`./tmp/${id}_proof.json`)), public: JSON.parse(fs.readFileSync(`./tmp/${id}_public.json`))})
        shellExec.default(`rm ./tmp/${id}_proof.json ./tmp/${id}_input.json ./tmp/${id}_public.json ./tmp/${id}.wtns`)

    } catch (error) {
        console.error(error)
        res.json({"error": error.message })
    }
}

module.exports = OfframperProve