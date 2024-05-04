const { verifyDKIMSignature } = require("@zk-email/helpers/dist/dkim");

const { sha256Pad, shaHash, partialSha, tryVerifyDKIM } = require("@zk-email/helpers/dist");
const { getAmountRegexIndex, getOnramperEmailRegexIndex, getPrecomputeIndex } = require("./utils");

async function Preprocess(req, res){


    // Create the sha hash checkpoints here
    try {
        console.log(req.body) 
        const data = await verifyDKIMSignature(Buffer.from(req.body.contents, "base64"), null, true)
        const paypal_amount_idx = getAmountRegexIndex(data.body.toString())
        const paypal_onramper_id_idx = getOnramperEmailRegexIndex(data.body.toString())
        const precompute_idx = getPrecomputeIndex(paypal_amount_idx, paypal_onramper_id_idx)
        const [body, bodyLen] = await sha256Pad(Uint8Array.from(data.body), Math.ceil(data.body.length / 512) * 512)

        
        const chunkResponses  = []
        let remainingChunkSize = bodyLen - 6144 - precompute_idx
        let index = 6144 + precompute_idx

        while (remainingChunkSize > 0) {
            const size = remainingChunkSize > 4096 ? 
                                4096 : remainingChunkSize > 2048 ?
                                2048 : remainingChunkSize > 1024 ?
                                1024 : 512
            const chunk = new Uint8Array(size).map((_, i, arr) => arr[i] = body[i + index] ?? 0)
            /* 
                Find out the precompute, then the body chunk and then the postcompute
                And then the effective length
            */
           chunkResponses.push({
               pre_hash: Array.from(partialSha(body, index)),
               contents: Buffer.from(chunk).toString("base64"),
               size,
               initial: 0,
               contentLength: remainingChunkSize < size ? remainingChunkSize : size
           })
            
               
            index += size
            remainingChunkSize -= size

        }

        // TODO: implement rapidsnark here
        res.json(chunkResponses)

    } catch (error) {
        console.error(error)
        res.json({"error": error.message })
    }
}

module.exports = Preprocess