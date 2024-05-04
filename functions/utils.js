const crypto = require("crypto")
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

const MAX_HEADER_PADDED_BYTES_FOR_EMAIL_TYPE = 512 // or 768
const MAX_BODY_PADDED_BYTES_FOR_EMAIL_TYPE = 6272

function getAmountRegexIndex(body){
    const starterIndex = body.search(/C(=\r\n)?o(=\r\n)?n(=\r\n)?v(=\r\n)?e(=\r\n)?r(=\r\n)?t(=\r\n)?e(=\r\n)?d(=\r\n)? (=\r\n)?T(=\r\n)?o/g)
    const processedPhrase = body.substring(starterIndex)

    const amountIndex = processedPhrase.indexOf("$")

    return starterIndex + amountIndex
}

function getOnramperEmailRegexIndex(body){
    // to be used 
    const endIndex = body.lastIndexOf("@")
    const processedPhrase = body.substring(endIndex - 340)
    const emailIndex = processedPhrase.indexOf("<span>")

    return endIndex + emailIndex - 340
}

function getEmailRegexIndex(header){
    // the header values including the DKIM signature
    const lowercaseIndex = header.indexOf("from:")
    const sentenceCaseindex = header.indexOf("From:")

    const actualIndex = lowercaseIndex < 0 ? sentenceCaseindex : lowercaseIndex;
    return actualIndex
}

function getOfframperRegexIndex(header){
    // the header values including the DKIM signature
    const lowercaseIndex = header.indexOf("to:")
    const sentenceCaseindex = header.indexOf("To:")

    
    const actualIndex = lowercaseIndex < 0 ? sentenceCaseindex : lowercaseIndex;
    return actualIndex + header.substring(actualIndex).indexOf("<")
}

function getPrecomputeIndex(...indices){
    const minIndex = Math.min(...indices)
    return Math.floor(minIndex / 64) * 64
}


function getTimestampIndex(header){
    
    const starterIndex = header.indexOf("dkim-signature")
    const index =  header.substring(starterIndex).indexOf("i=@")

    return starterIndex + index

}

async function verifySignature(publicKey, signature, data) {
    // Convert the public key and signature from base 10 BigInt to Buffer
    const publicKeyBuffer = Buffer.from(publicKey.toString(16), 'hex');
    const signatureBuffer = Buffer.from(signature.toString(16), 'hex');

    // Create a verifier object
    console.log(publicKeyBuffer.length)
    const ver = crypto.createVerify("SHA256")
    ver.update(data)
    const verify = ver.verify(publicKeyBuffer, signatureBuffer)
    // const key = await crypto.subtle.importKey("spki", publicKeyBuffer, {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, true, ["verify"])
    console.log(key)
    return verify;
    // await crypto.subtle.verify({name: "RSASSA-PKCS1-v1_5"}, key, signatureBuffer, data);
}

function _getTimestampIndex(header){
    // This function will bug out on Safari
    // for all versions of iOS below 16.3
    // https://caniuse.com/js-regexp-lookbehind 
    
    return header.search(/(?<=t=)[0-9]*(?=;)/g)
}

let a="useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

let nanoid = ( e = 21 ) => {
    let t = "";
    let r = crypto.getRandomValues(new Uint8Array(e));
    for(let n = 0; n < e; n++ )
        t+=a[63&r[n]];
    
    return t

}

module.exports = {
    getAmountRegexIndex,
    getEmailRegexIndex,
    getOnramperEmailRegexIndex,
    getOfframperRegexIndex,
    getPrecomputeIndex,
    getTimestampIndex,
    verifySignature,
    nanoid,
    MAX_BODY_PADDED_BYTES_FOR_EMAIL_TYPE,
    MAX_HEADER_PADDED_BYTES_FOR_EMAIL_TYPE
}