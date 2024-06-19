const { Buffer } = require("buffer");
const CryptoJS = require("crypto-js");

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = 4 - (str.length % 4);
    if (padding !== 4) {
      str += '='.repeat(padding);
    }
    return Buffer.from(str, 'base64').toString();
}
  
function base64UrlEncodeJSON(obj) {
  return base64UrlEncode(JSON.stringify(obj));
}

function jessEncode(payload, secret) {
  const header = {
    alg: "HS256",
    typ: "JWT",
  };
  const encodedHeader = base64UrlEncodeJSON(header);
  const encodedPayload = base64UrlEncodeJSON(payload);

  const token = `${encodedHeader}.${encodedPayload}`;
  const signature = sign(token, secret);

  return `${token}.${signature}`;
}

function jessDecode(token, secret) {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    const header = JSON.parse(base64UrlDecode(encodedHeader));
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    
    const validSignature = sign(`${encodedHeader}.${encodedPayload}`, secret);
    if (validSignature !== signature) {
      throw new Error('Invalid signature');
    }
  
    return { header, payload };
  }

function sign(str, secret) {
  const hash = CryptoJS.HmacSHA256(str, secret);
  return base64UrlEncode(CryptoJS.enc.Base64.stringify(hash));
}

module.exports = {
  jessEncode,
  jessDecode,
};
