const { Buffer } = require("buffer");
const CryptoJS = require("crypto-js");

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
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

function sign(str, secret) {
  const hash = CryptoJS.HmacSHA256(str, secret);
  return base64UrlEncode(CryptoJS.enc.Base64.stringify(hash));
}

module.exports = {
  jessEncode,
};
