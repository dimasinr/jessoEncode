const Buffer = require('buffer').Buffer;
const crypto = require('crypto-js');

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

const secret = "&N_rvL&3qp%8h?dd_K/-1x/$Ei:LW{K{RfRQ2RZDtjfQGHe*Ve*cEkWF9[%-}21?g:NcN&34R!3[ZM7!hg;F&/C:nE&mx73(}vnR"

function sign(str) {
  return Buffer.from(
    crypto.HmacSHA256(str, secret).toString(crypto.enc.Base64)
  ).toString();
}

function verify(str, signature) {
  const expectedSignature = sign(str, secret);
  return signature === expectedSignature;
}

function jessEncode(payload) {
  const header = {
    alg: "HS256",
    typ: "JWT"
  };

  const encodedHeader = base64UrlEncodeJSON(header);
  const encodedPayload = base64UrlEncodeJSON(payload);

  const token = `${encodedHeader}.${encodedPayload}`;
  const signature = sign(token, secret);

  return `${token}.${signature}`;
}

function jessDecode(token) {
  const [encodedHeader, encodedPayload, signature] = token.split(".");
  const data = JSON.parse(base64UrlDecode(encodedPayload));

  const validSignature = verify(
    `${encodedHeader}.${encodedPayload}`,
    signature,
    secret
  );
  if (!validSignature) {
    throw new Error("Invalid signature");
  }

  return { data };
}

module.exports = { jessEncode, jessDecode };
