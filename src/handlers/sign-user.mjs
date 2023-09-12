const jose = require("jose");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

var privateKey = fs.readFileSync(path.resolve(__dirname, "../privateKey.pem"));

export const sign = async (req, res, next) => {
  const userName = req.userName;
  const userEmail = req.userEmail;
  const token = jwt.sign(
    {
      sub: "12212wolo", // must be unique to each user
      name: userName,
      email: userEmail,
      aud: "urn:my-resource-server", // -> to be used in Custom Authentication as JWT Field
      iss: "https://my-authz-server", // -> to be used in Custom Authentication as JWT Field
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
    },
    privateKey,
    { algorithm: "RS256", keyid: "676da9d312c39a429932f543e6c1b6512e4983" } // <-- Replace it with your kid. This has to be present in the JWKS endpoint.
  );

  const JWKS = jose.createRemoteJWKSet(
    new URL("https://sysplex.us/web3_auth/keys/Keys.json")
  );

  const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS, {
    issuer: "https://my-authz-server",
    audience: "urn:my-resource-server",
  });

  res.json({
    token,
    payload,
    protectedHeader,
  });
};
