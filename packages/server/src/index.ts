import { Hono } from "hono";
import { setSignedCookie, getSignedCookie } from "hono/cookie";
import { serveStatic } from "hono/bun";
import { sign } from "hono/jwt";

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { RegistrationResponseJSON } from "@simplewebauthn/typescript-types";

import { prisma } from "@webauthn-expo/prisma";

const RP_ID = process.env.WEBAUTHN_RP_ID ?? "localhost";
const RP_NAME = process.env.WEBAUTHN_RP_NAME ?? "WebAuthn Test";
const SECRET = process.env.JWT_SECRET ?? "secret passphrase";
const CHALLENGE_TTL = Number(process.env.CHALLENGE_TTL ?? "14000000");
const app = new Hono();

function generateRandomID() {
  const id = crypto.getRandomValues(new Uint8Array(32));

  return btoa(
    Array.from(id)
      .map((c) => String.fromCharCode(c))
      .join(""),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function generateJWT(userId: string) {
  return sign(
    {
      sub: userId,
    },
    SECRET,
  );
}

app.get("/", serveStatic({ path: "./src/index.html" }));

app.post("/register", async (c) => {
  console.log({ method: "POST /register" });

  const { username } = await c.req.json<{ username: string }>();

  const user = await prisma.user.upsert({
    where: { username: username },
    update: {},
    create: { id: generateRandomID(), username: username },
  });

  const userId = user.id;

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: userId,
    userName: username,
    userDisplayName: username,
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
      authenticatorAttachment: "cross-platform",
    },
  });

  const expiresAt = new Date();
  expiresAt.setTime(expiresAt.getTime() + CHALLENGE_TTL);

  //console.log(options.challenge);

  await prisma.session.create({
    data: {
      userId: userId,
      id: options.challenge,
      expiresAt,
    },
  });

  await setSignedCookie(c, "userId", userId, SECRET, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: CHALLENGE_TTL,
  });
  return c.json(options);
});

app.post("/verify", async (c) => {
  const { username, cred } = await c.req.json<{
    username: string;
    cred: RegistrationResponseJSON;
  }>();

  console.log({ method: "POST /verify", username, cred });
  const userId = await getSignedCookie(c, SECRET, "userId");
  if (!userId) return c.text("Unauthorized", 401);

  //const user = await prisma.user.findUnique({
  //  where: {
  //    id: username,
  //  },
  //});

  const clientData = JSON.parse(atob(cred.response.clientDataJSON));

  console.log({ clientData });

  if (!clientData.challenge) {
    return c.text("Invalid challenge", 401);
  }

  const session = await prisma.session.findUnique({
    where: {
      id: clientData.challenge,
    },
  });
  if (!session) return c.text("Invalid challenge", 400);

  const verification = await verifyRegistrationResponse({
    response: cred,
    expectedChallenge: session.id,
    expectedRPID: RP_ID,
    expectedOrigin: c.req.header("origin")!, // !!! Allow from any origin
    requireUserVerification: true,
  });

  if (verification.verified) {
    const { credentialID, credentialPublicKey, counter } =
      verification.registrationInfo!;

    await prisma.session.delete({
      where: {
        id: session.id,
      },
    });

    await prisma.credential.create({
      data: {
        userId,
        name: username,
        externalId: credentialID.toString(),
        publicKey: Buffer.from(credentialPublicKey),
        signCount: counter,
        updatedAt: new Date(),
      },
    });

    await setSignedCookie(c, "token", await generateJWT(username), SECRET, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: CHALLENGE_TTL,
    });
    return c.json(verification);
  }
  return c.text("Unauthorized", 401);
});

export default app;
