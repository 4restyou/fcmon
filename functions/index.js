const crypto = require("node:crypto");
const admin = require("firebase-admin");
const { onRequest } = require("firebase-functions/v2/https");

admin.initializeApp();

const db = admin.firestore();
const HTTP_OPTIONS = { region: "us-central1", invoker: "public" };
const ALLOWED_ORIGINS = new Set([
  "https://fcmon-96ec1.web.app",
  "https://fcmon-96ec1.firebaseapp.com",
  "http://127.0.0.1:8765",
  "http://localhost:8765",
  "null",
]);

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function isFourDigitPw(pw) {
  return typeof pw === "string" && /^[0-9]{4}$/.test(pw);
}

function setCors(req, res) {
  const origin = req.get("origin");
  const isNetlifyOrigin = typeof origin === "string" && /^https:\/\/[a-z0-9-]+\.netlify\.app$/.test(origin);
  const isLocalDevOrigin = typeof origin === "string" && /^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin);
  if (ALLOWED_ORIGINS.has(origin) || isNetlifyOrigin || isLocalDevOrigin) {
    res.set("Access-Control-Allow-Origin", origin);
  }
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  res.set("Vary", "Origin");
}

function readJson(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") return JSON.parse(req.body || "{}");
  return {};
}

function sendJson(res, status, payload) {
  res.status(status).json(payload);
}

function publicUserData(userId, data) {
  const out = { id: userId, ...data };
  delete out.password;
  delete out.passwordHash;
  return out;
}

async function handleRequest(req, res, handler) {
  setCors(req, res);
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "POST") {
    sendJson(res, 405, { ok: false, error: "method-not-allowed" });
    return;
  }
  try {
    await handler(readJson(req), res);
  } catch (err) {
    console.error(err);
    sendJson(res, 500, { ok: false, error: "internal" });
  }
}

async function verifyUserByDoc(userDoc, pw) {
  const userId = userDoc.id;
  const userData = userDoc.data() || {};
  const secretRef = db.collection("userSecrets").doc(userId);
  const secretDoc = await secretRef.get();
  const secretHash = secretDoc.exists ? secretDoc.data().passwordHash : null;

  if (secretHash) {
    return secretHash === sha256("user:" + pw)
      ? { ok: true, userId, userData, migrated: false }
      : { ok: false };
  }

  const legacyHash = userData.passwordHash;
  const legacyPlain = userData.password;
  const matched = legacyHash ? legacyHash === sha256("user:" + pw) : legacyPlain === pw;
  if (!matched) return { ok: false };

  await secretRef.set({
    passwordHash: sha256("user:" + pw),
    migratedAt: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });
  await userDoc.ref.update({
    password: admin.firestore.FieldValue.delete(),
    passwordHash: admin.firestore.FieldValue.delete(),
  });
  delete userData.password;
  delete userData.passwordHash;

  return { ok: true, userId, userData, migrated: true };
}

exports.verifyUserPassword = onRequest(HTTP_OPTIONS, (req, res) => {
  return handleRequest(req, res, async (body, response) => {
    const pw = String(body.pw || "").trim();
    const userId = String(body.userId || "").trim();
    const name = String(body.name || "").trim();
    if (!isFourDigitPw(pw) || (!userId && !name)) {
      sendJson(response, 400, { ok: false, error: "invalid-argument" });
      return;
    }

    let userDocs = [];
    if (userId) {
      const doc = await db.collection("users").doc(userId).get();
      if (doc.exists) userDocs.push(doc);
    } else {
      const snap = await db.collection("users").where("name", "==", name).limit(5).get();
      userDocs = snap.docs;
    }

    for (const doc of userDocs) {
      const result = await verifyUserByDoc(doc, pw);
      if (result.ok) {
        sendJson(response, 200, {
          ok: true,
          userId: result.userId,
          user: publicUserData(result.userId, result.userData),
          migrated: result.migrated,
        });
        return;
      }
    }
    sendJson(response, 200, { ok: false });
  });
});

exports.updateUserPassword = onRequest(HTTP_OPTIONS, (req, res) => {
  return handleRequest(req, res, async (body, response) => {
    const userId = String(body.userId || "").trim();
    const currentPw = String(body.currentPw || "").trim();
    const newPw = String(body.newPw || "").trim();

    if (!userId || !isFourDigitPw(currentPw) || !isFourDigitPw(newPw)) {
      sendJson(response, 400, { ok: false, error: "invalid-argument" });
      return;
    }

    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists) {
      sendJson(response, 404, { ok: false, error: "user-not-found" });
      return;
    }

    const verified = await verifyUserByDoc(userDoc, currentPw);
    if (!verified.ok) {
      sendJson(response, 403, { ok: false, error: "forbidden" });
      return;
    }

    await db.collection("userSecrets").doc(userId).set({
      passwordHash: sha256("user:" + newPw),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
    await userDoc.ref.update({
      password: admin.firestore.FieldValue.delete(),
      passwordHash: admin.firestore.FieldValue.delete(),
    });

    sendJson(response, 200, { ok: true });
  });
});

exports.verifyMatchAdminPassword = onRequest(HTTP_OPTIONS, (req, res) => {
  return handleRequest(req, res, async (body, response) => {
    const pw = String(body.pw || "").trim();
    const gameId = String(body.gameId || "").trim();
    if (!gameId || !isFourDigitPw(pw)) {
      sendJson(response, 400, { ok: false, error: "invalid-argument" });
      return;
    }

    const matchRef = db.collection("matches").doc(gameId);
    const matchDoc = await matchRef.get();
    if (!matchDoc.exists) {
      sendJson(response, 200, { ok: false });
      return;
    }

    const matchData = matchDoc.data() || {};
    const secretRef = db.collection("matchSecrets").doc(gameId);
    const secretDoc = await secretRef.get();
    const secretHash = secretDoc.exists ? secretDoc.data().adminPwHash : null;

    if (secretHash) {
      sendJson(response, 200, { ok: secretHash === sha256("match:" + pw), migrated: false });
      return;
    }

    const legacyHash = matchData.adminPwHash;
    const legacyPlain = matchData.adminPw;
    const matched = legacyHash ? legacyHash === sha256("match:" + pw) : legacyPlain === pw;
    if (!matched) {
      sendJson(response, 200, { ok: false });
      return;
    }

    await secretRef.set({
      adminPwHash: sha256("match:" + pw),
      migratedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
    await matchRef.update({
      adminPw: admin.firestore.FieldValue.delete(),
      adminPwHash: admin.firestore.FieldValue.delete(),
    });

    sendJson(response, 200, { ok: true, migrated: true });
  });
});

exports.updateMatchAdminPassword = onRequest(HTTP_OPTIONS, (req, res) => {
  return handleRequest(req, res, async (body, response) => {
    const gameId = String(body.gameId || "").trim();
    const currentPw = String(body.currentPw || "").trim();
    const newPw = String(body.newPw || "").trim();

    if (!gameId || !isFourDigitPw(currentPw) || !isFourDigitPw(newPw)) {
      sendJson(response, 400, { ok: false, error: "invalid-argument" });
      return;
    }

    const matchRef = db.collection("matches").doc(gameId);
    const matchDoc = await matchRef.get();
    if (!matchDoc.exists) {
      sendJson(response, 404, { ok: false, error: "match-not-found" });
      return;
    }

    const matchData = matchDoc.data() || {};
    const secretRef = db.collection("matchSecrets").doc(gameId);
    const secretDoc = await secretRef.get();
    const secretHash = secretDoc.exists ? secretDoc.data().adminPwHash : null;
    const currentHash = sha256("match:" + currentPw);
    const legacyHash = matchData.adminPwHash;
    const legacyPlain = matchData.adminPw;
    const authorized = secretHash
      ? secretHash === currentHash
      : (legacyHash ? legacyHash === currentHash : legacyPlain === currentPw);

    if (!authorized) {
      sendJson(response, 403, { ok: false, error: "forbidden" });
      return;
    }

    await secretRef.set({
      adminPwHash: sha256("match:" + newPw),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
    await matchRef.update({
      adminPw: admin.firestore.FieldValue.delete(),
      adminPwHash: admin.firestore.FieldValue.delete(),
    });

    sendJson(response, 200, { ok: true });
  });
});
