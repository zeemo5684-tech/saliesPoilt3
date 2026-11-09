import firebaseAdmin from "npm:firebase-admin@12";
import type { FirebaseApp, App } from "npm:firebase-admin@12/lib/app/index";

let app: App | null = null;

function getApp(): App {
  if (app) return app;
  const projectId = "salespilot-e581d";
  const clientEmail = Deno.env.get("FIREBASE_CLIENT_EMAIL");
  const privateKeyRaw = Deno.env.get("FIREBASE_PRIVATE_KEY");
  if (!clientEmail || !privateKeyRaw) {
    throw new Error("FIREBASE_CLIENT_EMAIL or FIREBASE_PRIVATE_KEY not set");
  }
  const privateKey = privateKeyRaw.replace(/\\n/g, "\n");
  app = firebaseAdmin.initializeApp({
    credential: firebaseAdmin.credential.cert({ projectId, clientEmail, privateKey }),
    projectId,
  });
  return app;
}

export async function provisionFirebaseAccount(email: string, temporaryPassword: string): Promise<void> {
  const auth = getApp().auth();
  try {
    await auth.createUser({ email, password: temporaryPassword });
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === "auth/email-already-exists") return;
    throw e;
  }
}

export async function updateFirebasePassword(email: string, newPassword: string): Promise<void> {
  const auth = getApp().auth();
  try {
    const user = await auth.getUserByEmail(email);
    await auth.updateUser(user.uid, { password: newPassword });
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === "auth/user-not-found") {
      await auth.createUser({ email, password: newPassword });
      return;
    }
    throw e;
  }
}
