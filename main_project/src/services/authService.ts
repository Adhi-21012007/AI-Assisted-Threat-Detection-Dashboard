import { auth, db } from "../firebase";

import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  updateProfile,
} from "firebase/auth";

import {
  doc,
  setDoc,
  serverTimestamp,
} from "firebase/firestore";

// Signup
export async function signup(
  name: string,
  email: string,
  password: string
) {

  const credential = await createUserWithEmailAndPassword(
    auth,
    email,
    password
  );

  await updateProfile(credential.user, {
    displayName: name,
  });

  await setDoc(doc(db, "users", credential.user.uid), {

    uid: credential.user.uid,

    name,

    email,

    createdAt: serverTimestamp(),

  });

  return credential.user;

}

// Login
export async function login(
  email: string,
  password: string
) {

  const credential =
    await signInWithEmailAndPassword(
      auth,
      email,
      password
    );

  return credential.user;

}

// Logout
export async function logout() {

  await signOut(auth);

}