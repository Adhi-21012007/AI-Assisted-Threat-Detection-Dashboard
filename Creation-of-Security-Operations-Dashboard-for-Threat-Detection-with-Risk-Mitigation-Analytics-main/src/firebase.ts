import { initializeApp } from "firebase/app";

import { getFirestore } from "firebase/firestore";

import { getAuth } from "firebase/auth";

const firebaseConfig = {

  apiKey: "AIzaSyCiz8BIxvAIxRoGtql0XRZ4nSHpwL6hJRk",

  authDomain: "ai-threat-dashboard-ea80c.firebaseapp.com",

  projectId: "ai-threat-dashboard-ea80c",

  storageBucket: "ai-threat-dashboard-ea80c.firebasestorage.app",

  messagingSenderId: "908108870429",

  appId: "1:908108870429:web:74cfa8c2cb4b6f551527f4",

};

const app = initializeApp(firebaseConfig);

export const db = getFirestore(app);

export const auth = getAuth(app);