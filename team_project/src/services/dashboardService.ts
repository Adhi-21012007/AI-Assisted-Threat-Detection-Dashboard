import { db } from "../firebase";

import {
  doc,
  getDoc,
  onSnapshot,
} from "firebase/firestore";

// Read once
export async function getDashboardData() {

  const docRef = doc(db, "dashboard", "summary");

  const docSnap = await getDoc(docRef);

  if (docSnap.exists()) {

    return docSnap.data();

  }

  return null;

}

// Live listener
export function listenDashboardData(
  callback: (data: any) => void
) {

  const docRef = doc(db, "dashboard", "summary");

  return onSnapshot(docRef, (snapshot) => {

    if (snapshot.exists()) {

      callback(snapshot.data());

    }

  });

}