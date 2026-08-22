import { db } from "../firebase";

import {
  doc,
  updateDoc,
} from "firebase/firestore";

function random(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export async function updateLiveData() {

  const weeklyGraph = Array.from(
    { length: 7 },
    () => random(40, 90)
  );

  const threatsDetected =
    weeklyGraph.reduce((a, b) => a + b, 0) +
    random(700, 900);

  const protectedAssets =
    random(500, 650);

  const criticalAlerts =
    random(60, 110);

  const blockedThreats =
    threatsDetected - criticalAlerts;

  const accuracy =
    Number((98 + Math.random() * 1.8).toFixed(1));

  const highestThreat =
    Math.max(...weeklyGraph);

  const averageThreat =
    Math.round(
      weeklyGraph.reduce((a, b) => a + b, 0) /
      weeklyGraph.length
    );

  await updateDoc(
    doc(db, "dashboard", "summary"),
    {

      threatsDetected,

      protectedAssets,

      criticalAlerts,

      blockedThreats,

      accuracy,

      weeklyGraph,

      highestThreat,

      averageThreat,

      lastUpdated: new Date().toLocaleTimeString(),

      worldMap: {

        usa: random(300, 380),

        india: random(250, 330),

        germany: random(130, 190),

        uk: random(100, 170),

        japan: random(90, 150),

      },

    }
  );

}