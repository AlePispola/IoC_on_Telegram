// MongoDB Playground
use("GroupMonitoringRelease");

// 1. DEFINIZIONE DELLE PAROLE CHIAVE
const keywords = [
  "cyber", "hack", "security", "infosec",
  "exploit", "malware", "botnet", "ddos",
  "database", "leak", "breach", "dump", "logs",
  "osint", "intel", "carding", "access", "root",
  "linux", "python", "bug", "bounty"
];

// Costruzione dinamica OR di regex
const regexConditions = keywords.map(kw => ({
  "chat_name": { $regex: kw, $options: "i" }
}));

// 2. AGGREGAZIONE
db.getCollection("groups").aggregate([
  // A: filtro
  {
    $match: {
      $or: regexConditions
    }
  },

  // B: ordinamento per leggibilità
  {
    $sort: { "chat_name": 1 }
  },

  // C: raggruppamento
  {
    $group: {
      _id: null,
      totale_trovati: { $sum: 1 },

      risultati: {
        $push: {
          id: "$_id",
          name: "$chat_name",
          language: "$language"   // ⬅️ aggiunto
        }
      }
    }
  },

  // D: pulizia output
  {
    $project: {
      _id: 0,
      totale_trovati: 1,
      risultati: 1
    }
  }
]);
