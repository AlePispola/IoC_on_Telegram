// MongoDB Playground
use("GroupMonitoringRelease");

// Restituisce un array di stringhe univoche (chat_name)
// SOLO per i documenti dove il campo "language" è "English"
db.getCollection("groups").distinct("chat_name", { "language": "English" });