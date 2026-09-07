const file = document.getElementById("file");

function dump(obj) {
  return JSON.stringify(obj, null, 2);
}

file.addEventListener("change", async () => {
  const f = file.files[0];
  if (!f) return;

  const text = await f.text();
  const report = JSON.parse(text);
  const summary = report.summary || {};

  document.getElementById("score").textContent = summary.score ?? "--";
  document.getElementById("summary").textContent = dump(summary);
  document.getElementById("findings").textContent = dump((report.findings || []).slice(0, 30));
  document.getElementById("web").textContent = dump((report.web || []).slice(0, 20));
  document.getElementById("secrets").textContent = dump((report.secrets || []).slice(0, 20));
  document.getElementById("passwords").textContent = dump((report.passwords || []).slice(0, 20));
  document.getElementById("hashes").textContent = dump((report.hashes || []).slice(0, 20));
});
