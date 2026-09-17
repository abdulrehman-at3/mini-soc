// Small, dependency-light UI helpers for the Mini-SOC dashboard.
// Chart.js is loaded from a CDN in base.html; everything here degrades
// harmlessly (no charts, but the rest of the page still works) if it's
// unavailable (e.g. no internet access on the machine running this).

document.addEventListener("DOMContentLoaded", () => {
  // Confirm before any destructive-ish action explicitly opted in via
  // data-confirm="Some question?" on a <form> or <button>.
  document.querySelectorAll("[data-confirm]").forEach((el) => {
    el.addEventListener("submit", (e) => {
      if (!window.confirm(el.getAttribute("data-confirm"))) e.preventDefault();
    });
    el.addEventListener("click", (e) => {
      if (el.tagName === "BUTTON" && el.type !== "submit" && !window.confirm(el.getAttribute("data-confirm"))) {
        e.preventDefault();
      }
    });
  });

  initSeverityChart();
  initTimelineChart();
});

const SEVERITY_COLORS = { CRITICAL: "#f0455c", HIGH: "#f0954a", MEDIUM: "#f0c94a", LOW: "#4a9df0" };

function initSeverityChart() {
  const canvas = document.getElementById("chart-severity");
  if (!canvas || typeof Chart === "undefined") return;
  fetch("/api/stats/alerts-by-severity")
    .then((r) => r.json())
    .then((data) => {
      new Chart(canvas, {
        type: "bar",
        data: {
          labels: Object.keys(data),
          datasets: [{ data: Object.values(data), backgroundColor: Object.keys(data).map((k) => SEVERITY_COLORS[k]) }],
        },
        options: {
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false }, ticks: { color: "#8b98b3", font: { family: "IBM Plex Mono", size: 11 } } },
            y: { beginAtZero: true, grid: { color: "#22314b" }, ticks: { color: "#8b98b3", precision: 0 } },
          },
        },
      });
    })
    .catch(() => {});
}

function initTimelineChart() {
  const canvas = document.getElementById("chart-timeline");
  if (!canvas || typeof Chart === "undefined") return;
  fetch("/api/stats/events-timeline")
    .then((r) => r.json())
    .then((rows) => {
      new Chart(canvas, {
        type: "line",
        data: {
          labels: rows.map((r) => r.label),
          datasets: [{
            data: rows.map((r) => r.count), borderColor: "#3ddc97",
            backgroundColor: "rgba(61,220,151,0.12)", fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2,
          }],
        },
        options: {
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false }, ticks: { color: "#8b98b3", maxTicksLimit: 8, font: { family: "IBM Plex Mono", size: 10 } } },
            y: { beginAtZero: true, grid: { color: "#22314b" }, ticks: { color: "#8b98b3", precision: 0 } },
          },
        },
      });
    })
    .catch(() => {});
}
