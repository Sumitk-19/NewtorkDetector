async function loadStats() {
    const res = await fetch("/api/stats");
    const data = await res.json();

    const ctx = document.getElementById("attackChart");
    new Chart(ctx, {
        type: "bar",
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: "Attack Count",
                data: Object.values(data)
            }]
        }
    });
}

async function loadAlerts() {
    const res = await fetch("/api/alerts");
    const alerts = await res.json();

    const table = document.getElementById("alertTable");
    table.innerHTML = "";

    alerts.slice(-20).reverse().forEach(a => {
        const row = `<tr>
            <td>${a.type}</td>
            <td>${a.src_ip || "-"}</td>
            <td>${a.count || a.ports || "-"}</td>
            <td>${a.time}</td>
        </tr>`;
        table.innerHTML += row;
    });
}

loadStats();
loadAlerts();
setInterval(loadAlerts, 3000);
