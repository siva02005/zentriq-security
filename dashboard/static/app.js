const BASE = window.location.origin;
let API_KEY = localStorage.getItem('zentriq_api_key') || '';

function saveApiKey() {
    const input = document.getElementById('api-key-input');
    API_KEY = input.value.trim();
    localStorage.setItem('zentriq_api_key', API_KEY);
    document.getElementById('auth-status').textContent = '● Connected';
    document.getElementById('auth-status').style.color = '#00d4aa';
    input.value = '';
    refresh();
}

function headers() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`
    };
}

async function fetchPolicies() {
    try {
        const res = await fetch(`${BASE}/api/v1/policies`, { headers: headers() });
        if (!res.ok) return;
        const data = await res.json();
        const tbody = document.getElementById('policies-body');
        tbody.innerHTML = data.map(p => `
            <tr>
                <td>${esc(p.name)}</td>
                <td><span class="badge badge-${p.effect.toLowerCase()}">${p.effect}</span></td>
                <td>${p.priority}</td>
                <td>${p.action_types ? p.action_types.join(', ') : '—'}</td>
                <td>${esc(p.description)}</td>
            </tr>
        `).join('');
    } catch (e) { console.error('Failed to load policies', e); }
}

async function fetchAudit() {
    try {
        const res = await fetch(`${BASE}/api/v1/audit/events?limit=50`, { headers: headers() });
        if (!res.ok) return;
        const events = await res.json();

        let allow = 0, restrict = 0, block = 0;
        events.forEach(e => {
            if (e.decision === 'ALLOW') allow++;
            else if (e.decision === 'RESTRICT') restrict++;
            else if (e.decision === 'BLOCK') block++;
        });

        document.getElementById('allow-count').textContent = allow;
        document.getElementById('restrict-count').textContent = restrict;
        document.getElementById('block-count').textContent = block;
        document.getElementById('total-count').textContent = events.length;

        const tbody = document.getElementById('audit-body');
        tbody.innerHTML = events.map(e => `
            <tr>
                <td>${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—'}</td>
                <td>${esc(e.session_id || '—')}</td>
                <td>${esc(e.task_id || '—')}</td>
                <td>${esc(e.action_type)}</td>
                <td><span class="badge badge-${e.risk_level}">${e.risk_level} (${e.risk_score})</span></td>
                <td><span class="badge badge-${e.decision.toLowerCase()}">${e.decision}</span></td>
                <td style="font-size:11px;color:#5a7a8a">${esc(e.triggered_rule)}</td>
                <td title="${esc((e.reasons||[]).join('; '))}">${esc((e.reasons||[])[0] || '—')}</td>
            </tr>
        `).join('');
    } catch (e) { console.error('Failed to load audit events', e); }
}

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function refresh() {
    fetchPolicies();
    fetchAudit();
}

// Auto-refresh every 5 seconds
setInterval(refresh, 5000);

// Init
window.addEventListener('DOMContentLoaded', () => {
    if (API_KEY) {
        document.getElementById('auth-status').textContent = '● Connected';
        document.getElementById('auth-status').style.color = '#00d4aa';
        refresh();
    }
});
