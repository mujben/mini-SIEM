/**
 * Wrapper na Fetch API do komunikacji z backendem Flask
 */

// helper function for fetching headers - protects from csrf
function getHeaders() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if(!metaTag) {
        console.error("Błąd: brak tagu meta 'csrf-token' w nagłówku strony");
        return {'Content-Type': 'application/json'};
    }
    const csrfToken = metaTag.getAttribute('content');
    return {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken
    };
}

// --- HOSTS (GOTOWE - WZÓR) ---
export async function fetchHosts() {
    const res = await fetch('/api/hosts');
    return await res.json();
}
export async function createHost(data) {
    const res = await fetch('/api/hosts', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if(!res.ok) throw new Error((await res.json()).error);
    return await res.json();
}
export async function updateHost(id, data) {
    const res = await fetch(`/api/hosts/${id}`, {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if(!res.ok) throw new Error('Błąd edycji hosta');
    return await res.json();
}
export async function removeHost(id) {
    await fetch(`/api/hosts/${id}`, {
        method: 'DELETE',
        headers: getHeaders()
    });
}

// --- MONITORING / LOGI (GOTOWE) ---
export async function checkHostStatus(id, osType) {
    const endpoint = (osType === 'LINUX') 
        ? `/api/hosts/${id}/ssh-info` 
        : `/api/hosts/${id}/windows-info`;
        
    const res = await fetch(endpoint);
    if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || `Błąd HTTP ${res.status}`);
    }
    return await res.json();
}

export async function triggerLogFetch(hostId) {
    const res = await fetch(`/api/hosts/${hostId}/logs`, {
        method: 'POST',
        headers: getHeaders()
    });
    if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Błąd pobierania logów');
    }
    return await res.json();
}

// ===============================================================
// TODO: ZADANIE 4 - KOMUNIKACJA FRONTEND-BACKEND
// ===============================================================
// Brakuje funkcji do obsługi Rejestru IP oraz Alertów.
// Panel Admina i Dashboard będą rzucać błędy, dopóki tego nie uzupełnisz.
// Wzoruj się na funkcjach z sekcji HOSTS powyżej.

export async function fetchIPs() {
    const res = await fetch('/api/ips');
    if(!res.ok) throw new Error('Błąd pobierania IP');
    return await res.json();
}

export async function createIP(data) {
    const res = await fetch('/api/ips', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if(!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Błąd dodawania IP');
    }
    return await res.json();
}

export async function updateIP(id, data) {
    const res = await fetch(`/api/ips/${id}`, {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if(!res.ok) throw new Error('Błąd edycji IP');
    return await res.json();
}

export async function removeIP(id) {
    const res = await fetch(`/api/ips/${id}`, {
        method: 'DELETE',
        headers: getHeaders()
    });
    if(!res.ok) throw new Error('Błąd usuwania IP');
}

export async function fetchAlerts() {
    const res = await fetch('/api/alerts');
    if(!res.ok) throw new Error('Błąd pobierania alertów');
    return await res.json();
}
