import { initDashboard } from './dashboard.js';
import { initAdmin } from './admin.js';

// darkmode
const getStoredTheme = () => localStorage.getItem('theme');
const setStoredTheme = theme => localStorage.setItem('theme', theme);

const applyTheme = (theme) => {
    document.documentElement.setAttribute('data-bs-theme', theme);
    const icon = document.getElementById('theme-icon');
    if(icon) icon.innerText = (theme === 'dark' ? '☀️' : '🌙');
};

const initialTheme = getStoredTheme() || 'light';
applyTheme(initialTheme)

document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('bd-theme-toggle');
    if(toggle) {
        toggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-bs-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            applyTheme(newTheme);
            setStoredTheme(newTheme);
        })
    }
});

function main() {
    const path = window.location.pathname;

    if (path === '/' || path === '/index') {
        console.log("Dashboard Initialization");
        initDashboard();
    } 
    else if (path === '/config') {
        console.log("Admin Pannel Initialization");
        initAdmin();
    }
}

main();