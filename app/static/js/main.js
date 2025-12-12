import { initDashboard } from './dashboard.js';
import { initAdmin } from './admin.js';

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