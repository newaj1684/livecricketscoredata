const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'keys.json');

let db = {
    adminPassword: "admin89",
    clients: []
};

// Load database from file
function loadDatabase() {
    try {
        if (fs.existsSync(DB_PATH)) {
            const data = fs.readFileSync(DB_PATH, 'utf8');
            db = JSON.parse(data);
            if (!db.settings) {
                db.settings = {
                    upiId: "yagnikrathod089@oksbi",
                    payeeName: "Yagnik Rathod",
                    contactEmail: "yagnikrathod089@gmail.com"
                };
            }
            if (!db.orders) db.orders = [];
            if (!db.logs) db.logs = [];
        } else {
            saveDatabase();
        }
    } catch (e) {
        console.error("Database load error:", e.message);
    }
}

// Atomic & resilient database save
const TMP_PATH = path.join(__dirname, 'keys.json.tmp');
let saveTimeout = null;

function saveDatabase() {
    try {
        const jsonStr = JSON.stringify(db, null, 2);
        fs.writeFileSync(TMP_PATH, jsonStr, 'utf8');
        try {
            fs.renameSync(TMP_PATH, DB_PATH);
        } catch (renameErr) {
            // If rename fails (e.g. permission/filesystem lock), write directly
            fs.writeFileSync(DB_PATH, jsonStr, 'utf8');
        }
    } catch (e) {
        console.error("Database save error:", e.message);
    }
}

function queueSave() {
    if (saveTimeout) clearTimeout(saveTimeout);
    saveTimeout = setTimeout(saveDatabase, 500);
}

function addActivityLog(action, details) {
    if (!db.logs) db.logs = [];
    db.logs.unshift({
        id: "log_" + Date.now(),
        action,
        details,
        timestamp: new Date().toISOString()
    });
    if (db.logs.length > 60) db.logs = db.logs.slice(0, 60);
    queueSave();
}

function getActivityLogs() {
    return db.logs || [];
}

loadDatabase();

// Validate API Key and increment request count
function validateAndTrack(apiKey) {
    if (!apiKey) return { ok: false, code: 401, error: "Missing API Key. Pass ?api_key=... or x-api-key header." };

    const client = db.clients.find(c => c.apiKey === apiKey);
    if (!client) {
        return { 
            ok: false, 
            code: 401, 
            error: "Invalid API Key. Contact yagnikrathod089@gmail.com to purchase official API access." 
        };
    }

    if (client.status === 'suspended') {
        return { 
            ok: false, 
            code: 403, 
            error: "API Key Suspended. Contact yagnikrathod089@gmail.com for reactivation.",
            client_name: client.name 
        };
    }

    const now = new Date();
    if (new Date(client.expiresAt) < now) {
        return { 
            ok: false, 
            code: 403, 
            error: "Subscription Expired. Contact yagnikrathod089@gmail.com to renew your plan.",
            client_name: client.name,
            expired_at: client.expiresAt 
        };
    }

    if (client.limit > 0 && client.used >= client.limit) {
        return { 
            ok: false, 
            code: 429, 
            error: "Monthly API Quota Limit Exhausted.",
            message: `You have reached your quota limit of ${client.limit.toLocaleString()} requests. Contact yagnikrathod089@gmail.com to upgrade.`,
            client_name: client.name,
            plan: client.plan,
            used_requests: client.used,
            limit: client.limit
        };
    }

    // Increment usage
    client.used += 1;
    queueSave();

    return {
        ok: true,
        client: {
            name: client.name,
            plan: client.plan,
            used: client.used,
            limit: client.limit,
            remaining: client.limit > 0 ? (client.limit - client.used) : "Unlimited"
        }
    };
}

// Client self quota check
function getClientQuota(apiKey) {
    const client = db.clients.find(c => c.apiKey === apiKey);
    if (!client) return null;

    const isExpired = new Date(client.expiresAt) < new Date();
    const isExceeded = client.limit > 0 && client.used >= client.limit;

    let computedStatus = client.status;
    if (isExpired) computedStatus = "expired";
    else if (isExceeded) computedStatus = "quota_exceeded";

    return {
        client_name: client.name,
        email: client.email,
        plan: client.plan,
        total_limit: client.limit,
        used_requests: client.used,
        remaining_requests: client.limit > 0 ? Math.max(0, client.limit - client.used) : "Unlimited",
        percentage_used: client.limit > 0 ? ((client.used / client.limit) * 100).toFixed(2) + "%" : "0%",
        status: computedStatus,
        expires_at: client.expiresAt,
        support: "yagnikrathod089@gmail.com"
    };
}

// Get all clients with live computed status for Admin
function getAllClients() {
    const now = new Date();
    return db.clients.map(c => {
        const isExpired = new Date(c.expiresAt) < now;
        const isExceeded = c.limit > 0 && c.used >= c.limit;
        
        let displayStatus = c.status;
        if (c.status === 'active') {
            if (isExpired) displayStatus = 'expired';
            else if (isExceeded) displayStatus = 'quota_exceeded';
        }

        return {
            ...c,
            displayStatus,
            remaining: c.limit > 0 ? Math.max(0, c.limit - c.used) : 9999999,
            percentUsed: c.limit > 0 ? Math.min(100, Math.round((c.used / c.limit) * 100)) : 0
        };
    });
}

// Create new client API key
function createClientKey(name, email, plan, limit, expiryDays) {
    const id = "client_" + Date.now();
    const randomHex = crypto.randomBytes(16).toString('hex');
    const apiKey = `cric_live_${randomHex}`;
    
    const now = new Date();
    const expDate = new Date();
    expDate.setDate(now.getDate() + (parseInt(expiryDays) || 30));

    const newClient = {
        id,
        name: name || "Commercial App Client",
        email: email || "client@example.com",
        apiKey,
        plan: plan || "Pro App Plan",
        limit: parseInt(limit) || 10000,
        used: 0,
        status: "active",
        createdAt: now.toISOString(),
        expiresAt: expDate.toISOString()
    };

    db.clients.unshift(newClient);
    saveDatabase();
    addActivityLog("KEY_CREATED", `API Key created for ${newClient.name} (${newClient.plan})`);
    return newClient;
}

// Admin action: Reset usage counter to 0 (New billing cycle)
function resetUsage(id) {
    const client = db.clients.find(c => c.id === id);
    if (!client) return false;
    client.used = 0;
    saveDatabase();
    addActivityLog("USAGE_RESET", `Usage counter reset for ${client.name}`);
    return true;
}

// Admin action: Add quota to client
function addQuota(id, additionalLimit) {
    const client = db.clients.find(c => c.id === id);
    if (!client) return false;
    const added = parseInt(additionalLimit) || 10000;
    client.limit += added;
    saveDatabase();
    addActivityLog("QUOTA_ADDED", `+${added.toLocaleString()} requests added to ${client.name}`);
    return true;
}

// Admin action: Toggle status
function toggleStatus(id) {
    const client = db.clients.find(c => c.id === id);
    if (!client) return null;
    client.status = (client.status === 'active') ? 'suspended' : 'active';
    saveDatabase();
    addActivityLog("STATUS_CHANGED", `Status changed to ${client.status} for ${client.name}`);
    return client.status;
}

// Admin action: Extend expiry
function extendExpiry(id, days) {
    const client = db.clients.find(c => c.id === id);
    if (!client) return null;
    const currentExp = new Date(client.expiresAt);
    const baseDate = currentExp > new Date() ? currentExp : new Date();
    baseDate.setDate(baseDate.getDate() + (parseInt(days) || 30));
    client.expiresAt = baseDate.toISOString();
    saveDatabase();
    addActivityLog("EXPIRY_EXTENDED", `Expiry extended by ${days} days for ${client.name}`);
    return client.expiresAt;
}

// Admin action: Update client details
function updateClient(id, updates = {}) {
    const client = db.clients.find(c => c.id === id);
    if (!client) return null;
    if (updates.name) client.name = updates.name.trim();
    if (updates.email) client.email = updates.email.trim();
    if (updates.plan) client.plan = updates.plan.trim();
    if (updates.limit !== undefined && !isNaN(parseInt(updates.limit))) {
        client.limit = parseInt(updates.limit);
    }
    saveDatabase();
    addActivityLog("CLIENT_UPDATED", `Updated details for ${client.name}`);
    return client;
}

// Admin action: Delete client
function deleteClient(id) {
    const initialLen = db.clients.length;
    const target = db.clients.find(c => c.id === id);
    db.clients = db.clients.filter(c => c.id !== id);
    if (db.clients.length !== initialLen) {
        saveDatabase();
        addActivityLog("CLIENT_DELETED", `Deleted client: ${target ? target.name : id}`);
        return true;
    }
    return false;
}

// Verify Admin password
function verifyAdminPassword(password) {
    return password === (db.adminPassword || "@Yagnik089");
}

// Get public payment settings
function getSettings() {
    return {
        upiId: (db.settings && db.settings.upiId) || "yagnikrathod089@oksbi",
        payeeName: (db.settings && db.settings.payeeName) || "Yagnik Rathod",
        contactEmail: (db.settings && db.settings.contactEmail) || "yagnikrathod089@gmail.com"
    };
}

// Update payment settings (Admin only)
function updateSettings(newSettings) {
    if (!db.settings) db.settings = {};
    if (newSettings.upiId) db.settings.upiId = newSettings.upiId.trim();
    if (newSettings.payeeName) db.settings.payeeName = newSettings.payeeName.trim();
    if (newSettings.contactEmail) db.settings.contactEmail = newSettings.contactEmail.trim();
    saveDatabase();
    addActivityLog("SETTINGS_UPDATED", "Payment UPI and contact email settings updated");
    return getSettings();
}

// Change admin password (Admin only)
function changeAdminPassword(oldPassword, newPassword) {
    if (!verifyAdminPassword(oldPassword)) {
        return { ok: false, error: "Current password does not match." };
    }
    if (!newPassword || newPassword.trim().length < 6) {
        return { ok: false, error: "New password must be at least 6 characters long." };
    }
    db.adminPassword = newPassword.trim();
    saveDatabase();
    addActivityLog("PASSWORD_CHANGED", "Master Admin password was changed");
    return { ok: true, message: "Admin password successfully updated." };
}

// Create new buyer order/payment submission
function createOrder(orderData) {
    if (!db.orders) db.orders = [];
    const order = {
        id: "ord_" + Date.now(),
        email: orderData.email || "",
        plan: orderData.plan || "Starter Plan",
        amount: orderData.amount || 299,
        utr: orderData.utr || "Pending",
        status: "pending",
        createdAt: new Date().toISOString()
    };
    db.orders.unshift(order);
    saveDatabase();
    addActivityLog("ORDER_SUBMITTED", `Payment order submitted by ${order.email} (₹${order.amount})`);
    return order;
}

// Get all orders
function getOrders() {
    return db.orders || [];
}

// Approve order & automatically generate client key
function approveOrder(orderId, expiryDays = 30) {
    if (!db.orders) return { ok: false, error: "No orders found" };
    const order = db.orders.find(o => o.id === orderId);
    if (!order) return { ok: false, error: "Order not found" };

    let limit = 10000;
    if (order.plan.includes("Pro")) limit = 50000;
    else if (order.plan.includes("Enterprise")) limit = 150000;

    const newKey = createClientKey(order.email.split('@')[0], order.email, order.plan, limit, expiryDays);
    order.status = "approved";
    order.apiKey = newKey.apiKey;
    order.approvedAt = new Date().toISOString();
    saveDatabase();
    addActivityLog("ORDER_APPROVED", `Approved order & issued key for ${order.email}`);
    return { ok: true, order, client: newKey };
}

// Reject order
function rejectOrder(orderId) {
    if (!db.orders) return false;
    const order = db.orders.find(o => o.id === orderId);
    if (!order) return false;
    order.status = "rejected";
    saveDatabase();
    addActivityLog("ORDER_REJECTED", `Rejected order for ${order.email}`);
    return true;
}

// Delete order
function deleteOrder(orderId) {
    if (!db.orders) return false;
    const initialLen = db.orders.length;
    db.orders = db.orders.filter(o => o.id !== orderId);
    if (db.orders.length !== initialLen) {
        saveDatabase();
        addActivityLog("ORDER_DELETED", `Deleted order ID: ${orderId}`);
        return true;
    }
    return false;
}

// Raw database export for backup
function getRawDatabase() {
    return JSON.parse(JSON.stringify(db));
}

module.exports = {
    validateAndTrack,
    getClientQuota,
    getAllClients,
    createClientKey,
    resetUsage,
    addQuota,
    toggleStatus,
    extendExpiry,
    updateClient,
    deleteClient,
    verifyAdminPassword,
    getSettings,
    updateSettings,
    changeAdminPassword,
    createOrder,
    getOrders,
    approveOrder,
    rejectOrder,
    deleteOrder,
    getRawDatabase,
    getActivityLogs
};
