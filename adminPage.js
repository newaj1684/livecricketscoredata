const fs = require('fs');
const path = require('path');

function getAdminHTML() {
    return fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');
}

module.exports = { getAdminHTML };
