const fs = require('fs');
// copy all files from plugins folder to node_modules/zone-mta/plugins
const copydir = require('copy-dir');
const path = require('path');
const pluginsPath = path.join(__dirname, 'plugins');
const destPath = path.join(__dirname, 'node_modules/zone-mta/plugins');
copydir.sync(pluginsPath, destPath);
// copy all files config folder to node_modules/zone-mta/config
const configPath = path.join(__dirname, 'config');
const destConfigPath = path.join(__dirname, 'node_modules/zone-mta/config');
copydir.sync(configPath, destConfigPath);


require('zone-mta')
