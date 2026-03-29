import { updateStats } from './modules/stats.js';
import { updateRecent } from './modules/recent.js';
import { updateDetection } from './modules/detection.js';

setInterval(updateStats, 2000);
setInterval(updateRecent, 3000);
setInterval(updateDetection, 15000);
updateStats();
updateRecent();
updateDetection();
