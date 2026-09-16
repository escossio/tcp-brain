import { updateStats } from './modules/stats.js?v=20260428-2';
import { updateRecent } from './modules/recent.js?v=20260428-2';
import { updateDetection } from './modules/detection.js?v=20260428-2';

setInterval(updateStats, 2000);
setInterval(updateRecent, 3000);
setInterval(updateDetection, 15000);
updateStats();
updateRecent();
updateDetection();
