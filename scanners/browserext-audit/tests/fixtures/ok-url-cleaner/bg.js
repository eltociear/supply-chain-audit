// remove tracking parameters
const STRIP = ['utm_source', 'utm_medium', 'fbclid', 'gclid'];
function clean(u){ return u.replace(/[?&]tag=[^&]*/, '').replace(/[?&]affid=[^&]*/, ''); }
chrome.declarativeNetRequest.updateDynamicRules({addRules: [{id: 1, action: {type: 'redirect', redirect: {transform: {queryTransform: {removeParams: STRIP}}}}, condition: {urlFilter: '*'}}]});
