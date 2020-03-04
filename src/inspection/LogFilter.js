"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const nslookup_1 = require("../tools/nslookup");
/**
 * This is probably the most complex filter of all of them because it filters both normal and error-related logs at
 * once.
 * @class LogFilter
 */
class LogFilter {
    constructor(normalLogs, ruleErrors, doNSLookup) {
        this.normalLogs = normalLogs;
        this.ruleErrors = ruleErrors;
        this.doNSLookup = doNSLookup;
    }
    /**
     * This filters both a normal and error log to be ready for review
     * @returns {Promise<Map<string, RuleErrorCollection>>} The value being the rule ID and the rule being broken
     */
    filter() {
        return new Promise(async (resolve) => {
            let ips = await this.gatherIPs();
            // Review the activities for all the IP's
            ips = this.filterNormalLogs(ips);
            // Review error logs for a final time
            const finalFilter = this.filterErrorLogs(ips);
            // Return all the filtered data
            resolve(finalFilter);
        });
    }
    /**
     * This will gather an IP and get an ns-lookup if it's enabled
     * @returns {Promise<Map<string, IP>>} The key being the IP itself and the value being details of the IP
     */
    gatherIPs() {
        return new Promise((resolve) => {
            // IP collection to return
            const ips = new Map();
            // All the ns-lookups being processed
            const lookups = [];
            // Iterate through each error
            this.ruleErrors.forEach((ruleError) => {
                // Get the recorded IP if it has been recorded
                const ip = ips.get(ruleError.ip);
                // If it has been recorded
                if (ip) {
                    // Then add the rule broken by this IP
                    ip.brokenRules.push(ruleError);
                    // Save it in the map.
                    ips.set(ruleError.ip, ip);
                }
                else {
                    // If this is the first time setting this IP
                    // Build a new IP object
                    const newIP = {
                        // All the rules this IP broke
                        brokenRules: [ruleError],
                        // All if their normal activities (and rejected requests)
                        allActivities: [],
                        // Their IP
                        ip: ruleError.ip,
                        // All their rejected requests
                        rejectedRequests: [],
                        // Their useragent
                        useragent: '',
                        // Their ns-lookup result
                        nsLookup: ''
                    };
                    // If ns-lookups are turned on
                    if (this.doNSLookup) {
                        // Then do an ns-lookup
                        const result = nslookup_1.default(ruleError.ip);
                        // When it finally resolves set the nsLookup property to the result (can possibly be empty)
                        result.then((hostname) => {
                            newIP.nsLookup += hostname;
                        });
                        // Push this promise to the array of promises (so we can wait until all lookups are done)
                        lookups.push(result);
                    }
                    else
                        // If ns-lookups are turned off then set nsLookup to "no-lookup"
                        newIP.nsLookup += 'no-lookup';
                    // Record the new recorded IP
                    ips.set(ruleError.ip, newIP);
                }
            });
            // Return the IP's when all the lookups are complete
            Promise.all(lookups).then(() => resolve(ips));
        });
    }
    /**
     * This reviews all the normal activities of an IP address
     * @param {Map<string, IP>} ips K: the IP address V: The IP details (See type IP)
     * @returns {Map<string, IP>} return the same given Map object.
     */
    filterNormalLogs(ips) {
        this.normalLogs.forEach((normalLog) => {
            const ip = ips.get(normalLog.ip);
            if (ip) {
                // Gather all the rejected requests
                if (normalLog.statusCode !== '200')
                    ip.rejectedRequests.push(normalLog);
                // Get the IP's user-agent
                if (ip.useragent.length === 0)
                    ip.useragent = normalLog.useragent;
                // Push back into their activity history
                ip.allActivities.push(normalLog);
            }
        });
        return ips;
    }
    /**
     * Filter all the rules broken
     * @param {Map<string, IP>} ips K: the IP address V: The IP details (See type IP)
     * @returns {Map<string, RuleErrorCollection>}
     */
    filterErrorLogs(ips) {
        const errors = new Map();
        // Iterate through all the errors
        this.ruleErrors.forEach((ruleError) => {
            // Get the recorded recordedError (if it has already)
            const recordedError = errors.get(ruleError.id);
            // Get the IP of the IP collection
            const recordedIP = ips.get(ruleError.ip);
            // If both exist
            if (recordedError && recordedIP) {
                // Then get the IP that occurred in this error
                const collectedIP = recordedError.ips.find((x) => x.ip === recordedIP.ip);
                // If this IP has never been recorded breaking this error then record it
                if (!collectedIP) {
                    recordedError.ips.push(recordedIP);
                    // Save it back to the records
                    errors.set(ruleError.id, recordedError);
                }
            }
            else if (recordedError == undefined && recordedIP) {
                // If this error has never been seen before then record it as well as the IP that broken it
                const newErrorCollection = {
                    ...ruleError,
                    ips: [recordedIP]
                };
                // Save it back to the records
                errors.set(ruleError.id, newErrorCollection);
            }
        });
        // This is all the errors and each error object has all the IP's that triggered this rule error
        return errors;
    }
}
exports.LogFilter = LogFilter;
//# sourceMappingURL=LogFilter.js.map