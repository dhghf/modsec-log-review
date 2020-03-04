"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * This class filters all the "rule" errors that occurred in the log into data
 * that can be easily used in the FPReview class.
 * @class FPFilter False Positives Filter
 */
class FPFilter {
    /**
     * @param {IRuleError[]} ruleErrors The errors to filter through
     */
    constructor(ruleErrors) {
        this.errors = new Map();
        this.hostname = ruleErrors[0].hostname;
        // Organize the errors into a Map (this will make it to easily filter all the rules based on their ID).
        ruleErrors.forEach((ruleError) => {
            // This will get the rule broken if it exists in the map
            let ruleBroken = this.errors.get(ruleError.id);
            // If this rule was already accounted for then add it to the list of re-occurrences  as well as the data
            // and IP
            if (ruleBroken != undefined)
                this.errors.set(ruleError.id, ruleBroken.collect(ruleError));
            // Otherwise make a new OrganizedError to keep track of this error in the future if it reoccurs
            else
                this.errors.set(ruleError.id, new OrganizedError(ruleError));
        });
    }
}
exports.default = FPFilter;
/**
 * This helps organize the data and keep it consistent
 * @class DataCollector
 */
class OrganizedError {
    constructor(ruleError) {
        this.msg = ruleError.msg;
        this.id = ruleError.id;
        this.hits = 1;
        this.ipList = new Map();
        this.dataUsed = new Map();
        this.collect(ruleError);
    }
    /**
     * This filters a rule-related error into easy accessible data
     * @param {IRuleError} ruleError
     * @returns {OrganizedError}
     */
    collect(ruleError) {
        let savedIP = this.ipList.get(ruleError.ip);
        let savedData = this.dataUsed.get(ruleError.data);
        // If this IP has already been recorded
        if (savedIP)
            // Then make sure to capture the data that the IP used and the amount of times it occurred.
            this.ipList.set(ruleError.ip, savedIP.collect(ruleError));
        else
            // Otherwise add it to the Map to record later occurrences
            this.ipList.set(ruleError.ip, new IP(ruleError));
        // If this data has already been recorded
        if (savedData)
            // Then collect the IP that used it and the amount of times of its occurrences
            this.dataUsed.set(ruleError.data, savedData.collect(ruleError));
        else
            // Otherwise add it the Map to record later occurrences
            this.dataUsed.set(ruleError.data, new Data(ruleError));
        // Count the number of re-occurrences
        this.hits++;
        return this;
    }
}
exports.OrganizedError = OrganizedError;
/**
 * This IP class helps keep count of how many times the IP occurred
 * and all the data used
 * @class IP
 */
class IP {
    constructor(ruleError) {
        this.hits = 1;
        this.dataUsed = [ruleError.data];
        this.ip = ruleError.ip;
    }
    collect(ruleError) {
        // Add the data used that this IP used
        this.dataUsed.push(ruleError.data);
        // Account for the re-occurrences of this IP
        this.hits += 1;
        return this;
    }
}
exports.IP = IP;
/**
 * This is the data sent by a client (ie the attacker) it keeps track of all
 * the IP's that used this same data, how many times it reoccurred, and the
 * last date
 * @class Data
 */
class Data {
    constructor(ruleError) {
        this.ipList = [ruleError.ip];
        this.hits = 1;
        this.date = ruleError.date;
        this.data = ruleError.data;
    }
    /**
     * This collects and organizes a rule error
     * @param {IRuleError} ruleError
     * @returns {Data}
     */
    collect(ruleError) {
        // Add the IP that broken this rule
        this.ipList.push(ruleError.ip);
        // Add to the amount of times this rule appeared
        this.hits++;
        return this;
    }
}
exports.Data = Data;
//# sourceMappingURL=FPFilter.js.map