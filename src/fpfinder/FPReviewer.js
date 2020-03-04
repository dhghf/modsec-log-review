"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const FPFilter_1 = require("./FPFilter");
const nslookup_1 = require("../tools/nslookup");
/**
 * This class generates a review of an error log to help the user detect false-positives that occurred.
 * @class FPReviewer
 */
class FPReviewer {
    constructor(ruleErrors, doNSLookup) {
        this.filtered = new FPFilter_1.default(ruleErrors);
        this.doNSLookup = doNSLookup;
    }
    /**
     * This will generate both a brief overview and detailed overview of all the possible false-positives by sorting
     * them from possible to least-possible of being a false-positive
     * @returns {Promise<string>}
     */
    async getReview() {
        const fpOverview = await this.getOverview();
        const fpBreakdown = await this.getBreakdown();
        return `${fpOverview}\n${fpBreakdown}`;
    }
    /**
     * This will give a brief overview of the logs
     * @returns {Promise<string>}
     */
    async getOverview() {
        // This will initially record the review of the host being protected as well as some table headers
        // Like the number of IP's, re-occurrences (hits), rule ID, and the rule error message the ModSec emits in the
        // logs
        let output = `Reviewing ModSec logs for ${this.filtered.hostname}\nIPs\tHits\tRule  \tMessage\n`;
        // This will build the overview by iterating through each error
        this.filtered.errors.forEach((ruleBroken) => {
            // This is one row
            let row = `IPS\tHITS\tID\tMSG\n`
                // The number of unique IP's
                .replace(/(IPS)/, FPReviewer.fixWhiteSpace(ruleBroken.ipList.size.toString(), 3))
                // The number of re-occurrences
                .replace(/(HITS)/, FPReviewer.fixWhiteSpace(ruleBroken.hits.toString(), 4))
                // The rule ID
                .replace(/(ID)/, ruleBroken.id)
                // The rule error message that ModSec emits in the logs
                .replace(/(MSG)/, ruleBroken.msg);
            // Add the row to the output
            output += row;
        });
        // Finally return the reviewed overview
        return output;
    }
    /**
     * This gets a detailed breakdown of all the data used and unique IP's that appeared
     * @returns {Promise<string>}
     */
    async getBreakdown() {
        // This initially will record the host being reviewed (the host ModSec is protecting)
        let output = `Reviewing detailed breakdown for ${this.filtered.hostname}\n`;
        // This will get a ns-lookup collection (a Map with the key being the IP being looked up and the value the
        // ns-lookup result
        this.lookupCollection = this.doNSLookup ? await this.recursiveLookup() : undefined;
        // Iterate through each error
        this.filtered.errors.forEach((ruleBroken) => {
            // Record the rule being reviewed and the rule error message that emits in the log by ModSec
            output += `${ruleBroken.id} Breakdown - ${ruleBroken.msg}\n`;
            // IP Breakdown (the top 10 IP's causing an issue)
            output += this.reviewIP(ruleBroken);
            // Data Breakdown (the top 10 most used data when this error was triggered)
            output += this.reviewDataSent(ruleBroken);
        });
        // Finally return the detailed review back
        return output;
    }
    /**
     * This reviews all the IP's that triggered this rule
     * @param {OrganizedError} ruleError
     * @returns {string}
     */
    reviewIP(ruleError) {
        // This initially records all the unique IP's that occurred
        let ipBreakdown = ` - IP Addresses (${ruleError.ipList.size >= 10 ? `Top 10 of ${ruleError.ipList.size}` : ruleError.ipList.size})\n`;
        // This will sort the IP's based on most re-occurrences
        const sortedIPs = [];
        for (const ip of ruleError.ipList.values()) {
            sortedIPs.push(ip);
        }
        sortedIPs.sort((x, y) => x.hits - y.hits).reverse();
        // Then iterate top to bottom all the IP's
        sortedIPs.forEach((ip) => {
            // Get their ns-lookup result (if there is one or if it's on)
            let hostname = this.lookupCollection ? this.lookupCollection.get(ip.ip) : 'no-lookup';
            // Record how many times this IP occurred
            if (sortedIPs.indexOf(ip) <= 9) {
                ipBreakdown += `\t - ${ip.hits} - ${FPReviewer.fixWhiteSpace(ip.ip, 15)}\t[${hostname ? hostname : 'null'}]\n`;
            }
        });
        // Finally return the review of all the IP's that triggered this error
        return ipBreakdown;
    }
    /**
     * This reviews all the data that was used to trigger this error
     * @param {OrganizedError} ruleError
     * @returns {string}
     */
    reviewDataSent(ruleError) {
        // This will be output which basically first records the amount of errors
        let output = ` - Data Match (${ruleError.dataUsed.size >= 9 ? `10/${ruleError.dataUsed.size}` : ruleError.dataUsed.size})\n`;
        // This sorts the data based on most re-occurrences
        const sortedData = [];
        for (const data of ruleError.dataUsed.values()) {
            sortedData.push(data);
        }
        sortedData.sort((x, y) => (x.hits < y.hits ? -1 : 1));
        // Then iterate top to bottom all the data
        sortedData.forEach((data) => {
            if (sortedData.indexOf(data) <= 9) {
                // Record the amount of re-occurrences and the data used
                output += `\t - ${data.hits} - ${data.data}\n`;
            }
        });
        output += '\n';
        // Finally return the data review.
        return output;
    }
    /**
     * This does some fancy white-spacing to make the logs print out evenly
     * @param {string} data The context
     * @param {number} length The maximum possible length that the context could be otherwise
     */
    static fixWhiteSpace(data, length) {
        let output = data;
        if (data.length < length) {
            output += ' '.repeat(length - data.length);
        }
        return output;
    }
    /**
     * This recursively does an ns-lookup on all the IP's in all the rules broken
     * @returns {Promise<Map<string, string>>} The key is the IP itself the value is the ns-lookup result
     */
    recursiveLookup() {
        return new Promise((resolve) => {
            // This will help wait for all the ns-lookups to finish later down the line.
            const promises = [];
            // Iterate through all the errors
            this.filtered.errors.forEach((error) => {
                // Iterate through all the IP's that triggered this error
                error.ipList.forEach((ip) => {
                    // Add the list of promises of the ns-lookup of said IP
                    promises.push(new Promise(async (resolve) => resolve([ip.ip, await nslookup_1.default(ip.ip)])));
                });
            });
            // Wait for all ns-lookups to finish and then iterate through all of them
            Promise.all(promises).then((lookups) => {
                // This will return a Map the key being the IP and the value being the ns-lookup result
                const collection = new Map();
                // Iterate through all the ns-lookup results
                lookups.forEach((value) => {
                    let ip = value[0];
                    let result = value[1];
                    if (ip && result)
                        collection.set(ip, result);
                });
                // Finally resolve with a collection of ns-lookups
                resolve(collection);
            });
        });
    }
}
exports.FPReviewer = FPReviewer;
//# sourceMappingURL=FPReviewer.js.map