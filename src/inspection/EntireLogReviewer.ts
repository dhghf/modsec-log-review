import { IP, LogFilter, RuleErrorCollection } from './LogFilter'
import { INormalLog, IRuleError } from "modsec-log-parse";
import { Reviewer } from "../classes/Reviewer";

/**
 * This class reviews both an error and normal ModSec log and gets the entire review of both. Rather than focusing on
 * false-positives, this tracks each IP's normal usage and errors that said IP triggered in their
 * activity history.
 * @class EntireLogReviewer
 */
export class EntireLogReviewer implements Reviewer {
    private readonly normalLogs: INormalLog[];
    private readonly ruleErrors: IRuleError[];
    private readonly doNSLookup: boolean;

    constructor(normalLogs: INormalLog[], ruleErrors: IRuleError[], doNSLookup: boolean) {
        this.normalLogs = normalLogs;
        this.ruleErrors = ruleErrors;
        this.doNSLookup = doNSLookup;
    }

    /**
     * This is the header of an IP it's a brief overview of the IP's user-agent and nslookup if it's enabled.
     * @param {IP} ip
     */
    private static getHeader(ip: IP): string {
        return `${ip.ip}'s activity\n - nslookup: ${ip.nsLookup}\n - user-agent: ${ip.useragent}\n`;
    }

    /**
     * ModSec stores it's date in a way that JavaScript doesn't understand so this shifts the numbers around and
     * returns a Date object.
     * @param {Date} date
     */
    private static fixDate(date: string): Date {
        const selected = date.split('/');
        return new Date(`${selected[1]}/${selected[0]}/${selected[2].replace(/(:)/, ' ').split('+')[0]}`)
    }

    /**
     * This gets the review of the filtered data
     * @returns {Promise<string>}
     */
    public async getReview(): Promise<string> {
        let str = '';
        // This filters the data into only data we need.
        const filter = new LogFilter(this.normalLogs, this.ruleErrors, this.doNSLookup);
        const filtered = await filter.filter();

        // This iterates through the filtered data and builds the review
        filtered.forEach((ruleError: RuleErrorCollection, ruleID: string) => {
            // This gives us the amount of unique IP's that triggered this rule, the rule ID and the rule message that
            // is emitted in the logs when this rule is broken.
            str += `[${ruleError.ips.length}] ${ruleID} - ${ruleError.msg}\n`;
            ruleError.ips.forEach((ip: IP) => {
                // This will give us the user-agent and ns-lookup
                str += EntireLogReviewer.getHeader(ip);
                // This will get a detailed breakdown of a certain IP (See getBreakdown method)
                str += this.getBreakdown(ip, ruleID);
            })
        });
        return str
    }

    /**
     * This gets the detailed breakdown of an IP
     * @param {IP} ip IP being inspected
     * @param {string} id Rule ID
     */
    private getBreakdown(ip: IP, id: string): string {
        // Top then most used unique data re-occurrences that the IP used.
        let top10Data = 'Top 10 most used data:\n';
        // All of the IP's request that were rejected
        let rejects = 'Rejected requests:\n;';
        // The first time this IP was seen
        let first: Date;
        // THe last time this IP was seen
        let last: Date;
        let i = 0;
        // This will get all of the unique data used and will add it to the top10Data
        ip.brokenRules.filter((x: IRuleError) => x.id === id)
          .forEach((ruleError: IRuleError) => {
              const date = new Date(ruleError.date);
              if (i === 0)
                  first = date;
              if (i <= 9)
                  top10Data += ` [${date.getHours()}:${date.getMinutes()}]: ${ruleError.data}\n`;
              last = date;
              i++
          });
        // This will get all the rejected requests and add it to the rejects string
        ip.rejectedRequests.forEach((rejected: INormalLog) => {
            const date = EntireLogReviewer.fixDate(rejected.date);
            if (date <= last && date >= first) {
                rejects += ` [${date.getHours()}:${date.getMinutes()}] [${rejected.statusCode}/${rejected.method}]: ${rejected.uri}\n`
            }
        });
        // Finally this will return the top ten unique data used by this IP as well as the requests that were rejected
        // from this IP
        return `${top10Data}\n${rejects}\n`
    }
}
