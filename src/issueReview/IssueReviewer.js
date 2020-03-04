"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * This class reviews all the non-rule-related errors that occurred usually dealing with issues while communicating
 * between the host being protected and ModSec
 * @class IssueReviewer
 */
class IssueReviewer {
    /**
     * @param {IModSecError[]} errors Errors to review
     */
    constructor(errors) {
        // Filter the errors into usable data
        this.filtered = IssueReviewer.filter(errors);
    }
    /**
     * This will generate a review of all the issues that occurred
     * @returns {string}
     */
    getReview() {
        // This will initially record the number of issues that occurred while protected host X
        let results = `${this.filtered.issues.length} issues in ${this.filtered.hostname}\n`;
        // Then it will iterate through each issue and record their date, type, and error message that ModSec emits
        this.filtered.issues.forEach((error) => {
            results += `[${error.date}] [${error.type}]: ${error.msg}\n`;
        });
        // Finally return the issue-related review.
        return results;
    }
    /**
     * This filters the errors into something more usable
     * @param {IModSecError[]} errors
     */
    static filter(errors) {
        // This is the result to be returned
        const filtered = {
            // The non-rule-related errors
            issues: [],
            // The host being protected
            hostname: ''
        };
        // Iterate through all the errors
        errors.forEach((error) => {
            // If it's not a rule error then add it the array of issues
            if (error.type !== 'rule') {
                filtered.issues.push(error);
                // Only rule errors have the hostname for some reason so this will grab it if it occurs (if there is no
                // rule-related errors then the hostname can't be gotten unless the filename was used but it's not here)
            }
            else if (filtered.hostname.length <= 0 && error.hostname)
                filtered.hostname = error.hostname;
        });
        // Finally return the filtered data
        return filtered;
    }
}
exports.IssueReviewer = IssueReviewer;
//# sourceMappingURL=IssueReviewer.js.map