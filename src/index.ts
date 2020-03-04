import './inspection/EntireLogReviewer';
import './fpfinder/FPReviewer';
import './issueReview/IssueReviewer';
import { FPReviewer } from "./fpfinder/FPReviewer";
import { IModSecError, INormalLog, IRuleError } from "modsec-log-parse/lib/src";
import { EntireLogReviewer } from "./inspection/EntireLogReviewer";
import { IssueReviewer } from "./issueReview/IssueReviewer";

export function reviewIssues(errors: IModSecError[]) {
    const issueReviewer = new IssueReviewer(errors);
    return issueReviewer.getReview();
}

export function reviewFalsePositives(ruleErrors: IRuleError[], lookup: boolean = false) {
    const fpReviewer = new FPReviewer(ruleErrors, lookup);
    return fpReviewer.getReview();
}

export function reviewEntireLog(normalLogs: INormalLog[], errorLogs: IRuleError[], lookup: boolean = true): Promise<string> {
    const logReviewer = new EntireLogReviewer(normalLogs, errorLogs, lookup);
    return logReviewer.getReview();
}
