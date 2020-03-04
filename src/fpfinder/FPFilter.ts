import { IRuleError } from "modsec-log-parse";

/**
 * This class filters all the "rule" errors that occurred in the log into data
 * that can be easily used in the FPReview class.
 * @class FPFilter False Positives Filter
 */
export default class FPFilter {
  // The host being effected
  public readonly hostname: string;
  // string: Rule ID, OrganizedError: The rule error itself (but modified)
  public readonly errors: Map<string, OrganizedError>;

  /**
   * @param {IRuleError[]} ruleErrors The errors to filter through
   */
  constructor(ruleErrors: IRuleError[]) {
    this.errors = new Map();
    this.hostname = ruleErrors[0].hostname;
    // Organize the errors into a Map (this will make it to easily filter all the rules based on their ID).
    ruleErrors.forEach((ruleError: IRuleError) => {
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

/**
 * This helps organize the data and keep it consistent
 * @class DataCollector
 */
export class OrganizedError {
  // The message of the error
  public readonly msg: string;
  // The rule ID
  public readonly id: string;
  // The number of re-occurrences
  public hits: number;
  // The IP's that triggered this error
  public ipList: Map<string, IP>;
  // The data that the IP's used to trigger this rule
  public dataUsed: Map<string, Data>;

  constructor(ruleError: IRuleError) {
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
  public collect(ruleError: IRuleError): OrganizedError {
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

/**
 * This IP class helps keep count of how many times the IP occurred
 * and all the data used
 * @class IP
 */
export class IP {
  // How many this IP occurred
  public hits: number;
  // The data that the connector provided
  public dataUsed: string[];
  // The IP itself
  public readonly ip: string;

  constructor(ruleError: IRuleError) {
    this.hits = 1;
    this.dataUsed = [ruleError.data];
    this.ip = ruleError.ip;
  }

  public collect(ruleError: IRuleError): IP {
    // Add the data used that this IP used
    this.dataUsed.push(ruleError.data);
    // Account for the re-occurrences of this IP
    this.hits += 1;
    return this;
  }
}

/**
 * This is the data sent by a client (ie the attacker) it keeps track of all
 * the IP's that used this same data, how many times it reoccurred, and the
 * last date
 * @class Data
 */
export class Data {
  // All the IP's that used this data (the more IP's the more likely it's a false-positive)
  public ipList: string[];
  // The amount of times this data reoccurred
  public hits: number;
  // The last data of occurrence
  public date: string;
  // The data itself being used
  public readonly data: string;

  constructor(ruleError: IRuleError) {
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
  public collect(ruleError: IRuleError): Data {
    // Add the IP that broken this rule
    this.ipList.push(ruleError.ip);
    // Add to the amount of times this rule appeared
    this.hits++;
    return this;
  }
}
