import * as yargs from 'yargs'
import * as fs from 'fs'
import { ErrorLogParser, IModSecError, IRuleError, NormalLogParser } from "modsec-log-parse";
import { reviewEntireLog, reviewFalsePositives, reviewIssues } from "./index";

const MISSING_OUTPUT = 'Please provide an output path to store the report';
const MISSING_NORMAL_LOG = 'Please provide a resolvable path to a normal (non-error-related) ModSec log file';
const MISSING_ERROR_LOG = 'Please provide an path to the ModSec error log';

function save(location: string, data: string | Buffer): void {
    fs.writeFileSync(location, data);
    console.log('Saved to ' + location);
}


const argv = yargs
  /**
   * This is the false positives command this reviews an error logs and gets the data sorted to help the user detect
   * what errors are false positives rather than real issues. This accounts for all the IP's that trigger a rule and
   * how many times a rule was triggered as well as the data sent from an IP. See the handler method
   */
  .command({
      command: 'fp [error-log-path] [output-report]',
      describe: 'Review error logs for false positives',
      builder: (thisYargs) => thisYargs.positional('error-log-path', {
          describe: 'A resolvable path to a ModSec Error log file',
          type: "string"
      }).positional('output-report', {
          describe: 'An output file to store the false positives',
          type: 'string'
      }).option('noLookup', {
          alias: 'noLookup',
          describe: 'Prevent ns-lookups',
          type: 'boolean',
          default: false
      }),
      handler: async (args) => {
          // The output path to store the false-positives review
          const output = args['output-report'] as string | undefined;
          // THe error log to review
          const errorLogPath = args['errorLogPath'] as string | undefined;
          // If both were provided then continue to review them
          if (output && errorLogPath) {
              console.log('Gathering false positives...');

              // If the user wants to do ns-lookups tell them it's going to take a while depending on their amount of
              // UNIQUE IP's in the log.
              if (!args.noLookup)
                  console.log('This may take a while due to ns-lookups');
              const errorLogData: Buffer = fs.readFileSync(errorLogPath);
              /**
               * This will filter the log and only look for the rule-related errors and convert them to objects.
               * @const {IRuleError[]} ruleErrors
               */
              const ruleErrors = ErrorLogParser.parseLog(errorLogData)
                .filter((x: IModSecError) => x.type === 'rule') as IRuleError[];
              /**
               * This will generate an entire report into a string to be saved to a file
               * @const {string} falsePositivesReview False-positives report
               */
              const falsePositivesReview = await reviewFalsePositives(ruleErrors, !args.noLookup);
              // Finally save the report to the given output path
              save(output, falsePositivesReview);
          } else {
              // If an output path wasn't provided then prompt the user for one.
              if (output == undefined)
                  console.log(MISSING_OUTPUT);
              // If an error log to review wasn't provided then prompt the user for one.
              if (errorLogPath == undefined)
                  console.log(MISSING_ERROR_LOG);
              // This is the complete usage of the method.
              console.log('false-positives [error-log-path] [output-report]');
          }
      }
  })
  /**
   * This command inspects both a normal and error log. It's oriented towards giving an entire over view of all the
   * IP's that triggered a rule error and their previous "norma" activity as well into an output file. See the
   * handler method.
   */
  .command({
      command: 'inspect [error-log-path] [normal-log-path] [output-report]',
      describe: 'Review both normal and error logs for real issues',
      builder: (thisYargs) => thisYargs.positional('error-log-path', {
          describe: 'A resolvable path to a ModSec Error log file',
          type: "string"
      }).positional('normal-log-path', {
          describe: 'A resolvable path to a normal (non-error-related) ModSec log file',
          type: "string"
      }).positional('output-report', {
          describe: 'An output file to store the inspection',
          type: 'string'
      }).option('noLookup', {
          alias: 'no-lookup',
          describe: 'Prevent ns-lookups',
          type: 'boolean',
          default: false
      }),
      handler: async (args) => {
          // Output path to store the review to
          const output = args['output-report'] as string | undefined;
          // Normal log file to review
          const normalLogPath = args['normal-log-path'] as string | undefined;
          // Error log file to review (must be corresponding to the normal one ie same host)
          const errorLogPath = args['error-log-path'] as string | undefined;
          // If all were given then continue to review the logs
          if (output && normalLogPath && errorLogPath) {
              console.log('Reviewing logs...');
              const errorLogData = fs.readFileSync(errorLogPath);
              const normalLogData = fs.readFileSync(normalLogPath);

              /**
               * This will parse the normal log plain-text into objects that will be easier to review.
               * @const {INormalLog[]} normalLogs
               */
              const normalLogs = NormalLogParser.parseLog(normalLogData);
              /**
               * This will grab all the rule-related errors from the plain-text log to review.
               * @const {IRuleError[]} ruleErrors
               */
              const ruleErrors = ErrorLogParser.parseLog(errorLogData)
                .filter((x: IModSecError) => x.type === 'rule') as IRuleError[];

              /**
               * Finally with this parsed data continue to review both logs.
               * @const {string} inspected
               */
              const inspected = await reviewEntireLog(normalLogs, ruleErrors, !args.noLookup);

              // Save the review to the given output path.
              save(output, inspected);
          } else {
              // If the output was undefined then prompt the user for one
              if (output == undefined)
                  console.log(MISSING_OUTPUT);
              // If the normal log path was undefined then prompt the user for it
              if (normalLogPath == undefined)
                  console.log(MISSING_NORMAL_LOG);
              // If the error log path was undefined then prompt the user for it
              if (errorLogPath == undefined)
                  console.log(MISSING_ERROR_LOG);
              // This is the entire usage for the command
              console.log('inspect-log [error-log-path] [normal-log-path] [output-report]')
          }
      }
  })
  /**
   * This looks for non-rule related errors (issues that occurred while communicating to ModSec) and outputs it to a
   * given file path. See the handler method
   */
  .command({
      command: 'bugs [error-log-path] [output-report]',
      describe: 'Review an error log for ModSec (non-rule-related) errors',
      builder: (thisYargs) => thisYargs.positional('error-log-path', {
          describe: 'A resolvable path to a ModSec Error log file',
          type: "string"
      }).positional('output-report', {
          describe: 'An output file to store the issues',
          type: 'string'
      }).option('noLookup', {
          alias: 'no-lookup',
          describe: 'Prevent ns-lookups',
          type: 'boolean',
          default: false
      }),
      handler: (args) => {
          // Where to put the issue report
          const output = args['output-report'] as string | undefined;
          // The error log to scan
          const errorLogPath = args['error-log-path'] as string | undefined;
          // If both were given then continue to review the error log
          if (output && errorLogPath) {
              const errorLogData = fs.readFileSync(errorLogPath);
              /**
               * This parses the plain-text log into an array of objects
               * @const {IModSecError[]} errorLogs
               */
              const errorLogs = ErrorLogParser.parseLog(errorLogData);
              /**
               * This is all the bugs found (non-rule related errors)
               * @const {string} bugs Bugs report
               */
              const bugs = reviewIssues(errorLogs);
              // Finally save the report to the given output path
              save(output, bugs);
          } else {
              // If an output path wasn't provided then prompt the user for one
              if (output == undefined)
                  console.log(MISSING_OUTPUT);
              // If the error log path to review wasn't provided then prompt the user for one
              if (errorLogPath == undefined)
                  console.log(MISSING_ERROR_LOG);
              // This is how to use the command
              console.log('bugs [error-log-path] [output-report]')
          }
      }
  })
  /**
   * This runs all the the scans from above
   */
  .command({
      command: 'all [error-log-path] [normal-log-path] [output-report]',
      describe: 'Review everything about a pair of ModSec log files',
      builder: (thisYargs) => thisYargs.positional('error-log-path', {
          describe: 'A resolvable path to a ModSec Error log file',
          type: "string"
      }).positional('output-report', {
          describe: 'An output file to store the issues',
          type: 'string'
      }).positional('normal-log-path', {
          describe: 'A resolvable path to a normal (non-error-related) ModSec log file',
          type: "string"
      }),
      handler: async (args) => {
          const output = args['output-report'] as string | undefined;
          const errorLogPath = args['error-log-path'] as string | undefined;
          const normalLogPath = args['normal-log-path'] as string | undefined;
          if (output && errorLogPath && normalLogPath) {
              const errorLogs = ErrorLogParser.parseLog(fs.readFileSync(errorLogPath));
              const normalLogs = NormalLogParser.parseLog(fs.readFileSync(normalLogPath));
              const ruleErrors = errorLogs.filter(x => x.type === 'rule') as IRuleError[];

              const fp: string = await reviewFalsePositives(ruleErrors, !args.noLookup);
              const bugs: string = reviewIssues(errorLogs);
              const inspect: string = await reviewEntireLog(normalLogs, ruleErrors, !args.noLookup);
              save(output, `${fp}\n${bugs}\n${inspect}`);
          } else {
              if (output == undefined)
                  console.log(MISSING_OUTPUT);
              if (errorLogPath == undefined)
                  console.log(MISSING_ERROR_LOG);
              if (normalLogPath == undefined)
                  console.log(MISSING_NORMAL_LOG);
              console.log('all [error-log-path] [normal-log-path] [output-report]')
          }
      }
  })
  .argv;
