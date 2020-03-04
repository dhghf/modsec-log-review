# modsec-log-reviewer
## Requirements
 - [NodeJS](https://nodejs.org)
 - NPM (installed with NodeJS installer)
 
## Setup
Once all requirements are installed run `npm install` to install all the node dependencies. Then run
`npm build` to compile the code.

## Usage
Run `npm start` to execute the program

### Commands
 - `fp [error-log-path] [output-path]`: Scan a ModSec error log file for false positives
 - `inspect [error-log-path] [normal-log-path] [output-path]` Scan both an error log file 
 and regular log (non-error-related) that correlate with the same host.
 - `bugs [error-log-path] [output-path]` Look for non-rule-related issues with ModSec
 and the host
 - `all [error-log-path] [normal-log-path] [output-path]` Runs all the commands at once
 
An Example:
 `npm start all ./test/log-examples/ebay_ssl_error_log ./test/log-examples/ebay_ssl_log ./output.log`
 
### Flags
 - `nons`: Prevents ns-lookups (saves time)
 - `help`: Print help dialogue
 - example: `npm start --help`
 - example: `npm start [command] --help`
 - example: `npm start [command] nons`
