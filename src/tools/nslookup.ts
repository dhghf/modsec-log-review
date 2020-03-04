import * as dns from 'dns';

const collected: Map<string, string | null> = new Map();

export default function nsLookup(ip: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const result = collected.get(ip);
    if (result != undefined) {
      resolve(result)
    } else {
      dns.reverse(ip, (err, hostname) => {
        if (err) {
          collected.set(ip, null);
          reject(null);
        } else if (hostname) {
          collected.set(ip, hostname[0]);
          resolve(hostname[0]);
        }
      })
    }
  })
}
