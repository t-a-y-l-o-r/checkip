# checkip
API Application for a variety of security programs

## Flags and Usage
  _-ip_ {ipv4address} -- the flag to use when scanning a single ipv4address

  _-if_ {filepath} --input-file -- the flag to use when scanning multiple
                                      ipv4addresses

  _-ap_ --all-ips -- ensures all given ips are scanned,
			even when a record exists

  _-h_ --help -- displays a list of all flags and basic usage


## Up and Coming
  * add flags for the following:
    * ip log file
    * ouput report file
  * database storage???
  * URL option?
    * For VirusTotal long report, include:
      * Subdomains
      * Top 20 URLs
      * Communicating Files
      * Files Referring (if possible, filtered to MacOS type files only)

