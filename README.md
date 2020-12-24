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
  * QOL:
    * setup an rc/dotfile per the unix convension
    * reformat flags to be standardized (i.e. --force, --verbose, etc)
    * ip log file
    * output report file
  * Features:
    * URL option?
    * For VirusTotal long report, include:
      * Subdomains
      * Top 20 URLs
      * Communicating Files
      * Files Referring (if possible, filtered to MacOS type files only)
  * Architecture stuff:
    * local storage?

## Known Issues
Mac users, please add this line to your shell's dotfile:
`export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=Yes`
