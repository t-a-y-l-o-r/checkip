# checkip
A simple cli wrapper for a variety of security API tools.
Primarily used to detect relations of ip addresses.
Will attempt to resolve their known level of hostility per community standards.

## Flags and Usage
  _-ip_ {ipv4address} -- the flag to use when scanning a single ipv4address. Required if `-if` is not used.

  _-if_ {filepath} --input-file -- the flag to use when scanning multiple
                                      ipv4addresses. Required if `-ip` is not used

  _-f_ --force -- ensures all given ips are scanned,
			even when a record exists

  _-s_ --silent -- runs without sending anything to standardIO

  _-v_ --verbose -- runs with extra output

  _-h_ --help -- displays a list of all flags and basic usage

## Configuration
OTX and VirusTotal api keys must be used for this program to run.
Please obtain these from their offical sites for personal use.

The keys can be provided through the configuration engine in one of the following ways:
(Order of priority)
1. Environ keys: `VIRUS_TOTAL_KEY` and `OTX_KEY` respectively
2. `~/.checkip/config.ini`
3. `./config.ini` where `./` is the active directory for the program

If the `config.ini` setup is used, the following headers and keys are required:

```
[VIRUS_TOTAL]
key=abc123

[OTX]
key=321cba
```

## Up and Coming
  * QOL:
    * reformat flags to be standardized (i.e. --force, --verbose, etc)
    * ip log file
    * output report file
  * Features:
    * ivp6 addresses
    * URL option?
    * For VirusTotal long report, include:
      * Subdomains
      * Top 20 URLs
      * Communicating Files
      * Files Referring
    * specify which client will be reached out to (have a flag for each?)
    * verbose flag / silent flag
  * Architecture stuff:
    * local storage?

## Known Issues
Mac users, please add this line to your shell's dotfile:
`export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=Yes`
