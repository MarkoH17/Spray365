![Spray 365 Logo](screenshots/spray365_logo.png)

<p align="center">
  <a href="https://github.com/MarkoH17/Spray365/releases/latest">
    <img src="https://img.shields.io/github/v/tag/markoh17/spray365?label=latest&style=flat-square">
  </a>
  <a href="https://github.com/MarkoH17/Spray365/stargazers">
    <img src="https://img.shields.io/github/stars/MarkoH17/Spray365?&style=flat-square">
  </a>
  <a href="https://github.com/MarkoH17/Spray365/network/members">
    <img src="https://img.shields.io/github/forks/MarkoH17/Spray365?&style=flat-square">
  </a>
  <a href="https://github.com/MarkoH17/Spray365/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/MarkoH17/Spray365?&style=flat-square">
  </a>
  <a href="https://github.com/MarkoH17/Spray365/blob/main/spray365.py">
    <img src="https://img.shields.io/github/languages/top/markoh17/spray365?style=flat-square">
  </a>
  <br>
</p>

# What is Spray365?
Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD). How is Spray365 different from the many other password spraying tools that are already available? Spray365 enables passwords to be sprayed from an "execution plan". While having a pre-generated execution plan that describe the spraying operation well before it occurs has many other benefits that Spray365 leverages, this also allows password sprays to be resumed (`-R` option) after a network error or other interruption. While it is easiest to generate a Spray365 execution plan using Spray365 directly, other tools that produce a compatible JSON structure make it easy to build unique password spraying workflows. 

Spray365 exposes a few options that are useful when spraying credentials. Random user agents can be used to detect and bypass insecure conditional access policies that are configured to limit the types of allowed devices. Similarly, the `--shuffle_auth_order` argument is a great way to spray credentials in a less-predictable manner. This option was added in an attempt to bypass intelligent account lockouts (e.g., Azure Smart Lockout). While it’s not perfect, randomizing the order in which credentials are attempted have other benefits too, like making the detection of these spraying operations even more difficult. Spray365 also supports proxying traffic over HTTP/HTTPS, which integrates well with other tools like Burp Suite for manipulating the source of the spraying operation.

### Generating an Execution Plan (Step 1)
![Generating Execution Plan](screenshots/basic_generation.png)

### Spraying Credentials with an Execution Plan (Step 2)
![Spraying Execution Plan](screenshots/basic_spraying.png)

## Getting Started

### Installation
Clone the repository, install the required Python packages, and run Spray365!
```bash
$ git clone https://github.com/MarkoH17/Spray365
$ cd Spray365
~/Spray365$ pip3 install -r requirements.txt
~/Spray365$ python3 spray365.py
```

### Usage
#### Generate an Execution Plan
An execution plan is needed to spray credentials, so we need to create one! Spray365 can generate its own execution plan by running it in "generate" (`-g`) mode.
```bash
$ python3 spray365.py generate --execution_plan <execution_plan_filename> -d <domain_name> -u <file_containing_usernames> -pf <file_containing_passwords>
```
e.g.
```bash
$ python3 spray365.py generate --execution_plan ex-plan.s365 -d example.com -u usernames -pf passwords
```

#### Spraying an Execution Plan
Once an execution plan is available, Spray365 can be used to process it. Running Spray365 in "spray" (`-s`) mode will process the specified execution plan and spray the appropriate credentials.
```bash
$ python3 spray365.py spray --execution_plan <execution_plan_filename>
```
e.g.
```bash
$ python3 spray365.py spray --execution_plan ex-plan.s365
```

### Other Options for Advanced Usage
#### Generate Mode Options

`-ep / --execution_plan <string>`: File to store the generated Spray365 execution plan (default: None)

`-d / --domain <string>`: Office 365 domain to authenticate against (default: None)

`-u / --user_file <string>`: File containing usernames to spray (one per line without domain) (default: None)

`-p / --password <string>`: Password to spray (default: None)

`-pf / --password_file <string>`: File containing passwords to spray (one per line) (default: None)

`--delay <int>`: Delay in seconds to wait between authentication attempts (default: 30)

`-cID / --aad_client <string>`: Client ID used during authentication workflow (None for random selection, specify multiple in a comma-separated string) (default: None)

`-eID / --aad_endpoint <string>`: Endpoint ID to specify during authentication workflow (None for random selection, specify multiple in a comma-separated string) (default: None)

`-S / --shuffle_auth_order`: Shuffle order of authentication attempts so that each iteration (User1:Pass1, User2:Pass1, User3:Pass1) will be sprayed in a random order, and with a random arrangement of passwords, e.g (User4:Pass16, User13:Pass25, User19:Pass40). Be aware this option introduces the possibility that the time between consecutive authentication attempts for a given user may occur DELAY seconds apart. Consider using the -mD/--min_cred_loop_delay option to enforce a minimum delay between authentication attempts for any given user. (default: False)

`-SO / --shuffle_optimization_attempts <int>`: Number of random execution plans to generate for identifying the fastest execution plan (default: 10)

`-mD / --min_cred_loop_delay <int>`: Minimum time to wait between authentication attempts for a given user. This option takes into account the time one spray iteration will take, so a pre-authentication delay may not occur every time (disable with 0) (default: 0)

`-cUA / --custom_user_agent <string>`: Set custom user agent for authentication requests (default: None)

`-rUA / --random_user_agent`: Randomize user agent for authentication requests (default: False)
  
#### Spray Mode Options
  
`-ep, --execution_plan <string>`: File containing Spray365 execution plan to use for password spraying (default: None)

`-l, --lockout <int>`: Number of account lockouts to observe before aborting spraying session (disable with 0) (default: 5)

`-x, --proxy <string>`: HTTP Proxy URL (format: http[s]://proxy.address:port) (default: None)

`-k, --insecure`: Disable HTTPS certificate verification (default: False)

`-R, --resume_index <int>`: Resume spraying passwords from this position in the execution plan (default: 0)

`-i, --ignore_success`: Ignore successful authentication attempts for users and continue to spray credentials. Setting this flag will enable spraying credentials for users even if Spray365 has already identified valid credentials. (default: False)


## Acknowledgements
| Author | Tool / Other | Link |
| --- | --- | --- |
| [@__TexasRanger](https://twitter.com/__TexasRanger) | msspray: Conduct password spray attacks against Azure AD as well as validate the implementation of MFA on Azure and Office 365 endpoints | [https://github.com/SecurityRiskAdvisors/msspray](https://github.com/SecurityRiskAdvisors/msspray)

## Disclaimer
Usage of this software for attacking targets without prior mutual consent is illegal. It is the end user’s responsibility to obey all applicable local, state and federal laws, in addition to any applicable acceptable use policies. Using this software releases the author(s) of any responsiblity for misuse or damage caused.
