# log4j-log4shell-affected
Lists of affected components and affected apps/vendors by CVE-2021-44228 (aka Log4shell or Log4j RCE) for security responders. 

We believe it is important to classify the vendors and products between:
1. Internal risk - what you need to patch first to remove risk internally
2. External risk - all third/fourth-party vendors that have custody of your data that might've been hacked that you will need to monitor and tackle once you're done patching

### Here are the lists:

#### [External Risk - Affected Apps](https://github.com/authomize/log4j-log4shell-affected/blob/master/affected_apps.md)

i.e. all vendors you should worry about if you have data in their environemnt or if they access to your environment

#### [Internal Risk - Affected Components](https://github.com/authomize/log4j-log4shell-affected/blob/master/affected_components.md)

i.e. software components you might have used in building your products that you should worry if they cause you to be vulnerable 
 

## Other useful resources
### Lists

[Artifacts using log4j](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core)

[Compromised apps with confirmation](https://github.com/YfryTchsGD/Log4jAttackSurface)

[List of responses from various vendors, some affected and some not](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592)

[Official list maintained by CISA - US Govt](https://github.com/cisagov/log4j-affected-db)

[Official list maintained by NCSC - NL govt, high update frequency](https://github.com/NCSC-NL/log4shell/tree/main/software)


### Guides how to repsond

[A fast and simple guide on what to do to respond to the log4j incident](https://www.authomize.com/blog/authomizes-response-and-mitigation-guide-to-the-log4shell-vulnerability/)

[General incident response guide in case you discover a 3rd party vendor of yours got hacked](https://resources.panorays.com/hubfs/assets/The_Third-Party_Incident_Response_Playbook.pdf)


## Contributing
We are happy to recieve contributions from the community. 
Contribution guidelines:
- Please make a PR editing the raw CSV files. 
- Please be sure to include a reference source for each added row (claims without a validated link for source of claim will not be accepted)


## About this repo
This repo is maintained to simplify response for enterprises and organizations by separating between:
1. Internal risk - Software components you need to search for and patch in your products / internal environment
2. External risk - Third and fourth-party vendors/apps who might've been affected and you should to monitor if your data is in their custody

This list is a community project open for everyone to contribute to and is curated by:
![Authomize Logo](https://www.authomize.com/wp-content/uploads/2021/12/github-banner-authomize.png)


## Our favorite description of the situation
![Meme](https://user-images.githubusercontent.com/57227377/145719037-d8fe4303-7d50-41ea-919f-1e7f525f8680.png)
