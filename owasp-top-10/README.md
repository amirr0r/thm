# OWASP Top 10

From [OWASP Top Ten](https://owasp.org/www-project-top-ten/):

ID  | Vulnerability                         | Description
----|---------------------------------------|--------------
1   | **Injection**                         | execute commands on the back end server ([Example](https://www.exploit-db.com/exploits/45274))
2   | **Broken Authentication**             | bypass authentication functions ([Example](https://www.exploit-db.com/exploits/47388))
3   | **Sensitive Data Exposure**           | sensitive data available in clear-text
4   | **XML External Entities (XXE)**       | abuses features of XML parsers/data. 
<ul><li>**in-band** → immediate response to the XXE payload.</li><li>**out-of-band** (blind) → attacker has to reflect the output of their XXE payload to some other file or their own server.</li></ul>
5   | **Broken Access Control**             | access pages and features we should not have access to
6   | **Security Misconfiguration**         | insecure (incomplete) default configurations, verbose error messages etc.
7   | **Cross-Site Scripting (XSS)**        | injecting JavaScript code to be executed on the client-side
8   | **Insecure Deserialization**          | abusing data unpacking
9   | **Components with Known Vulns**       | Known vulnerabilities usually have known exploits 
10  | **Insufficient Logging & Monitoring** | Logging is important because in the event of an incident, the attacker's actions can be traced.

## Useful links

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [THM - OWASP Top 10](https://tryhackme.com/room/owasptop10)