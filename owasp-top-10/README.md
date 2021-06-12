# OWASP Top 10

From [OWASP Top Ten](https://owasp.org/www-project-top-ten/):

ID  | Vulnerability                         | Description
----|---------------------------------------|--------------
1   | **Injection**                         | execute commands on the back end server ([Example](https://www.exploit-db.com/exploits/45274))
2   | **Broken Authentication**             | bypass authentication functions ([Example](https://www.exploit-db.com/exploits/47388))
3   | **Sensitive Data Exposure**           | sensitive data available in clear-text
4   | **XML External Entities (XXE)**       | abuses features of XML parsers/data. <ul><li>**in-band** → immediate response to the XXE payload.</li><li>**out-of-band** (blind) → attacker has to reflect the output of their XXE payload to some other file or their own server.</li></ul>
5   | **Broken Access Control**             | access pages and features we should not have access to
6   | **Security Misconfiguration**         | insecure (incomplete) default configurations, verbose error messages etc.
7   | **Cross-Site Scripting (XSS)**        | injecting JavaScript code to be executed on the client-side
8   | **Insecure Deserialization**          | abusing data unpacking (replacing data processed by an application with malicious code)
9   | **Components with Known Vulns**       | Known vulnerabilities usually have known exploits 
10  | **Insufficient Logging & Monitoring** | Logging is important because in the event of an incident, the attacker's actions can be traced.

___

## 1. Injection

Injection occurs when an application misinterprets user-input as actual code rather than a string, changing the code flow and executing it. 

> Injection attacks depend on what technologies are being used and how exactly the input is interpreted by these technologies. 

If an attacker is able to perform injection, it can result in multiple bad consequences: 
- accessing, modifying, deleting sensitive data
- gaining access to the machine on which the command is executed  _(spawning a [reverse shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#reverse-shell-cheat-sheet) for instance)_  and carrying out more attacks against infrastructure linked to this machine

### Examples

- **SQL injection**: escaping user-input bounds by injecting a special character like ('), and then writing code to be executed
- **Command injection**: user input is passed to a system call. As a result, an attacker is able to execute arbitrary system commands on application servers.

### Countermeasures

- **Sanitization**: removing special characters and non-standard characters from user input before displaying it or storing it.
- **Validation**: ensuring that submitted user input matches the expected format (i.e., submitted email matched email format). In addition to that, allow list can be used.

___

## 2. Broken Authentication

Authentication allows users to gain access to web applications by verifying their identities. 

The most common form of authentication is using a username and password mechanism.

Once a user is authenticated, a session cookie will be set as long as the user will be logged in.


### Common flaws

- **Brute force attacks**
- **Weak credentials**
- **Weak Session Cookies**

### Countermeasures

- **Multi Factor Authentication** (code on mobile, or via a [Yubikey](https://www.yubico.com/?lang=fr))
- **Automatic lockout** after a certain number of attempts

### Example

- **Re-registration of an existing user** _(by adding a space before the username for instance)_

___

## 3. Sensitive Data Exposure

When a webapp accidentally divulges sensitive data, we refer to it as "Sensitive Data Exposure".

```console
root@kali:~/thm/owasp-top-10# sqlite3 webapp.db 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
sessions  users   
sqlite> PRAGMA table_info(users);
0|userID|TEXT|1||1
1|username|TEXT|1||0
2|password|TEXT|1||0
3|admin|INT|1||0
sqlite> select * from users;
4413096d9c933359b898b6202288a650|admin|6eea9b7ef19179a06954edd0f6c05ceb|1
23023b67a32488588db1e28579ced7ec|Bob|ad0234829205b9033196ba818f7a872b|1
4e8423b514eef575394ff78caed3254d|Alice|268b38ca7b84f44fa0a6cdc86e6301e0|0
```
___

## 4. XML External Entity (XXE)

### What is XML?

XML (eXtensible Markup Language) is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. It is a markup language used for storing and transporting data. 

It's a similar to the JSON format.

Every XMl document starts with this prolog (not compulsory):

`<?xml version="1.0" encoding="UTF-8"?>`

> Every XML document must contain a `ROOT` element.

### XXE

By abusing XML parsers, an XXE allows an attacker to interact with any backend or external systems that the application itself can access and can allow the attacker to read the file on that system. 

They can also cause Denial of Service (DoS) attack or could use XXE to perform Server-Side Request Forgery (SSRF) inducing the web application to make requests to other applications. 

> XXE may even enable port scanning and lead to remote code execution.

There are two types:

1. **in-band**: the attacker can receive an immediate response to the payload
2. **out-of-band** (blind XXE): no immediate response from the web application and attacker has to reflect the output of their XXE payload to some other file or their own server.

#### Some XXE payloads

1) Defining a `ENTITY` called `name` and assigning it a value `"feast"`:

```xml
<!DOCTYPE replace [<!ENTITY name "feast"> ]>
 <userInfo>
  <firstName>falcon</firstName>
  <lastName>&name;</lastName>
 </userInfo>
```

2) Reading a file on a system

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```

___

## 5. Broken Access Control 

Websites have pages that are protected from regular visitors, for example only the site's admin user should be able to access a page to manage other users. If a website visitor is able to access the protected page/pages that they are not authorized to view, the access controls are broken.

### IDOR

IDOR, or Insecure Direct Object Reference, is the act of exploiting a misconfiguration in the way user input is handled, to access resources you wouldn't ordinarily be able to access. IDOR is a type of access control vulnerability.

### Example

For example, let's say we're logging into our bank account, and after correctly authenticating ourselves, we get taken to a URL like this https://example.com/bank?account_number=1234. On that page we can see all our important bank details, and a user would do whatever they needed to do and move along their way thinking nothing is wrong.

There is however a potentially huge problem here, a hacker may be able to change the account_number parameter to something else like 1235, and if the site is incorrectly configured, then he would have access to someone else's bank information.

[![PwnFunction - IDOR](https://i.ytimg.com/vi/rloqMGcPMkI/maxresdefault.jpg)](https://youtu.be/rloqMGcPMkI)

___

## 6. Security Misconfiguration

Security misconfigurations include:

- Poorly configured permissions on cloud services, like S3 buckets
- Having unnecessary features enabled, like services, pages, accounts or privileges
- Default accounts with unchanged passwords
- Error messages that are overly detailed and allow an attacker to find out more about the system
- Not using [HTTP security headers](https://owasp.org/www-project-secure-headers/), or revealing too much detail in the Server: HTTP header

___

## 7. Cross-site Scripting (XSS)

Cross-site scripting, also known as XSS is a security vulnerability _(typically found in web applications)_ that allows an attacker to inject malicious scripts code (JavaScript, VBScript, Flash, CSS) which will be executed on the client-side.

There are three main types of XSS:

1. **Stored XSS**: occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).
2. **Reflected XSS**: the malicious payload is part of the victims request to the website (e.g., search result → [XSS on Google Search](https://www.youtube.com/watch?v=lG7U3fuNw3A)). Examples:

    - `http://10.10.173.150/reflected?keyword=%3Cscript%3Ealert%28%22Hello%22%29%3C%2Fscript%3E`
    - `http://10.10.173.150/reflected?keyword=%3Cscript%3Ealert%28window.location.hostname%29%3C%2Fscript%3E` (show IP address)

3. **DOM-based XSS**: the malicious payload is not actually parsed by the victim's browser until the website's legitimate JavaScript is executed.

> DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document and this document can be either displayed in the browser window or as the HTML source.

### Countermeasures

- **Sanitization**: removing special characters and non-standard characters from user input before displaying it or storing it.
- **Validation**: ensuring that submitted user input matches the expected format (i.e., submitted email matched email format). In addition to that, allow list can be used.

### Useful links

- [www.xss-payloads.com](http://www.xss-payloads.com/) payloads that go from [keylogger](http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html), taking snapshots from a webcam or even get a more capable [port and network scanner](http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html)

___

## 8. Insecure Deserialization

> **Definition**: Serialization is the process of converting objects used in programming into simpler, compatible formatting for transmitting between systems or networks for further processing or storage. Alternatively, deserialization is the reverse of this; converting serialized information into their complex form - an object that the application will understand.

Simply, insecure deserialization is replacing data processed by an application with malicious code; allowing anything from DoS (Denial of Service) to RCE (Remote Code Execution) that the attacker can use to gain a foothold in a pentesting scenario.
___

##  9. Components With Known Vulnerabilities

> Example: WordPress 4.6 is vulnerable to an unauthenticated remote code execution (RCE) [[exploitDB](https://www.exploit-db.com/exploits/41962)]
___

## 10. Insufficient Logging and Monitoring

When web applications are set up, every action performed by the user should be logged. Logging is important because in the event of an incident, the attackers actions can be traced.

___

## Useful links

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [THM - OWASP Top 10](https://tryhackme.com/room/owasptop10)