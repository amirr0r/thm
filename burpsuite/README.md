# Burpsuite

BurpSuite, developed by [PortSwigger](https://portswigger.net/), is widely regarded as **the de facto tool** to use when performing **web app pentesting**.

BurpSuite is a proxy for HTTP(S) traffic, allowing us to inspect and modify HTTP requests. It can also be used to automate certain tasks such as bruteforce.

## Features

Feature         | Description
----------------|--------------------------------------------------------------------------------------------
**Proxy**       | redirect web traffic into Burp for further examination
**Target**      | set the scope of our project, can be used to create a site map of the tested application.
**Intruder**    | field fuzzing, credential stuffing and more
**Repeater**    | Inspect, repeat and/or modify requests
**Sequencer**   | analyze "randomness" in different pieces of data such as password reset tokens
**Decoder**     | allows us to perform various decoding/encoding (base64, URL encoding, etc.)
**Comparer**    | perform a 'diff' on responses and other pieces of data (such as site maps or proxy histories)
**Extender**    | allows us to add extensions
**Scanner**     | automatically identify different vulnerabilities _(only available in the premium version)_

## Intruder

1. _Sniper_: cycle through our payload set, putting the next available payload in each position in turn
2. _Battering Ram_: use one payload set in every single position we've selected simultaneously
3. _Pitchfork_: select multiple payload sets (one per position) and iterate through them simultaneously
4. _Cluster Bomb_: select multiple payload sets (one per position) and iterate through all possible combinations

## Useful links

- [Les tutos de Nico - Burp Suite](https://web.archive.org/web/20200217020027/http://www.lestutosdenico.com/outils/burp-suite)
- [FoxyProxy - Mozilla extension](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)
- [BurpSuite Intruder Documentation](https://portswigger.net/burp/documentation/desktop/tools/intruder/using)