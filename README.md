<!-- hfisher -->
<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.5-green?style=for-the-badge">
  <img src="https://img.shields.io/github/license/hsecurities/hfisher?style=for-the-badge">
  <img src="https://img.shields.io/github/stars/hsecurities/hfisher?style=for-the-badge">
  <img src="https://img.shields.io/github/issues/hsecurities/hfisher?color=red&style=for-the-badge">
  <img src="https://img.shields.io/github/forks/hsecurities/hfisher?color=teal&style=for-the-badge">
</p>


<p align="center"><b>A beginners friendly, Automated phishing tool with 30+ templates.</b></p>

##

<h3><p align="center">Disclaimer</p></h3>

<i>Any actions and or activities related to <b>hfisher</b> is solely your responsibility. The misuse of this toolkit can result in <b>criminal charges</b> brought against the persons in question. <b>The contributors will not be held responsible</b> in the event any criminal charges be brought against any individuals misusing this toolkit to break the law.

<b>This toolkit contains materials that can be potentially damaging or dangerous for social media</b>. Refer to the laws in your province/country before accessing, using,or in any other way utilizing this in a wrong way.

<b>This Tool is made for educational purposes only</b>. Do not attempt to violate the law with anything contained here. <b>If this is your intention, then Get the hell out of here</b>!

It only demonstrates "how phishing works". <b>You shall not misuse the information to gain unauthorized access to someones social media</b>. However you may try out this at your own risk.</i>

##

### Features

- Latest and updated login pages.
- Beginners friendly
- Multiple tunneling options
  - Localhost
  - Cloudflared
  - LocalXpose
- Mask URL support 
- Docker support

##

### Installation

- Just, Clone this repository -
  ```
  git clone --depth=1 https://github.com/hsecurities/hfisher.git
  ```

- Now go to cloned directory and run `hfisher.sh` -
  ```
  $ cd hfisher
  $ bash hfisher.sh
  ```

- On first launch, It'll install the dependencies and that's it. ***hfisher*** is installed.

##

### Installation (Termux)
You can easily install hfisher in Termux by using tur-repo
```
$ pkg install tur-repo
$ pkg install hfisher
$ hfisher
```
### A Note : 
***Termux discourages hacking*** .. So never discuss anything related to *hfisher* in any of the termux discussion groups. For more check : [wiki](https://wiki.termux.com/wiki/Hacking)

##

<p align="left">
  <a href="https://shell.cloud.google.com/cloudshell/open?cloudshell_git_repo=https://github.com/hsecurities/hfisher.git&tutorial=README.md" target="_blank"><img src="https://gstatic.com/cloudssh/images/open-btn.svg"></a>
</p>

##


### Run on Docker

- Docker Image Mirror:
  - **DockerHub** : 
    ```
    docker pull htrtech/hfisher
    ```
  - **GHCR** : 
    ```
    docker pull ghcr.io/hsecurities/hfisher:latest
    ```

- By using the wrapper script [**run-docker.sh**](https://raw.githubusercontent.com/hsecurities/hfisher/master/run-docker.sh)

  ```
  $ curl -LO https://raw.githubusercontent.com/hsecurities/hfisher/master/run-docker.sh
  $ bash run-docker.sh
  ```
- Temporary Container

  ```
  docker run --rm -ti htrtech/hfisher
  ```
  - Remember to mount the `auth` directory.


##  

<summary><h3>If you have \r Error</h3></summary>
<b>Use sed (Universal)</b>  
The <b>sed</b> command is available on virtually all <b>Linux/macOS</b> systems, so you don't need to install anything.  
Run this single command to remove all the \r characters:  

`sed -i 's/\r$//' your_script.sh`

##

<details>
  <summary><h3>Dependencies</h3></summary>

<b>hfisher</b> requires following programs to run properly - 
- `git`
- `curl`
- `php`

> All the dependencies will be installed automatically when you run **hfisher** for the first time.
</details>

<details>
  <summary><h3>Tested on</h3></summary>

- **Ubuntu**
- **Debian**
- **Arch**
- **Manjaro**
- **Fedora**
- **Termux**
</details>

<!-- // -->
