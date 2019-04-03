# Nessus Map
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)
[![GitHub version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=gh&v=1.0)](http://badge.fury.io/gh/boennemann%2Fbadges)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)

**Nessus XML Praser**

<img src="https://i.imgur.com/IH6qY1I.png" />

### Requirements
- Python3
- Django

### Tested on
- xubuntu 18.04

### What it does
- Vulnerability based parsing
- Service based parsing
- Unsupported OS parsing
- Generate Executive Summary

### How it works
<pre>Place all nessus db i-e .nessus file under XML directory and start server.</pre>

### How to Setup
- Clone this repo `git clone https://github.com/d3vilbug/Nessus_Map.git`
- Change directory `cd Nessus_Map`
- Copy all `.nessus` files in `XML` directory
- Start server with `python3 manage.py runserver`

### Vulnerability Parsing

<img src="https://i.imgur.com/SUFwFVI.gif" />

<img src="https://i.imgur.com/yoznEVU.png" />


### Services Parsing

<img src="https://i.imgur.com/8pL1r40.png" />


### Executive Summary

<img src="https://i.imgur.com/470Siss.gif" />

<img src="https://i.imgur.com/lNEJUlu.png" />


### Unsupported OS

<img src="https://i.imgur.com/dujyqiK.png" />

