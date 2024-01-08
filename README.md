# Nessus Map

[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)
[![GitHub version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=gh&v=1.0)](http://badge.fury.io/gh/boennemann%2Fbadges)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)

**Nessus XML Praser**

<img src="https://i.imgur.com/gtw4lVP.png" />

### Requirements

- Python3
- Django

### Tested on

- Ubuntu 18.04
- Windows 11 Pro (PowerShell)

### What it does

- Vulnerability based parsing
- Service based parsing
- Host bases parsing
- Unsupported OS parsing
- Generate Executive Summary of scan
- Export parsed .nessus(s) to JSON file(s)
- Import JSON file in Nessus_Map
- Combines multiple Nessus Scan results

### How it works

- Takes in .nessus from Nessus Scan results
- Parses the XML data
- Generates easy-to-read output for all vulnerabilities

### How to Setup

- Clone this repo `https://github.com/Ebryx/Nessus_Map.git`
- Change directory `cd Nessus_Map`
- Export `.nessus` report from Nessus Dashboard
- Copy/Move the `.nessus` report in `XML` directory
  Repeat this step for multiple scan reports
- Start server with `python3 manage.py runserver`

### Setting up with Python Virtualenv

```bash
git clone https://github.com/Ebryx/Nessus_Map
cd Nessus_Map
mkdir env
cd env
python3 -m venv .
source bin/activate
cd ..
pip install -r requirements.txt
python manage.py runserver
```

### Vulnerability Parsing

<img src="https://i.imgur.com/etrzGc3.gif" />

### Host Parsing

<img src="https://i.imgur.com/sgZp1AI.png" />

### Services Parsing

<img src="https://i.imgur.com/FZUFRKm.png" />

### Executive Reoprt

<img src="https://i.imgur.com/J4vrkD7.png" />

<img src="https://i.imgur.com/vWeU257.png" />

### Export parsed .nessus(s) to JSON file(s)

<img src="https://i.imgur.com/aQaPBZm.gif" />

### Import JSON file in Nessus_Map

<img src="https://i.imgur.com/oDBuD8r.gif" />
