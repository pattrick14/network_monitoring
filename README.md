# Network Monitoring Tool

## Overview

This project is a network monitoring tool that allows users to scan their networks, analyze traffic, and visualize data. Built with Python, it leverages libraries such as Scapy and Pygame for functionality and UI interaction.

## Setup Instructions

Follow the steps below to set up and run the project.

### 1. Clone the Repository

First, clone the repository to your local machine:

```git clone https://github.com/pattrick14/network_monitoring.git```

```cd network_monitoring```


### 2. Switch to Root User

For network scanning privileges, switch to the root user:

```sudo su root```


### 3. Set Up a Virtual Environment

Create and activate a Python virtual environment:

```python3 -m venv env```
```source env/bin/activate```


### 4. Install Necessary Libraries

Install the required libraries. Run the following commands:

```sudo apt-get update```

```sudo apt-get install python3-pip```

```pip install pygame scapy pandas plotly tkinterweb```

```sudo apt-get install python3-tk```


### 5. Run the Project

Finally, execute the project with:

```python3 networkmonitoring.py```


## Dependencies

- pygame: For GUI development
- scapy: For network packet manipulation and analysis
- pandas: To handle and analyze data
- plotly: For interactive plotting
- tkinterweb: For web content within tkinter applications
