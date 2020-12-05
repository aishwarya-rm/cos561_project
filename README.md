# COS516 Final Project

This project aims to analyze the video streaming performance of the four following services: Amazon Prime, Netflix, Twitch and YouTube for the COS516 Final Project.  

Our code is inspired by the work here: [https://github.com/leishman/netflix_and_chill]

# Reproducing Our Results

The script to run metrics for each service is contained in the folder labeled by name. Some flags include 

- `-t` the amount of time to run the script for (the time out) measured in seconds
- `--analyze` whether to analyze the packet contents

We recommend using `sudo` priviledges to run the script as scapy requires `sudo` for certain operations. An example run command would be

   `sudo python netflix/monitor_video.py -t 300 --analyze`
