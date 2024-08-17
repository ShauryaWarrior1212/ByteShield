# Use an appropriate base image
FROM ubuntu:20.04

# Install Nmap and any other necessary packages
RUN apt-get update && apt-get install -y \
    nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the default command
CMD ["bash"]
