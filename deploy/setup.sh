#!/bin/bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv git curl wget
pip3 install semgrep bandit --break-system-packages
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
wget https://github.com/aquasecurity/trivy/releases/download/v0.48.3/trivy_0.48.3_Linux-64bit.deb
sudo dpkg -i trivy_0.48.3_Linux-64bit.deb
rm trivy_0.48.3_Linux-64bit.deb
git clone https://github.com/Girlweb/guardianai.git
cd guardianai/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "Setup complete - add API keys to backend/.env then run: python main.py"
