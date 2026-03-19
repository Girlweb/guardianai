#!/bin/bash
cd ~/guardianai/backend
source venv/bin/activate
nohup python main.py > /tmp/guardianai_api.log 2>&1 &
echo "Backend started - http://$(hostname -I | awk '{print $1}'):8001"
cd ~/guardianai/frontend
nohup python3 -m http.server 80 > /tmp/guardianai_web.log 2>&1 &
echo "Frontend started - http://$(hostname -I | awk '{print $1}')"
