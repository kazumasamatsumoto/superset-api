#!/bin/bash

echo "Testing guest token endpoint..."

TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwiaWF0IjoxNzY1NTAwNjk4LCJqdGkiOiI0YTUyOWQ3Zi1kOTQ3LTRmZWYtODdlNi04MTViZmIwMDc4MDUiLCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoiMSIsIm5iZiI6MTc2NTUwMDY5OCwiY3NyZiI6ImJmNjcyNGRlLWM2MjUtNGMzMS1iNTkxLTNhMDA3NTU0MjRmOCIsImV4cCI6MTc2NTUwMTU5OH0.72ntC-9GCLLSTGgRW3nGlvA_ZZGTy74V0LBsY3u4V_I"

curl -X POST http://localhost:3000/api/superset/guest-token \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"dashboardId": "9f3cc130-2e14-4125-9a92-0a7b006c3a53", "username": "admin"}' \
  -v
