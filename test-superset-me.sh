#!/bin/bash

TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwiaWF0IjoxNzY1NTAwNjk4LCJqdGkiOiI0YTUyOWQ3Zi1kOTQ3LTRmZWYtODdlNi04MTViZmIwMDc4MDUiLCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoiMSIsIm5iZiI6MTc2NTUwMDY5OCwiY3NyZiI6ImJmNjcyNGRlLWM2MjUtNGMzMS1iNTkxLTNhMDA3NTU0MjRmOCIsImV4cCI6MTc2NTUwMTU5OH0.72ntC-9GCLLSTGgRW3nGlvA_ZZGTy74V0LBsY3u4V_I"

echo "Testing Superset /api/v1/me endpoint..."
curl -X GET http://localhost:8088/api/v1/me \
  -H "Authorization: Bearer $TOKEN" \
  -v
