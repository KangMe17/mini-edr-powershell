# Mini EDR - PowerShell Malware Detection and Prevention

Đây là hệ thống Mini EDR phục vụ khóa luận: **Xây dựng hệ thống phát hiện và tự động ngăn chặn mã độc PowerShell dựa trên phân tích hành vi trong môi trường Windows**.

## 1. Kiến trúc

```text
PowerShell
   ↓
AMSI Provider DLL (C++)
   ↓ Named Pipe \\.\pipe\EdrAmsiPipe
C++ Native Bridge Agent
   ↓ HTTP http://127.0.0.1:9001/telemetry
Python EDR Agent
   ├── Process Sensor
   ├── File Sensor
   ├── Event Log 4104 Sensor
   ├── Feature Extraction G2.96
   ├── Data Analysis
   ├── Rule Detection
   └── ML-ready Random Forest Plugin
```

## 2. Thành phần

| Thành phần | Ngôn ngữ | Vai trò |
|---|---|---|
| AmsiProvider | C++ DLL | AMSI Provider, bắt script PowerShell |
| CppAgent | C++ EXE | Nhận Named Pipe, local rule, terminate process, forward telemetry |
| PythonAgent | Python | Multi-sensor telemetry hub, feature extraction, rule + ML-ready analysis |

## 3. Yêu cầu môi trường

- Windows 10 VM
- Visual Studio 2022 hoặc Visual Studio có C++ Desktop Development
- Python 3.x
- PowerShell Script Block Logging bật nếu muốn test Event ID 4104
- Chạy CMD/PowerShell bằng Administrator khi đăng ký AMSI Provider

## 4. Cài Python dependencies

```powershell
cd PythonAgent
python -m pip install -r requirements.txt
```

Nếu Python không nằm trong PATH, dùng đường dẫn trực tiếp, ví dụ:

```powershell
E:\python131\python.exe -m pip install -r requirements.txt
```

## 5. Build C++ project

Mở solution bằng Visual Studio, build:

```text
AmsiProvider -> tạo AmsiProvider.dll
CppAgent     -> tạo AgentConsole.exe hoặc CppAgent.exe
```

Copy file build ra:

```text
C:\EDR\
├── AmsiProvider.dll
├── AgentConsole.exe
└── PythonAgent\
```

## 6. Đăng ký AMSI Provider

Mở CMD bằng Administrator:

```cmd
cd C:\EDR
regsvr32 /u AmsiProvider.dll
regsvr32 AmsiProvider.dll
```

Kiểm tra registry:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{11111111-2222-3333-4444-555555555555}"
```

Nếu thấy:

```text
Mini EDR AMSI Provider
```

là đăng ký thành công.

## 7. Chạy hệ thống

### Terminal 1: chạy Python Agent

```powershell
cd C:\EDR\PythonAgent
python PythonAgent.py
```

Kiểm tra health:

```cmd
curl.exe http://127.0.0.1:9001/health
```

### Terminal 2: chạy C++ Agent

```cmd
cd C:\EDR
AgentConsole.exe
```

### Terminal 3: mở PowerShell mới để test

```powershell
powershell -EncodedCommand SQBFAFgA
```

Hoặc:

```powershell
iex "Write-Host AMSI_TEST"
```

Hoặc:

```powershell
Invoke-Expression "calc"
```

## 8. Test các sensor

### AMSI Sensor

```powershell
iex "Write-Host AMSI_TEST"
```

Kỳ vọng Python Agent:

```text
SOURCE: amsi_cpp_bridge
FINAL: ALERT
```

### Process Sensor

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA
```

Kỳ vọng:

```text
SOURCE: process_sensor
FINAL: ALERT
```

### File Sensor

```powershell
Set-Content -Path "$env:USERPROFILE\Downloads\test_edr.ps1" -Value 'Invoke-Expression "calc"'
```

Kỳ vọng:

```text
SOURCE: file_sensor
FINAL: ALERT
```

### Event Log 4104 Sensor

Bật Script Block Logging trong Group Policy:

```text
Computer Configuration
→ Administrative Templates
→ Windows Components
→ Windows PowerShell
→ Turn on PowerShell Script Block Logging
→ Enabled
```

Cập nhật policy:

```powershell
gpupdate /force
```

Test:

```powershell
powershell -NoProfile -Command "Invoke-Expression 'Write-Host EVENTLOG_TEST'"
```

Kỳ vọng:

```text
SOURCE: eventlog_4104_sensor
FINAL: ALERT
```

## 9. ML Model

Hiện tại Python Agent có thể chạy không cần model. Khi có model Random Forest, đặt 2 file vào:

```text
PythonAgent/model/
├── random_forest_model.pkl
└── feature_columns.pkl
```

Reload model:

```cmd
curl.exe -X POST http://127.0.0.1:9001/reload-model
```

Nếu model load thành công:

```text
ML ENABLED: True
```

## 10. Logs

Python Agent lưu log tại:

```text
PythonAgent/logs/
├── edr_events.jsonl
└── edr_features_g296.csv
```

C++ Agent lưu:

```text
edr_cpp_agent.log
```

## 11. Lưu ý

- Đây là hệ thống Mini EDR chạy trong môi trường lab.
- Không chạy trên máy production.
- AMSI Provider và C++ Agent chạy ở user-mode.
- Cơ chế response hiện tại là terminate process khi verdict là TERMINATE.
- Backend tập trung, model versioning, Windows Service và ETW được xem là hướng phát triển.
