# Mini EDR - PowerShell Malware Detection and Prevention

Đây là hệ thống Mini EDR phục vụ khóa luận: **Xây dựng hệ thống phát hiện và tự động ngăn chặn mã độc PowerShell dựa trên phân tích hành vi trong môi trường Windows**.

Hệ thống tập trung vào việc giám sát, phát hiện và phản ứng với các hành vi PowerShell đáng ngờ trong môi trường Windows thông qua kiến trúc kết hợp C++ và Python.

---

## 1. Kiến trúc tổng thể

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
          ↓
Logs
   ├── edr_events.jsonl
   ├── edr_features_g296.csv
   └── edr_cpp_agent.log
          ↓
ReportChatAgent
   ├── LangGraph Investigation Workflow
   ├── Log Retrieval
   ├── Event Correlation
   └── DeepSeek Report Generation
```

## 2. Thành phần

| Thành phần        | Ngôn ngữ | Vai trò                                                                                                                  |
| ----------------- | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| `AmsiProvider`    | C++ DLL  | AMSI Provider, bắt nội dung script PowerShell tại tầng AMSI                                                              |
| `CppAgent`        | C++ EXE  | Nhận telemetry từ AMSI Provider qua Named Pipe, xử lý local rule, terminate process, forward telemetry sang Python Agent |
| `PythonAgent`     | Python   | Multi-sensor telemetry hub, feature extraction, data analysis, rule detection và ML-ready analysis                       |
| `ReportChatAgent` | Python   | Agentic AI Investigation Agent, đọc log EDR, tương quan event và viết báo cáo bằng DeepSeek                              |


## 3. Yêu cầu môi trường

Windows 10 VM
Visual Studio 2022 hoặc Visual Studio có C++ Desktop Development
Python 3.x
PowerShell Script Block Logging nếu muốn test Event ID 4104
Chạy CMD/PowerShell bằng Administrator khi đăng ký AMSI Provider
DeepSeek API key nếu muốn dùng ReportChatAgent

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

| File                    | Vai trò                                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------------------ |
| `edr_events.jsonl`      | Log chính của Python Agent, chứa event, sensor, script, feature, data analysis, verdict                |
| `edr_features_g296.csv` | Feature vector phục vụ phân tích dữ liệu và ML                                                         |
| `edr_cpp_agent.log`     | Log native bridge, chứa AMSI PID, hash, local verdict, forward status, Python verdict và action nếu có |


## 11. Agentic AI Investigation Agent

Hệ thống bổ sung module ReportChatAgent để hỗ trợ điều tra, giải thích cảnh báo và viết báo cáo từ log Mini EDR. Module này sử dụng LangGraph Single-Agent Workflow kết hợp DeepSeek API để đọc log, lọc event theo câu hỏi người dùng, tương quan dữ liệu từ Python Agent và C++ Agent, sau đó sinh báo cáo điều tra bằng ngôn ngữ tự nhiên.

Module này không thay thế Detection/Response Engine. Python Agent và C++ Agent vẫn là nơi đưa ra verdict và hành động response. ReportChatAgent chỉ đóng vai trò hỗ trợ phân tích và báo cáo.

### 11.1. Kiến trúc Agentic AI

User Question
   ↓
LangGraph Investigation Workflow
   ├── parse_intent
   ├── generate_investigation_queries
   ├── load_python_events
   ├── load_cpp_log
   ├── select_events
   ├── correlate_events
   ├── build_context
   └── generate_answer
          ↓
DeepSeek LLM
          ↓
Investigation Report / Explanation

### 11.2. Luồng xử lý

Người dùng đặt câu hỏi
   ↓
Phân tích intent của câu hỏi
   ↓
Tách điều kiện điều tra: PID, process, source, verdict, keyword, time range
   ↓
Đọc log từ Python Agent và C++ Agent
   ↓
Lọc event phù hợp
   ↓
Tương quan event theo PID, hash, script và thời gian
   ↓
Tạo context rút gọn
   ↓
Gửi context cho DeepSeek LLM
   ↓
Trả về báo cáo hoặc giải thích

### 11.3. Vai trò các node trong LangGraph

| Node                             | Vai trò                                                                                |
| -------------------------------- | -------------------------------------------------------------------------------------- |
| `parse_intent`                   | Xác định người dùng muốn giải thích alert, terminate, timeline hay viết báo cáo        |
| `generate_investigation_queries` | Tách câu hỏi thành điều kiện lọc như PID, process, thời gian, source, verdict, keyword |
| `load_python_events`             | Đọc log `edr_events.jsonl` từ Python Agent                                             |
| `load_cpp_log`                   | Đọc log `edr_cpp_agent.log` từ C++ Agent                                               |
| `select_events`                  | Lọc event phù hợp với câu hỏi                                                          |
| `correlate_events`               | Tương quan event theo PID, hash, script và thời gian                                   |
| `build_context`                  | Tạo context rút gọn để gửi cho LLM                                                     |
| `generate_answer`                | Gọi DeepSeek API để viết giải thích hoặc báo cáo                                       |

### 11.4. Dữ liệu đầu vào

ReportChatAgent đọc các file log sau:
PythonAgent/logs/edr_events.jsonl
edr_cpp_agent.log

| File                | Vai trò                                                                                                |
| ------------------- | ------------------------------------------------------------------------------------------------------ |
| `edr_events.jsonl`  | Log chính của Python Agent, chứa sensor, script, feature, risk score, verdict                          |
| `edr_cpp_agent.log` | Log của C++ Agent, chứa AMSI PID, hash, local verdict, forward status, Python verdict và action nếu có |

### 11.5. Cài dependencies cho ReportChatAgent

cd ReportChatAgent
python -m pip install -r requirements.txt

### 11.6. Cấu hình DeepSeek API

Tạo file .env trong thư mục ReportChatAgent:

DEEPSEEK_API_KEY=your_deepseek_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash

EDR_EVENTS_LOG_PATH=Path_edr_events.jsonl
EDR_CPP_LOG_PATH=Path_edr_cpp_agent.log

MAX_CONTEXT_EVENTS=20
MAX_OUTPUT_TOKENS=3500

### 11.7. Chạy ReportChatAgent

cd ReportChatAgent
python app.py

Mở trình duyệt:

http://127.0.0.1:9100

### 11.8. Ví dụ câu hỏi

Người dùng có thể hỏi:

Viết báo cáo cho các event alert từ 10:10 đến 10:20
Viết báo cáo cho process powershell.exe từ 10:35 đến 10:37
Tại sao PID 9652 bị ALERT?
Giải thích event có EncodedCommand
Giải thích các event từ file_sensor
Có event nào có C++ local verdict ALERT không?

### 11.9. Kết quả mong đợi

ReportChatAgent sẽ trả về báo cáo hoặc giải thích gồm các phần:

1. Phạm vi truy vấn
2. Kết luận ngắn
3. Bằng chứng chính từ log
4. Timeline
5. Chuỗi hành vi / Attack Chain
6. Tương quan C++ Agent nếu có
7. Giải thích verdict
8. Khuyến nghị kiểm tra tiếp theo

Ví dụ kết quả có thể mô tả:

- Các event ALERT trong khoảng thời gian người dùng yêu cầu
- Sensor phát hiện gồm amsi_cpp_bridge, process_sensor, file_sensor hoặc eventlog_4104_sensor
- C++ Agent local verdict và trạng thái forward sang Python Agent nếu có dữ liệu tương ứng
- Các lý do như EncodedCommand indicator, Dynamic execution, ExecutionPolicy bypass, NoProfile execution
- Verdict tổng hợp là ALERT hoặc TERMINATE tùy log

## 12. Lưu ý

Đây là hệ thống Mini EDR chạy trong môi trường lab.
Không chạy trên máy production.
AMSI Provider và C++ Agent chạy ở user-mode.
Cơ chế response hiện tại là terminate process khi verdict là TERMINATE.
ReportChatAgent chỉ hỗ trợ điều tra và viết báo cáo, không trực tiếp quyết định verdict.
