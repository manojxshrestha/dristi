# Fix: Burp MCP Port 9876 (or any port) Already in Use

If you encounter an error where the Burp MCP service fails to start because port `9876` is already being used, follow the steps below.

## 1. Open Command Prompt as Administrator

Search for **Command Prompt** in Windows and select **Run as Administrator**.

![cmd](https://github.com/user-attachments/assets/b07257ca-59dd-4993-97ec-bd62a8b6c5c4)

---

## 2. Find the Process Using Port 9876

Run:

```cmd
netstat -ano | findstr :9876
```

Example output:

```cmd
TCP    0.0.0.0:9876           0.0.0.0:0              LISTENING       4768
```

The last column is the **PID** (Process ID).

![findstr](https://github.com/user-attachments/assets/5135706a-2415-4e13-b7fc-56d6aac98995)

---

## 3. Kill the Process

Replace `4768` with the PID from your output.

```cmd
taskkill /PID 4768 /F
```

Expected output:

```cmd
SUCCESS: The process with PID 4768 has been terminated.
```

![taskkill](https://github.com/user-attachments/assets/70735d82-b7d1-4954-9419-7b9e7750e04d)

---

## 4. Run the Connection Script

Navigate to your Dristi scripts directory and run:

```bash
./connect-burp.sh
```

![connect-burp](https://github.com/user-attachments/assets/58471248-6643-48d1-97e3-978440b41811)

---

## Verification

After the script completes successfully, you should see:

- ✅ Burp MCP running
- ✅ Python proxy started
- ✅ Proxy verification successful
- ✅ OpenCode configuration updated
- ✅ WSTG MCP server started

Finally, **restart OpenCode** and begin using the Burp MCP integration.
